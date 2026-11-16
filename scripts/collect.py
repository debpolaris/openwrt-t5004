import hashlib
import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path

from verify import verify_config, verify_kernel, verify_manifest

ROOT = Path(__file__).resolve().parents[1]


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(*args):
    subprocess.run(args, check=True)


def archive(destination, directory, members):
    run('tar', '--sort=name', '--exclude-vcs', '-I', 'zstd -T2 -3', '-cf', str(destination), '-C', str(directory), *members)


def main():
    work = Path(os.environ['OPENWRT_DIR']).resolve()
    target = work / 'bin/targets/ramips/mt7621'
    dist = ROOT / 'dist'
    dist.mkdir(exist_ok=False)
    firmware = dist / 'firmware'
    optional = dist / 'optional-packages'
    firmware.mkdir()
    optional.mkdir()
    verify_config((work / '.config').read_text())
    kernel = verify_kernel(work)
    profiles = json.loads((target / 'profiles.json').read_text())
    device = profiles['profiles']['iptime_t5004']
    if 'iptime,t5004' not in device['supported_devices']:
        raise ValueError('T5004 device identifier missing from image metadata')
    images = device['images']
    upgrades = [entry for entry in images if entry['type'] == 'sysupgrade']
    if len(upgrades) != 1:
        raise ValueError('Expected one T5004 sysupgrade image')
    for entry in images:
        image = target / entry['name']
        if image.parent != target or 'iptime_t5004' not in image.name:
            raise ValueError('Unexpected image path')
        if sha256(image) != entry['sha256']:
            raise ValueError('Image digest differs from profiles.json')
        shutil.copy2(image, firmware / image.name)
    sysupgrade = target / upgrades[0]['name']
    with tarfile.open(sysupgrade) as image:
        kernel_members = [item for item in image.getmembers() if item.name.endswith('/kernel')]
        root_members = [item for item in image.getmembers() if item.name.endswith('/root')]
        if len(kernel_members) != 1 or len(root_members) != 1:
            raise ValueError('Invalid NAND sysupgrade layout')
        if kernel_members[0].size > 4 * 1024 * 1024:
            raise ValueError('Kernel exceeds the T5004 4 MiB partition')
    fwtool = work / 'staging_dir/host/bin/fwtool'
    metadata_path = firmware / 'sysupgrade-metadata.json'
    run(str(fwtool), '-i', str(metadata_path), str(sysupgrade))
    if 'iptime,t5004' not in json.loads(metadata_path.read_text())['supported_devices']:
        raise ValueError('Sysupgrade trailer does not identify T5004')
    manifests = list(target.glob('*.manifest'))
    if len(manifests) != 1:
        raise ValueError('Expected a single-device firmware manifest')
    packages = verify_manifest(manifests[0].read_text())
    for package in ['kmod-amneziawg', 'amneziawg-tools']:
        matches = [path for path in (work / 'bin').rglob(f'{package}-*.apk') if path.is_file()]
        unique = {sha256(path): path for path in matches}
        if len(unique) != 1:
            raise ValueError(f'Expected one matching optional package: {package}')
        path = next(iter(unique.values()))
        shutil.copy2(path, optional / path.name)
    roots = list(work.glob('build_dir/target-*/root-ramips'))
    if len(roots) != 1:
        raise ValueError('Expected the final ramips root filesystem')
    rootfs = roots[0]
    forbidden = list(rootfs.glob('etc/dropbear/*host_key')) + list(rootfs.glob('root/.ssh/*'))
    if forbidden or (rootfs / 'etc/dropbear/authorized_keys').exists():
        raise ValueError('Device SSH credentials must not be embedded')
    if (rootfs / 'usr/bin/awg').exists() or list(rootfs.glob('lib/modules/*/amneziawg.ko')):
        raise ValueError('AWG was unexpectedly installed in the firmware')
    public_keys = rootfs / 'etc/apk/keys'
    if public_keys.exists():
        shutil.copytree(public_keys, dist / 'package-public-keys')
    for path in manifests + [target / name for name in ['profiles.json', 'config.buildinfo', 'feeds.buildinfo', 'version.buildinfo']]:
        shutil.copy2(path, dist / path.name)
    shutil.copy2(ROOT / 'config/sources.json', dist / 'sources.json')
    shutil.copy2(work / '.config', dist / 'build.config')
    for name in ['af_inet.c', 'tcp_ipv4.c']:
        text = (kernel / 'net/ipv4' / name).read_text()
        if 'kfree_rcu' not in text:
            raise ValueError('Kernel security verification failed')
    archive(dist / 'matching-packages.tar.zst', work / 'bin', ['packages', 'targets/ramips/mt7621/packages'])
    tracked = subprocess.check_output(['git', '-C', str(work), 'ls-files', '-z'])
    extra = ['.config', 'feeds.conf', 'feeds', 'dl', 'package/custom']
    source_list = work.parent / 'source-files.list'
    source_list.write_bytes(tracked + b''.join(name.encode() + b'\0' for name in extra))
    run('tar', '--sort=name', '--exclude-vcs', '-I', 'zstd -T2 -3', '-cf', str(dist / 'corresponding-source.tar.zst'), '-C', str(work), '--null', '-T', str(source_list))
    archive(dist / 'build-recipe.tar.zst', ROOT, ['.github', '.gitattributes', '.gitignore', 'config', 'scripts', 'LICENSE'])
    report = {
        'device': 'iptime,t5004',
        'target': 'ramips/mt7621',
        'kernel': '6.12.116',
        'kernel_cve_2026_98432_fix_verified': True,
        'wireguard_installed': True,
        'amneziawg_installed': False,
        'microsocks_installed': False,
        'installed_package_count': len(packages),
        'recipe_commit': os.environ.get('GITHUB_SHA'),
        'run_id': os.environ.get('GITHUB_RUN_ID'),
        'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT'),
        'runtime_tested': False,
        'known_limitation': 'Review OpenWrt issue 25457 before using VLAN-aware bridge STP.',
        'source_delivery': 'Corresponding sources and the build recipe accompany the binaries in this artifact.',
    }
    (dist / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
    files = sorted(path for path in dist.rglob('*') if path.is_file())
    (dist / 'SHA256SUMS').write_text(''.join(f'{sha256(path)}  {path.relative_to(dist).as_posix()}\n' for path in files))
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a') as stream:
            stream.write('## T5004 build verified\n\nLinux 6.12.116; WireGuard installed; AWG optional packages only.\n\nDevice boot and live networking have not been tested. Do not flash unrelated hardware.\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
