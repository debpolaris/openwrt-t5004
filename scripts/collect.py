import hashlib
import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path

from verify import verify_config, verify_kernel, verify_manifest, verify_metadata, verify_shadow, verify_sysupgrade

ROOT = Path(__file__).resolve().parents[1]


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(*args):
    subprocess.run(args, check=True)


def flatten_checksums(dist):
    path = dist / 'SHA256SUMS'
    entries = [(digest, Path(name).name) for digest, name in (line.split(maxsplit=1) for line in path.read_text().splitlines())]
    names = [name for _, name in entries]
    if len(names) != len(set(names)):
        raise ValueError('Release asset filenames must be unique')
    path.write_text(''.join(f'{digest}  {name}\n' for digest, name in entries))


def archive(destination, directory, members):
    run('tar', '--sort=name', '--exclude-vcs', '--exclude=__pycache__', '--exclude=*.pyc', '-I', 'zstd -T2 -3', '-cf', str(destination), '-C', str(directory), *members)


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
    verify_kernel(work)
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
    verify_sysupgrade(sysupgrade)
    root_image = work.parent / 'verified-root.squashfs'
    with tarfile.open(sysupgrade) as image, root_image.open('wb') as output:
        shutil.copyfileobj(image.extractfile('sysupgrade-iptime_t5004/root'), output)
    rootfs = work.parent / 'verified-rootfs'
    run('fakeroot', 'unsquashfs', '-no-progress', '-d', str(rootfs), str(root_image))
    fwtool = work / 'staging_dir/host/bin/fwtool'
    metadata_path = firmware / 'sysupgrade-metadata.json'
    run(str(fwtool), '-i', str(metadata_path), str(sysupgrade))
    verify_metadata(json.loads(metadata_path.read_text()))
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
    forbidden = (list(rootfs.glob('etc/dropbear/*host_key'))
                 + list(rootfs.glob('etc/ssh/ssh_host_*_key'))
                 + list(rootfs.glob('root/.ssh/*')))
    if forbidden or (rootfs / 'etc/dropbear/authorized_keys').exists():
        raise ValueError('Device SSH credentials must not be embedded')
    verify_shadow((rootfs / 'etc/shadow').read_text())
    for path in (rootfs / 'etc').rglob('*'):
        if path.is_file() and not path.is_symlink() and b'PRIVATE KEY-----' in path.read_bytes():
            raise ValueError('Private keys must not be embedded in the image')
    if (rootfs / 'usr/bin/awg').exists() or list(rootfs.glob('lib/modules/*/amneziawg.ko')):
        raise ValueError('AWG was unexpectedly installed in the firmware')
    if not (rootfs / 'usr/bin/wg').is_file() or not list(rootfs.glob('lib/modules/*/wireguard.ko')):
        raise ValueError('WireGuard payload is missing from the actual image')
    if not (rootfs / 'usr/sbin/dropbear').is_file():
        raise ValueError('Dropbear payload is missing from the actual image')
    sftp_link = rootfs / 'usr/libexec/sftp-server'
    if (not (rootfs / 'usr/lib/sftp-server').is_file()
            or not sftp_link.is_symlink()
            or os.readlink(sftp_link) != '../lib/sftp-server'):
        raise ValueError('OpenSSH SFTP server payload or Dropbear compatibility link is invalid')
    server_artifacts = [
        'usr/sbin/sshd',
        'etc/init.d/sshd',
        'lib/preinit/99_10_failsafe_sshd',
        'usr/lib/sshd-auth',
        'usr/lib/sshd-session',
        'etc/ssh/sshd_config',
        'etc/ssh/sshd_config.d',
        'etc/pam.d/sshd',
        'etc/security/access-sshd-local.conf',
    ]
    if any((rootfs / path).exists() or (rootfs / path).is_symlink() for path in server_artifacts):
        raise ValueError('OpenSSH server must not be installed in the firmware')
    public_keys = rootfs / 'etc/apk/keys'
    if not any(path.is_file() for path in public_keys.glob('*')):
        raise ValueError('Package verification public keys are missing')
    shutil.copytree(public_keys, dist / 'package-public-keys')
    apk = str(work / 'staging_dir/host/bin/apk')
    repositories = sorted((work / 'bin').rglob('packages.adb'))
    apk_args = [apk, '--root', str(rootfs), '--keys-dir', str(public_keys), '--arch', 'mipsel_24kc',
                '--repositories-file', '/dev/null', '--no-network', '--no-scripts', '--simulate']
    for repository in repositories:
        apk_args.extend(['--repository', repository.as_uri()])
    versions = dict(line.split(' - ', 1) for line in manifests[0].read_text().splitlines() if ' - ' in line)
    install_check = subprocess.check_output([*apk_args, 'add', f"kernel={versions['kernel']}", 'amneziawg-tools'], text=True)
    (dist / 'optional-install-check.txt').write_text(install_check)
    for path in manifests + [target / name for name in ['profiles.json', 'config.buildinfo', 'feeds.buildinfo', 'version.buildinfo']]:
        shutil.copy2(path, dist / path.name)
    shutil.copy2(ROOT / 'config/sources.json', dist / 'sources.json')
    shutil.copy2(work / '.config', dist / 'build.config')
    for pattern in ['linux-6.12.118.tar.*', 'kmod-amneziawg-*.tar.*', 'amneziawg-tools-*.tar.*']:
        if not list((work / 'dl').glob(pattern)):
            raise ValueError(f'Corresponding source archive is missing: {pattern}')
    archive(dist / 'matching-packages.tar.zst', work / 'bin', ['packages', 'targets/ramips/mt7621/packages'])
    tracked = subprocess.check_output(['git', '-C', str(work), 'ls-files', '-z'])
    extra = ['.config', 'feeds.conf', 'feeds', 'dl', 'package/custom', 'package/feeds', 'version', 'version.date']
    source_list = work.parent / 'source-files.list'
    source_list.write_bytes(tracked + b''.join(name.encode() + b'\0' for name in extra))
    run('tar', '--sort=name', '--exclude-vcs', '-I', 'zstd -T2 -3', '-cf', str(dist / 'corresponding-source.tar.zst'), '-C', str(work), '--null', '-T', str(source_list))
    archive(dist / 'build-recipe.tar.zst', ROOT, ['.github', '.gitattributes', '.gitignore', 'config', 'scripts', 'LICENSE'])
    report = {
        'device': 'iptime,t5004',
        'target': 'ramips/mt7621',
        'kernel': '6.12.118',
        'kernel_package_version': versions['kernel'],
        'kernel_cve_2026_98432_fix_verified': True,
        'kernel_cve_2026_99288_fix_verified': True,
        'dropbear_installed': True,
        'openssh_sftp_server_installed': True,
        'openssh_server_installed': False,
        'wireguard_installed': True,
        'amneziawg_installed': False,
        'microsocks_installed': False,
        'optional_install_simulation_passed': True,
        'optional_package_installation': 'Use the signed repositories in matching-packages.tar.zst and the bundled public keys. Loose APK files are not individually signed.',
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
            stream.write('## T5004 build verified\n\nLinux 6.12.118; Dropbear with OpenSSH SFTP server; WireGuard installed; AWG optional packages only.\n\nDevice boot and live networking have not been tested. Do not flash unrelated hardware.\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
