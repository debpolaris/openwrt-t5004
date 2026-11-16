import json
import os
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(*args, cwd=None):
    subprocess.run(args, cwd=cwd, check=True)


def checkout(source, destination):
    if not re.fullmatch(r'[0-9a-f]{40}', source['commit']):
        raise ValueError('Source revisions must be full commit hashes')
    run('git', 'init', '--initial-branch=source', str(destination))
    run('git', '-C', str(destination), 'remote', 'add', 'origin', source['url'])
    run('git', '-C', str(destination), 'fetch', '--depth=1', 'origin', source['commit'])
    run('git', '-C', str(destination), 'checkout', '--detach', 'FETCH_HEAD')
    actual = subprocess.check_output(['git', '-C', str(destination), 'rev-parse', 'HEAD'], text=True).strip()
    if actual != source['commit']:
        raise ValueError('Fetched source does not match the locked commit')


def replace_assignment(text, name, value):
    text, count = re.subn(rf'^{re.escape(name)}\s*:?=.*$', f'{name}:={value}', text, flags=re.MULTILINE)
    if count != 1:
        raise ValueError(f'Expected one {name} assignment in the upstream recipe')
    return text


def main():
    lock = json.loads((ROOT / 'config/sources.json').read_text())
    work = Path(os.environ['OPENWRT_DIR']).resolve()
    if work.exists():
        raise FileExistsError('Build directory must be empty and outside the recipe checkout')
    checkout(lock['openwrt'], work)
    kernel = (work / 'target/linux/generic/kernel-6.12').read_text()
    if 'LINUX_VERSION-6.12 = .116' not in kernel:
        raise ValueError('Expected the verified Linux 6.12.116 source baseline')
    feed_lines = [f"src-git {name} {source['url']}^{source['commit']}" for name, source in lock['feeds'].items()]
    (work / 'feeds.conf').write_text('\n'.join(feed_lines) + '\n')
    recipes = work.parent / 'awg-recipes'
    checkout(lock['awg_packages'], recipes)
    for package, key in [('kmod-amneziawg', 'awg_kernel'), ('amneziawg-tools', 'awg_tools')]:
        destination = work / 'package/custom' / package
        shutil.copytree(recipes / package, destination)
        makefile = destination / 'Makefile'
        text = replace_assignment(makefile.read_text(), 'PKG_VERSION', lock[key]['version'])
        text = replace_assignment(text, 'PKG_SOURCE_VERSION', lock[key]['commit'])
        if package == 'kmod-amneziawg':
            text, count = re.subn(r'^define Build/Prepare\n.*?^endef\n', '', text, flags=re.MULTILINE | re.DOTALL)
            if count != 1:
                raise ValueError('Expected the obsolete kernel-source copy override')
            text, count = re.subn(r'^\s*WIREGUARD_VERSION="\$\(WIREGUARD_VERSION\)" \\\n', '', text, flags=re.MULTILINE)
            if count != 1:
                raise ValueError('Expected the obsolete module-version override')
        makefile.write_text(text)
    run('./scripts/feeds', 'update', '-a', cwd=work)
    for name, source in lock['feeds'].items():
        actual = subprocess.check_output(['git', '-C', str(work / 'feeds' / name), 'rev-parse', 'HEAD'], text=True).strip()
        if actual != source['commit']:
            raise ValueError(f'Unexpected source revision for feed {name}')
    run('./scripts/feeds', 'install', '-a', cwd=work)
    shutil.copy2(ROOT / 'config/t5004.config', work / '.config')
    print('Prepared pinned OpenWrt and AWG sources without device credentials or WAN overrides.')


if __name__ == '__main__':
    main()
