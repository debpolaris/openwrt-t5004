import re
import sys
from pathlib import Path

REQUIRED_CONFIG = {
    'CONFIG_TARGET_ramips': 'y',
    'CONFIG_TARGET_ramips_mt7621': 'y',
    'CONFIG_TARGET_ramips_mt7621_DEVICE_iptime_t5004': 'y',
    'CONFIG_PACKAGE_kmod-wireguard': 'y',
    'CONFIG_PACKAGE_wireguard-tools': 'y',
    'CONFIG_PACKAGE_kmod-amneziawg': 'm',
    'CONFIG_PACKAGE_amneziawg-tools': 'm',
}


def verify_config(text):
    values = dict(line.split('=', 1) for line in text.splitlines() if line.startswith('CONFIG_') and '=' in line)
    for key, expected in REQUIRED_CONFIG.items():
        if values.get(key) != expected:
            raise ValueError(f'{key} must be {expected}, got {values.get(key)}')
    for package in ['microsocks', 'luci-proto-amneziawg']:
        if values.get(f'CONFIG_PACKAGE_{package}') in ('y', 'm'):
            raise ValueError(f'Unexpected package: {package}')
    devices = [key for key, value in values.items() if key.startswith('CONFIG_TARGET_ramips_mt7621_DEVICE_') and value == 'y']
    if devices != ['CONFIG_TARGET_ramips_mt7621_DEVICE_iptime_t5004']:
        raise ValueError('The build must target only ipTIME T5004')


def verify_manifest(text):
    packages = {line.split()[0] for line in text.splitlines() if line.strip()}
    if not {'kmod-wireguard', 'wireguard-tools'} <= packages:
        raise ValueError('WireGuard is missing from the firmware manifest')
    if packages & {'kmod-amneziawg', 'amneziawg-tools', 'microsocks'}:
        raise ValueError('Optional or excluded packages were installed into the firmware')
    return packages


def verify_kernel(work):
    candidates = list(work.glob('build_dir/target-*/linux-ramips_mt7621/linux-6.12.116'))
    if len(candidates) != 1:
        raise ValueError('Expected exactly one prepared Linux 6.12.116 tree')
    kernel = candidates[0]
    for filename, expression in [
        ('net/ipv4/af_inet.c', 'kfree_rcu(rcu_dereference_protected(inet->inet_opt, 1), rcu);'),
        ('net/ipv4/tcp_ipv4.c', 'kfree_rcu(rcu_dereference_protected(inet_rsk(req)->ireq_opt, 1), rcu);'),
    ]:
        if expression not in (kernel / filename).read_text():
            raise ValueError(f'CVE-2026-98432 correction missing from {filename}')
    release = (kernel / 'include/generated/utsrelease.h').read_text()
    if not re.search(r'^#define UTS_RELEASE "6\.12\.116"$', release, re.MULTILINE):
        raise ValueError('Compiled kernel release is not 6.12.116')
    return kernel


if __name__ == '__main__':
    mode, source = sys.argv[1:]
    if mode == 'config':
        verify_config(Path(source).read_text())
    elif mode == 'kernel':
        verify_kernel(Path(source))
    else:
        raise ValueError(f'Unknown validation mode: {mode}')
    print(f'{mode} validation passed')
