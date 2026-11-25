import re
import sys
import tarfile
from pathlib import Path

REQUIRED_CONFIG = {
    'CONFIG_TARGET_ramips': 'y',
    'CONFIG_TARGET_ramips_mt7621': 'y',
    'CONFIG_TARGET_ramips_mt7621_DEVICE_iptime_t5004': 'y',
    'CONFIG_PACKAGE_dropbear': 'y',
    'CONFIG_DROPBEAR_SFTPSERVER': 'y',
    'CONFIG_PACKAGE_openssh-sftp-server': 'y',
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
    for key, value in values.items():
        if key.startswith('CONFIG_PACKAGE_openssh-') and value in ('y', 'm') and key != 'CONFIG_PACKAGE_openssh-sftp-server':
            raise ValueError(f'Only openssh-sftp-server may be installed: {key}')
    devices = [key for key, value in values.items() if key.startswith('CONFIG_TARGET_ramips_mt7621_DEVICE_') and value == 'y']
    if devices != ['CONFIG_TARGET_ramips_mt7621_DEVICE_iptime_t5004']:
        raise ValueError('The build must target only ipTIME T5004')


def verify_manifest(text):
    packages = {line.split()[0] for line in text.splitlines() if line.strip()}
    if not {'dropbear', 'openssh-sftp-server', 'kmod-wireguard', 'wireguard-tools'} <= packages:
        raise ValueError('Dropbear, SFTP, or WireGuard is missing from the firmware manifest')
    unexpected_openssh = {package for package in packages if package.startswith('openssh-') and package != 'openssh-sftp-server'}
    if unexpected_openssh:
        raise ValueError(f'Unexpected OpenSSH packages: {sorted(unexpected_openssh)}')
    if packages & {'kmod-amneziawg', 'amneziawg-tools', 'microsocks'}:
        raise ValueError('Optional or excluded packages were installed into the firmware')
    return packages


def verify_shadow(text):
    for line in text.splitlines():
        if line.split(':')[1] not in ('', '*', '!', 'x'):
            raise ValueError('Password hashes must not be embedded')


def verify_metadata(metadata):
    if metadata.get('compat_version') != '1.1':
        raise ValueError('Unexpected T5004 DSA compatibility version')
    if 'iptime,t5004' not in metadata.get('new_supported_devices', []):
        raise ValueError('Sysupgrade trailer does not identify T5004')
    if metadata.get('version', {}).get('target') != 'ramips/mt7621':
        raise ValueError('Unexpected sysupgrade target')


def verify_sysupgrade(path):
    prefix = 'sysupgrade-iptime_t5004/'
    with tarfile.open(path) as image:
        members = image.getmembers()
        required = {}
        for name in ['CONTROL', 'kernel', 'root']:
            matches = [item for item in members if item.name == prefix + name]
            if len(matches) != 1 or not matches[0].isfile() or matches[0].size == 0:
                raise ValueError(f'Invalid sysupgrade member: {name}')
            required[name] = matches[0]
        if image.extractfile(required['CONTROL']).read().strip() != b'BOARD=iptime_t5004':
            raise ValueError('Unexpected sysupgrade board')
        if required['kernel'].size > 4 * 1024 * 1024:
            raise ValueError('Kernel exceeds the T5004 4 MiB partition')
        if image.extractfile(required['kernel']).read(4) != b'\x27\x05\x19\x56':
            raise ValueError('Expected a uImage kernel')
        if image.extractfile(required['root']).read(4) != b'hsqs':
            raise ValueError('Expected a SquashFS root filesystem')


def verify_kernel(work):
    candidates = list(work.glob('build_dir/target-*/linux-ramips_mt7621/linux-6.12.118'))
    if len(candidates) != 1:
        raise ValueError('Expected exactly one prepared Linux 6.12.118 tree')
    kernel = candidates[0]
    for filename, expression in [
        ('net/ipv4/af_inet.c', 'kfree_rcu(rcu_dereference_protected(inet->inet_opt, 1), rcu);'),
        ('net/ipv4/tcp_ipv4.c', 'kfree_rcu(rcu_dereference_protected(inet_rsk(req)->ireq_opt, 1), rcu);'),
    ]:
        if expression not in (kernel / filename).read_text():
            raise ValueError(f'CVE-2026-98432 correction missing from {filename}')
    noisytcp = {
        'net/ipv4/inet_hashtables.c': [
            'hlist_nulls_unhashed_lockless(&sk->sk_nulls_node)',
        ],
        'net/ipv6/inet6_hashtables.c': [
            'hlist_nulls_unhashed_lockless(&sk->sk_nulls_node)',
        ],
        'net/ipv4/inet_connection_sock.c': [
            '/* The timer was not armed, drop its reference here. */ reqsk_put(nreq); no_ownership: reqsk_migrate_reset(nreq); reqsk_queue_removed(queue, nreq); /* Drop the temporary reference and the one reserved for ehash. */ reqsk_put(nreq); reqsk_put(nreq);',
            '__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPMIGRATEREQFAILURE); reqsk_migrate_reset(nreq); reqsk_put(nreq);',
            '__NET_INC_STATS(sock_net(nsk), LINUX_MIB_TCPMIGRATEREQFAILURE); reqsk_migrate_reset(nreq); reqsk_put(nreq);',
        ],
        'net/ipv4/syncookies.c': [
            'bh_unlock_sock(child); sock_put(child); reqsk_put(req); return NULL;',
        ],
        'net/ipv4/tcp_input.c': [
            '/* tcp_disconnect() already dropped one reqsk ref. */ reqsk_put(req); goto drop;',
        ],
    }
    for filename, expressions in noisytcp.items():
        source = re.sub(r'\s+', ' ', (kernel / filename).read_text()).strip()
        for expression in expressions:
            if expression not in source:
                raise ValueError(f'CVE-2026-99288 correction missing from {filename}')
    release = (kernel / 'include/generated/utsrelease.h').read_text()
    if not re.search(r'^#define UTS_RELEASE "6\.12\.118"$', release, re.MULTILINE):
        raise ValueError('Compiled kernel release is not 6.12.118')
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
