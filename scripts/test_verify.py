import io
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

from prepare import replace_assignment
from verify import verify_config, verify_kernel, verify_manifest, verify_metadata, verify_sysupgrade

ROOT = Path(__file__).resolve().parents[1]


class BuildValidationTests(unittest.TestCase):
    def test_seed_configuration(self):
        verify_config((ROOT / 'config/t5004.config').read_text())

    def test_awg_must_not_be_in_firmware(self):
        text = (ROOT / 'config/t5004.config').read_text().replace('CONFIG_PACKAGE_kmod-amneziawg=m', 'CONFIG_PACKAGE_kmod-amneziawg=y')
        with self.assertRaises(ValueError):
            verify_config(text)

    def test_second_device_is_rejected(self):
        text = (ROOT / 'config/t5004.config').read_text() + 'CONFIG_TARGET_ramips_mt7621_DEVICE_other=y\n'
        with self.assertRaises(ValueError):
            verify_config(text)

    def test_manifest_requires_wireguard(self):
        with self.assertRaises(ValueError):
            verify_manifest('base-files - 1\n')

    def test_manifest_excludes_optional_packages(self):
        with self.assertRaises(ValueError):
            verify_manifest('kmod-wireguard - 1\nwireguard-tools - 1\namneziawg-tools - 1\n')

    def test_valid_manifest(self):
        verify_manifest('kmod-wireguard - 1\nwireguard-tools - 1\nbase-files - 1\n')

    def test_recipe_version_replacement(self):
        self.assertEqual(replace_assignment('PKG_VERSION:=old\n', 'PKG_VERSION', 'new'), 'PKG_VERSION:=new\n')

    def test_recipe_changes_fail_closed(self):
        with self.assertRaises(ValueError):
            replace_assignment('OTHER:=old\n', 'PKG_VERSION', 'new')


class KernelValidationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.work = Path(directory.name)
        self.kernel = self.work / 'build_dir/target-mipsel/linux-ramips_mt7621/linux-6.12.116'
        (self.kernel / 'net/ipv4').mkdir(parents=True)
        (self.kernel / 'include/generated').mkdir(parents=True)
        (self.kernel / 'net/ipv4/af_inet.c').write_text('kfree_rcu(rcu_dereference_protected(inet->inet_opt, 1), rcu);\n')
        (self.kernel / 'net/ipv4/tcp_ipv4.c').write_text('kfree_rcu(rcu_dereference_protected(inet_rsk(req)->ireq_opt, 1), rcu);\n')
        (self.kernel / 'include/generated/utsrelease.h').write_text('#define UTS_RELEASE "6.12.116"\n')

    def test_patched_kernel(self):
        self.assertEqual(verify_kernel(self.work), self.kernel)

    def test_both_security_corrections_are_required(self):
        for filename in ['af_inet.c', 'tcp_ipv4.c']:
            with self.subTest(filename=filename):
                source = self.kernel / 'net/ipv4' / filename
                original = source.read_text()
                source.write_text(original.replace('kfree_rcu', 'kfree'))
                with self.assertRaisesRegex(ValueError, 'correction missing'):
                    verify_kernel(self.work)
                source.write_text(original)

    def test_compiled_release_must_match(self):
        (self.kernel / 'include/generated/utsrelease.h').write_text('#define UTS_RELEASE "6.12.112"\n')
        with self.assertRaisesRegex(ValueError, 'Compiled kernel release'):
            verify_kernel(self.work)

    def test_ambiguous_kernel_tree_is_rejected(self):
        (self.work / 'build_dir/target-other/linux-ramips_mt7621/linux-6.12.116').mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            verify_kernel(self.work)


class ImageValidationTests(unittest.TestCase):
    @unittest.skipUnless(all(shutil.which(tool) for tool in ['fakeroot', 'mksquashfs', 'unsquashfs']), 'SquashFS host tools unavailable')
    def test_unprivileged_device_node_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            (source / 'dev').mkdir(parents=True)
            (source / 'payload').write_text('verified')
            image = root / 'root.squashfs'
            command = 'mknod "$1/dev/console" c 5 1 && mksquashfs "$1" "$2" -noappend -no-progress -processors 1'
            subprocess.run(['fakeroot', 'sh', '-c', command, 'sh', str(source), str(image)], check=True, stdout=subprocess.DEVNULL)
            output = root / 'unpacked'
            subprocess.run(['fakeroot', 'unsquashfs', '-no-progress', '-d', str(output), str(image)], check=True, stdout=subprocess.DEVNULL)
            self.assertEqual((output / 'payload').read_text(), 'verified')
            self.assertTrue((output / 'dev/console').exists())

    def test_dsa_metadata(self):
        verify_metadata({'compat_version': '1.1', 'new_supported_devices': ['iptime,t5004'],
                         'supported_devices': ['Image version mismatch'], 'version': {'target': 'ramips/mt7621'}})

    def test_wrong_metadata(self):
        with self.assertRaises(ValueError):
            verify_metadata({'compat_version': '1.0', 'supported_devices': ['iptime,t5004']})
        with self.assertRaises(ValueError):
            verify_metadata({'compat_version': '1.1', 'new_supported_devices': ['other,device']})

    def test_sysupgrade_members(self):
        cases = [
            ('valid', b'BOARD=iptime_t5004\n', b'\x27\x05\x19\x56data', b'hsqsdata', False, True),
            ('wrong board', b'BOARD=other\n', b'\x27\x05\x19\x56data', b'hsqsdata', False, False),
            ('wrong header', b'BOARD=iptime_t5004\n', b'not uImage', b'hsqsdata', False, False),
            ('empty root', b'BOARD=iptime_t5004\n', b'\x27\x05\x19\x56data', b'', False, False),
            ('symlink root', b'BOARD=iptime_t5004\n', b'\x27\x05\x19\x56data', b'hsqsdata', True, False),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'image.bin'
            for name, control, kernel, root, link, valid in cases:
                with self.subTest(name=name):
                    with tarfile.open(path, 'w') as image:
                        for member, data in [('CONTROL', control), ('kernel', kernel), ('root', root)]:
                            info = tarfile.TarInfo(f'sysupgrade-iptime_t5004/{member}')
                            if link and member == 'root':
                                info.type = tarfile.SYMTYPE
                                info.linkname = 'kernel'
                                image.addfile(info)
                            else:
                                info.size = len(data)
                                image.addfile(info, io.BytesIO(data))
                    if valid:
                        verify_sysupgrade(path)
                    else:
                        with self.assertRaises(ValueError):
                            verify_sysupgrade(path)


if __name__ == '__main__':
    unittest.main()
