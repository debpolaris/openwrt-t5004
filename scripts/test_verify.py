import unittest
from pathlib import Path

from prepare import replace_assignment
from verify import verify_config, verify_manifest

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


if __name__ == '__main__':
    unittest.main()
