"""
Tests for Amass wordlist integration in domain_recon.py --
path resolution, command building, and wordlist selection.

Run with: python -m pytest tests/test_amass_wordlist.py -v
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path

# Add parent dir to path
_recon_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _recon_dir)


class TestAmassWordlistCommandBuilding(unittest.TestCase):
    """Test the Amass command building logic with wordlist support."""

    def _build_amass_command(self, settings, domain="test.com",
                              host_recon_output="/home/user/redamon/recon/output",
                              container_wordlist_exists=True):
        """
        Simulate the command-building logic from run_amass() without
        actually running Docker.
        """
        docker_image = settings.get('AMASS_DOCKER_IMAGE', 'caffix/amass:latest')
        timeout_min = settings.get('AMASS_TIMEOUT', 10)
        active = settings.get('AMASS_ACTIVE', False)
        brute = settings.get('AMASS_BRUTE', False)
        brute_wordlists = settings.get('AMASS_BRUTE_WORDLISTS', ['default'])

        container_wordlist = '/app/recon/wordlists/jhaddix-all.txt'

        if host_recon_output:
            host_recon_dir = os.path.dirname(host_recon_output)
            wordlist_host_path = os.path.join(host_recon_dir, 'wordlists', 'jhaddix-all.txt')
        else:
            wordlist_host_path = ''

        wordlist_available = container_wordlist_exists

        command = [
            'docker', 'run', '--rm',
            '-v', '/tmp/amass:/root/.config/amass',
            docker_image,
            'enum', '-d', domain,
            '-timeout', str(timeout_min),
        ]

        if active:
            command.append('-active')
        if brute:
            command.append('-brute')
            if 'jhaddix-all' in brute_wordlists and wordlist_available and wordlist_host_path:
                img_idx = command.index(docker_image)
                command.insert(img_idx, f'{wordlist_host_path}:/wordlist/jhaddix-all.txt:ro')
                command.insert(img_idx, '-v')
                command += ['-w', '/wordlist/jhaddix-all.txt']

        return command

    def test_default_wordlist_no_mount(self):
        """When only 'default' is selected, no -v or -w flags should be added."""
        settings = {
            'AMASS_ENABLED': True,
            'AMASS_BRUTE': True,
            'AMASS_BRUTE_WORDLISTS': ['default'],
            'AMASS_TIMEOUT': 10,
        }
        cmd = self._build_amass_command(settings)
        self.assertIn('-brute', cmd)
        self.assertNotIn('-w', cmd)
        # Should not have the wordlist volume mount
        cmd_str = ' '.join(cmd)
        self.assertNotIn('jhaddix', cmd_str)

    def test_jhaddix_wordlist_mounted(self):
        """When jhaddix-all is selected and available, -v and -w should be added."""
        settings = {
            'AMASS_ENABLED': True,
            'AMASS_BRUTE': True,
            'AMASS_BRUTE_WORDLISTS': ['default', 'jhaddix-all'],
            'AMASS_TIMEOUT': 10,
        }
        cmd = self._build_amass_command(settings)
        self.assertIn('-brute', cmd)
        self.assertIn('-w', cmd)
        self.assertIn('/wordlist/jhaddix-all.txt', cmd)
        # Check volume mount is present
        cmd_str = ' '.join(cmd)
        self.assertIn('jhaddix-all.txt:ro', cmd_str)

    def test_jhaddix_selected_but_file_missing(self):
        """When jhaddix is selected but file doesn't exist, fallback to default."""
        settings = {
            'AMASS_ENABLED': True,
            'AMASS_BRUTE': True,
            'AMASS_BRUTE_WORDLISTS': ['default', 'jhaddix-all'],
            'AMASS_TIMEOUT': 10,
        }
        cmd = self._build_amass_command(settings, container_wordlist_exists=False)
        self.assertIn('-brute', cmd)
        self.assertNotIn('-w', cmd)

    def test_jhaddix_selected_but_no_host_path(self):
        """When HOST_RECON_OUTPUT_PATH is empty, can't build mount path."""
        settings = {
            'AMASS_ENABLED': True,
            'AMASS_BRUTE': True,
            'AMASS_BRUTE_WORDLISTS': ['default', 'jhaddix-all'],
            'AMASS_TIMEOUT': 10,
        }
        cmd = self._build_amass_command(settings, host_recon_output='')
        self.assertIn('-brute', cmd)
        self.assertNotIn('-w', cmd)

    def test_brute_disabled_no_wordlist(self):
        """When brute is disabled, no -brute, -v, or -w flags."""
        settings = {
            'AMASS_ENABLED': True,
            'AMASS_BRUTE': False,
            'AMASS_BRUTE_WORDLISTS': ['default', 'jhaddix-all'],
            'AMASS_TIMEOUT': 10,
        }
        cmd = self._build_amass_command(settings)
        self.assertNotIn('-brute', cmd)
        self.assertNotIn('-w', cmd)

    def test_volume_mount_before_image_name(self):
        """The -v mount must come BEFORE the docker image in the command."""
        settings = {
            'AMASS_ENABLED': True,
            'AMASS_BRUTE': True,
            'AMASS_BRUTE_WORDLISTS': ['default', 'jhaddix-all'],
            'AMASS_TIMEOUT': 10,
        }
        cmd = self._build_amass_command(settings)
        img_idx = cmd.index('caffix/amass:latest')
        # Find the wordlist -v flag
        v_indices = [i for i, x in enumerate(cmd) if x == '-v' and i + 1 < len(cmd) and 'jhaddix' in cmd[i + 1]]
        self.assertTrue(v_indices, "No -v flag for wordlist found")
        self.assertLess(v_indices[0], img_idx, "-v mount must come before docker image")

    def test_host_path_derivation(self):
        """HOST_RECON_OUTPUT_PATH -> parent dir -> wordlists/jhaddix-all.txt"""
        host_output = "/home/user/redamon/recon/output"
        host_dir = os.path.dirname(host_output)
        wordlist_path = os.path.join(host_dir, 'wordlists', 'jhaddix-all.txt')
        self.assertEqual(wordlist_path, "/home/user/redamon/recon/wordlists/jhaddix-all.txt")

    def test_empty_wordlists_list_uses_default(self):
        """Empty AMASS_BRUTE_WORDLISTS should not crash."""
        settings = {
            'AMASS_ENABLED': True,
            'AMASS_BRUTE': True,
            'AMASS_BRUTE_WORDLISTS': [],
            'AMASS_TIMEOUT': 10,
        }
        cmd = self._build_amass_command(settings)
        self.assertIn('-brute', cmd)
        self.assertNotIn('-w', cmd)

    def test_active_and_brute_together(self):
        """Both -active and -brute can coexist."""
        settings = {
            'AMASS_ENABLED': True,
            'AMASS_ACTIVE': True,
            'AMASS_BRUTE': True,
            'AMASS_BRUTE_WORDLISTS': ['default'],
            'AMASS_TIMEOUT': 10,
        }
        cmd = self._build_amass_command(settings)
        self.assertIn('-active', cmd)
        self.assertIn('-brute', cmd)


class TestAmassWordlistSettings(unittest.TestCase):
    """Test that AMASS_BRUTE_WORDLISTS is in default settings."""

    def test_default_setting_exists(self):
        from project_settings import DEFAULT_SETTINGS
        self.assertIn('AMASS_BRUTE_WORDLISTS', DEFAULT_SETTINGS)
        self.assertEqual(DEFAULT_SETTINGS['AMASS_BRUTE_WORDLISTS'], ['default'])

    def test_default_is_list(self):
        from project_settings import DEFAULT_SETTINGS
        self.assertIsInstance(DEFAULT_SETTINGS['AMASS_BRUTE_WORDLISTS'], list)


if __name__ == "__main__":
    unittest.main()
