import importlib.util
import subprocess
import sys
import unittest

class BootstrapTests(unittest.TestCase):
    def test_installed_cli_starts_without_credentials(self):
        self.assertIsNotNone(importlib.util.find_spec('starbots_security'), 'Security package is not implemented')
        process = subprocess.run([sys.executable, '-m', 'starbots_security.cli', '--help'], capture_output=True, text=True)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertIn('sb-security', process.stdout)

if __name__ == '__main__':
    unittest.main()
