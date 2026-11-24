"""Explicit local scanner integration gate; missing prerequisites fail, never skip."""
import json
import os
from pathlib import Path
import unittest
import tempfile
from unittest.mock import patch
from starbots_security.runner import run_scanner


class RealScanners(unittest.TestCase):
    def test_inline_suppression_is_unknown_without_process_execution(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d,'main.tf').write_text('# trivy:ignore:AVD-AWS-0107\nresource "aws_s3_bucket" "synthetic" {}\n')
            with patch('starbots_security.runner.bounded_process',side_effect=AssertionError('Suppressed input must not execute')) as process:
                r=run_scanner('trivy',d,d,as_of='2026-10-18T21:33:00Z')
            process.assert_not_called();self.assertEqual(r['state'],'UNKNOWN');self.assertIn('suppression',' '.join(r['errors']))

    def test_vulnerable_and_corrected_synthetic_fixtures(self):
        self.assertTrue('STARBOTS_TOOLCHAIN' in os.environ, 'Set the reviewed STARBOTS_TOOLCHAIN directory for this explicit integration gate')
        product = Path(__file__).resolve().parents[2]
        fixtures = product / 'src/starbots_security/data/scanners'
        evidence = Path(os.environ['STARBOTS_SCANNER_EVIDENCE']) if 'STARBOTS_SCANNER_EVIDENCE' in os.environ else None
        for variant, state in [('vulnerable', 'FAIL'), ('corrected', 'PASS')]:
            for fixture, tool in [('gitleaks', 'gitleaks'), ('osv-npm', 'osv-scanner'), ('osv-python', 'osv-scanner'), ('trivy', 'trivy')]:
                with self.subTest(variant=variant, fixture=fixture):
                    observation = run_scanner(tool, fixtures / variant / fixture, os.environ['STARBOTS_TOOLCHAIN'], as_of='2026-10-18T12:00:00Z')
                    if evidence:
                        evidence.mkdir(parents=True, exist_ok=True)
                        (evidence / (variant + '-' + fixture + '.json')).write_text(json.dumps(observation, indent=2), encoding='utf-8')
                    self.assertEqual(observation['state'], state, observation['errors'])
                    self.assertTrue(observation['coverage']['performed'])
                    self.assertTrue(observation['provenance']['container_removed'])
                    self.assertIn('tool_version',observation['provenance'])
                    self.assertEqual(observation['provenance']['sandbox']['network'],'none')
                    self.assertNotRegex(json.dumps(observation),r'(?i)[a-z]:[\\/]+users[\\/]')
                    if fixture=='gitleaks':
                        self.assertNotIn('ghp_FAKE0123456789TOKENabcdefghijklmnopq',json.dumps(observation))


if __name__ == '__main__': unittest.main()
