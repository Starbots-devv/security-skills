import importlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


class HTTPFixtureIntegrationTests(unittest.TestCase):
    def test_noneditable_wheel_outside_checkout_has_http_and_sql_resources(self):
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as directory:
            temporary=Path(directory); project=temporary/'build'; project.mkdir()
            for name in ['pyproject.toml','README.md','LICENSE']:
                shutil.copy2(root/name, project/name)
            shutil.copytree(root/'src',project/'src',ignore=shutil.ignore_patterns('__pycache__','*.egg-info'))
            built=subprocess.run([sys.executable,'-m','pip','wheel','--no-deps','--no-build-isolation',
                                  '--no-index','--wheel-dir',str(temporary/'wheels'),str(project)],
                                 capture_output=True,text=True)
            self.assertEqual(built.returncode,0,built.stdout+built.stderr)
            wheel=next((temporary/'wheels').glob('*.whl'))
            installed=subprocess.run([sys.executable,'-m','pip','install','--no-deps','--no-index',
                                      '--target',str(temporary/'installed'),str(wheel)],capture_output=True,text=True)
            self.assertEqual(installed.returncode,0,installed.stdout+installed.stderr)
            script="""import sys,json
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from starbots_security.application import run_api_fixture,run_rls_fixture
out=Path(sys.argv[2])
results=[run_api_fixture(v,out/v) for v in ['corrected','vulnerable']]
results.append(run_rls_fixture('corrected',out/'missing'))
assert [r['state'] for r in results]==['PASS','FAIL','UNKNOWN'],results
assert 'WITH CHECK' in results[-1]['evidence']['fixture_sql']
assert len(results[-1]['evidence']['fixture_sha256'])==64
runtime_file=sys.argv[3]
if runtime_file:
    runtime=json.loads(Path(runtime_file).read_text(encoding='utf-8-sig'))
    measured=[run_rls_fixture(v,out/('rls-'+v),runtime=runtime) for v in ['vulnerable','corrected']]
    assert [r['state'] for r in measured]==['FAIL','PASS'],measured
    assert all(r['evidence']['cleanup']['completed'] for r in measured)
    assert all(len(r['evidence']['probes'])==21 for r in measured)
print(json.dumps({'states':[r['state'] for r in results],'module':sys.modules['starbots_security.application'].__file__}))
"""
            ran=subprocess.run([sys.executable,'-I','-c',script,str(temporary/'installed'),str(temporary/'out'),
                                os.environ.get('STARBOTS_PG_RUNTIME','')],
                               cwd=temporary,capture_output=True,text=True)
            self.assertEqual(ran.returncode,0,ran.stdout+ran.stderr)
            self.assertIn(str(temporary/'installed'),json.loads(ran.stdout)['module'])

    def test_both_variants_are_measured_over_local_http(self):
        self.assertIsNotNone(importlib.util.find_spec('starbots_security.application'),
                             'Actual local HTTP fixture probes are required')
        app = importlib.import_module('starbots_security.application')
        for variant, expected in [('vulnerable', 'FAIL'), ('corrected', 'PASS')]:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                result = app.run_api_fixture(variant, directory)
                self.assertEqual(result['state'], expected, result)
                ids = {p['id'] for p in result['evidence']['probes']}
                self.assertTrue({'a-read-b', 'b-read-a', 'a-write-b', 'b-write-a',
                                 'same-tenant-other-user', 'wrong-role', 'sensitive-field',
                                 'bulk-member', 'export-member', 'forged-header',
                                 'unauthenticated', 'expired', 'a-legitimate-write',
                                 'b-legitimate-write'} <= ids)
