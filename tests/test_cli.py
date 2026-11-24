import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from starbots_security.cli import main

class CLITests(unittest.TestCase):
    def invoke(self,args):
        out=io.StringIO()
        with contextlib.redirect_stdout(out):code=main(args)
        return code,json.loads(out.getvalue())
    def test_actual_agent_review_and_digest_verification(self):
        with tempfile.TemporaryDirectory() as t:
            out=str(Path(t)/'review')
            code,result=self.invoke(['assess-fixture','--variant','corrected','--skill','agent-tools','--output-dir',out,'--client-id','synthetic','--project-id','fixture','--as-of','2026-10-18T22:00:00Z'])
            self.assertEqual(code,3);self.assertEqual(result['readiness'],'BLOCKED')
            self.assertFalse(result['execution_eligible'])
            args=['verify-assessment','--review-dir',out,'--assessment-sha256',result['assessment_sha256'],'--client-id','synthetic','--project-id','fixture','--as-of','2026-10-18T22:00:00Z']
            self.assertEqual(self.invoke(args)[0],3)
            args[args.index(result['assessment_sha256'])]='0'*64
            self.assertEqual(self.invoke(args)[0],2)
    def test_imported_clean_scanner_data_remains_unknown(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'result.json';p.write_text('[]')
            code,result=self.invoke(['import-result','--tool','gitleaks','--input',str(p)])
            self.assertEqual(code,0);self.assertEqual(result['state'],'UNKNOWN')
