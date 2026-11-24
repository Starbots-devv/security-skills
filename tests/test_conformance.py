import copy
import importlib
import json
from pathlib import Path
import tempfile
import unittest

PACKAGE='starbots_security'

class ConformanceTests(unittest.TestCase):
    def setUp(self):
        self.c=importlib.import_module(PACKAGE+'.contracts')
        self.io=importlib.import_module(PACKAGE+'.io')

    def test_every_shipped_schema_has_positive_and_negative_fixture(self):
        root=Path(__file__).resolve().parents[1]/'examples/contracts'
        self.assertTrue(root.exists(),'Contract fixtures are not implemented')
        schemas,_=self.c._schemas()
        self.assertEqual({p.stem for p in root.glob('*.json')},set(schemas))
        for p in root.glob('*.json'):
            with self.subTest(kind=p.stem):
                d=json.loads(p.read_text());self.c.validate(d)
                d['payload']['unapproved_field']=True
                with self.assertRaises(self.io.ValidationError):self.c.validate(d)

    def test_all_readiness_vectors_are_shared(self):
        vectors=self.io.parse_json(self.c._protocol().joinpath('conformance-vectors.json').read_bytes())
        for v in vectors:
            c={'id':'SB-AUTH','mandatory':True,'state':v['state'],'evidence_refs':['proof'] if v['evidence_present'] else [],'rationale':'Synthetic conformance case','external_refs':[]}
            r=self.c.readiness([c],[],{'performed':['SB-AUTH'],'missing':[],'excluded':[]},{'proof'} if v['evidence_present'] else set())
            self.assertEqual(r['state'],v['expected'])

    def test_artifact_verifier_is_implemented_and_rejects_missing_subject(self):
        verifier=getattr(self.c,'verify_assessment',None)
        self.assertTrue(callable(verifier),'Evidence-backed assessment verification is not implemented')
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(self.io.ValidationError):verifier(t,{'path':'missing.json','sha256':'a'*64},None,as_of='2026-10-17T00:00:00Z')

    def test_protocol_source_and_packaged_snapshot_match(self):
        root=Path(__file__).resolve().parents[1]
        base=root/('contracts/1.0.0' if PACKAGE=='starbots_security' else 'vendor/security-protocol/1.0.0')
        manifest=self.c.verify_protocol()
        for name in [*manifest['files'],'manifest.json']:
            self.assertEqual((base/name).read_bytes(),self.c._protocol().joinpath(name).read_bytes())

if __name__=='__main__':unittest.main()
