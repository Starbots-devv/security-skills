import copy
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

PACKAGE = "starbots_security"

def evidence():
    return {"schema_version":"1.0.0","kind":"Evidence","id":"evidence-1","client_id":"fictional","project_id":"workers","created_at":"2026-10-17T00:00:00Z","producer":{"name":"fixture","version":"1","source_commit":"UNRELEASED"},"payload":{"evidence_type":"manual-review","source":"local","source_uri":"synthetic://fixture","observed_at":"2026-10-17T00:00:00Z","valid_until":"2026-11-01T00:00:00Z","classification":"synthetic","evidence_level":"synthetic","artifact_path":"proof.txt","artifact_sha256":"a"*64,"redaction_status":"synthetic","collector":"fixture","tool_version":None,"rules_digest":None,"authorized_scope_id":"fictional-local"}}

class ContractTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec(PACKAGE+'.contracts'), 'Versioned contracts are not implemented')
        self.contracts=importlib.import_module(PACKAGE+'.contracts')
        self.io=importlib.import_module(PACKAGE+'.io')

    def test_evidence_round_trip(self):
        self.contracts.validate(evidence(), expected_kind='Evidence')

    def test_closed_envelope_and_payload(self):
        for target in ('root','payload'):
            d=evidence(); (d if target=='root' else d['payload'])['approved']=True
            with self.assertRaises(self.io.ValidationError): self.contracts.validate(d)

    def test_unknown_version_and_wrong_kind_fail(self):
        d=evidence();d['schema_version']='2.0.0'
        with self.assertRaises(self.io.ValidationError):self.contracts.validate(d)
        with self.assertRaises(self.io.ValidationError):self.contracts.validate(evidence(),expected_kind='Scenario')

    def test_invalid_date_and_scope_fail(self):
        for field,value in [('created_at','2026-02-31T00:00:00Z'),('client_id','../other')]:
            d=evidence();d[field]=value
            with self.assertRaises(self.io.ValidationError):self.contracts.validate(d)
        with self.assertRaises(self.io.ValidationError):self.contracts.validate(evidence(),client_id='another-client')

    def test_freshness_is_explicit_and_future_evidence_fails(self):
        with self.assertRaises(self.io.ValidationError):self.contracts.validate(evidence(),as_of='2026-12-01T00:00:00Z')
        with self.assertRaises(self.io.ValidationError):self.contracts.validate(evidence(),as_of='2026-10-01T00:00:00Z')

    def test_duplicate_keys_floats_nonfinite_and_unicode_keys_fail(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'input.json'
            for raw in ('{"id":1,"id":2}','{"x":0.1}','{"x":NaN}','{"x":9007199254740992}','{"é":1}'):
                p.write_text(raw,encoding='utf-8')
                with self.assertRaises(self.io.ValidationError):self.io.load_json(t,'input.json')

    def test_depth_and_size_limits(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'input.json';p.write_text('['*34+'0'+']'*34)
            with self.assertRaises(self.io.ValidationError):self.io.load_json(t,'input.json')
            p.write_text('"'+'a'*40+'"')
            with self.assertRaises(self.io.ValidationError):self.io.load_json(t,'input.json',max_bytes=20)

    def test_paths_cannot_escape_or_use_windows_devices(self):
        with tempfile.TemporaryDirectory() as t:
            for path in ('../outside.json','/outside.json','C:/outside.json','a/../../x','NUL.json','a:stream','a/CON.txt','a\\..\\x'):
                with self.subTest(path=path):
                    with self.assertRaises(self.io.ValidationError):self.io.resolve_local(t,path)

    def test_manifest_binds_bytes_and_client(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);(root/'proof.txt').write_bytes(b'proof')
            artifact={'role':'evidence','path':'proof.txt','sha256':hashlib.sha256(b'proof').hexdigest()}
            manifest={'subject_id':'subject-1','revision':'1','client_id':'fictional','project_id':'workers','artifacts':[artifact]}
            raw=self.io.json_bytes(manifest);(root/'subject-manifest.json').write_bytes(raw)
            subject=evidence();subject['kind']='SubjectRef';subject['payload']={'subject_id':'subject-1','revision':'1','manifest_path':'subject-manifest.json','manifest_sha256':hashlib.sha256(raw).hexdigest(),'artifacts':[artifact]}
            self.contracts.validate(subject)
            self.io.verify_subject(root,subject,client_id='fictional',project_id='workers')
            with self.assertRaises(self.io.ValidationError):self.io.verify_subject(root,subject,client_id='other',project_id='workers')
            (root/'proof.txt').write_bytes(b'changed')
            with self.assertRaises(self.io.ValidationError):self.io.verify_subject(root,subject,client_id='fictional',project_id='workers')

    def test_protocol_integrity_and_no_network_schema_resolution(self):
        self.contracts.verify_protocol()
        with patch('socket.socket',side_effect=AssertionError('Network forbidden')):
            self.contracts.validate(evidence())
        with tempfile.TemporaryDirectory() as t:
            self.contracts.export_protocol(t,source_commit='a'*40)
            self.contracts.verify_protocol_path(t,self.contracts.protocol_digest())
            p=Path(t)/'readiness-table.json';p.write_bytes(p.read_bytes()+b' ')
            with self.assertRaises(self.io.ValidationError):self.contracts.verify_protocol_path(t,self.contracts.protocol_digest())

    def test_readiness_never_trusts_boolean_or_missing_proof(self):
        controls=[{'id':'SB-AUTH','mandatory':True,'state':'PASS','evidence_refs':[],'rationale':'Claim without proof','external_refs':[]}]
        result=self.contracts.readiness(controls,[],{'performed':['SB-AUTH'],'missing':[],'excluded':[]},set())
        self.assertEqual(result['state'],'BLOCKED')
        controls[0]['state']='UNKNOWN'
        result=self.contracts.readiness(controls,[],{'performed':[],'missing':['SB-AUTH'],'excluded':[]},set())
        self.assertEqual(result['state'],'BLOCKED')

if __name__=='__main__':unittest.main()
