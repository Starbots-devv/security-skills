import importlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('starbots_security.assessment'),'Assessment module is not implemented')
        self.a=importlib.import_module('starbots_security.assessment')
    def test_missing_checks_are_explicit_unknown_and_blocked(self):
        with tempfile.TemporaryDirectory() as t:
            r=self.a.build_review(Path(t)/'result',{},client_id='fixture',project_id='test',as_of='2026-10-18T11:00:00Z')
            p=r['payload'];self.assertEqual(p['readiness']['state'],'BLOCKED')
            self.assertEqual(len(p['controls']),6);self.assertTrue(all(c['state']=='UNKNOWN' for c in p['controls']))
    def test_prior_unresolved_critical_cannot_disappear_on_partial_rerun(self):
        from starbots_security.io import load_json
        with tempfile.TemporaryDirectory() as t:
            prior=Path(t)/'prior';out=Path(t)/'next'
            finding=dict(id='known-critical',location='synthetic',severity='critical',severity_rationale='Synthetic regression fixture')
            self.a.build_review(prior,{'SB-AUTH':dict(state='UNKNOWN',errors=['Incomplete'],findings=[finding])},client_id='fixture',project_id='test',as_of='2026-10-18T11:00:00Z')
            result=self.a.build_review(out,{},client_id='fixture',project_id='test',as_of='2026-10-18T12:00:00Z',prior_assessment=prior/'security-assessment.json')
            self.assertEqual(len(result['payload']['findings']),1)
            self.assertEqual(result['payload']['findings'][0]['redacted_evidence_ref'],'prior-critical')
            self.assertTrue(any('unresolved critical' in x for x in result['payload']['readiness']['reasons']))
    def test_assessment_cannot_outlive_trusted_advisory_snapshot(self):
        # Synthetic observation tests expiry policy, not scanner execution.
        from starbots_security.io import load_json,digest,ValidationError
        from starbots_security.contracts import verify_assessment
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)/'out'
            r=self.a.build_review(root,{'SB-DEPENDENCIES':dict(state='PASS',coverage={'performed':True},errors=[])},client_id='fixture',project_id='test',as_of='2026-10-25T01:00:00Z')
            self.assertLessEqual(r['payload']['expires_at'],'2026-10-25T02:02:48Z')
            with self.assertRaises(ValidationError):verify_assessment(root,dict(path='security-assessment.json',sha256=digest((root/'security-assessment.json').read_bytes())),load_json(root,'subject.json'),as_of='2026-10-25T03:00:00Z',expected_policy_id='starbots-local-review')
    def test_bound_evidence_rejects_tamper_client_expiry_and_wrong_policy(self):
        from starbots_security.io import load_json,ValidationError,digest
        from starbots_security.contracts import verify_assessment
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)/'result';self.a.build_review(root,{},client_id='fixture',project_id='test',as_of='2026-10-18T11:00:00Z')
            subject=load_json(root,'subject.json');ref={'path':'security-assessment.json','sha256':digest((root/'security-assessment.json').read_bytes())}
            verify_assessment(root,ref,subject,as_of='2026-10-18T11:00:00Z',expected_policy_id='starbots-local-review')
            with self.assertRaises(ValidationError):verify_assessment(root,ref,subject,as_of='2026-10-18T11:00:00Z')
            with self.assertRaises(ValidationError):verify_assessment(root,ref,subject,as_of='2026-10-20T11:00:00Z',expected_policy_id='starbots-local-review')
            path=next(x['path'] for x in subject['payload']['artifacts'] if x['role']=='observation')
            (root/path).write_text('tampered')
            with self.assertRaises(ValidationError):verify_assessment(root,ref,subject,as_of='2026-10-18T11:00:00Z',expected_policy_id='starbots-local-review')
    def test_forged_pass_without_execution_never_becomes_ready(self):
        obs={'SB-AUTH':dict(state='PASS',evidence={'approved':True},coverage={'executed':False},errors=[])}
        with tempfile.TemporaryDirectory() as t:
            r=self.a.build_review(Path(t)/'out',obs,client_id='fixture',project_id='test',as_of='2026-10-18T11:00:00Z')
            self.assertEqual(r['payload']['controls'][0]['state'],'UNKNOWN');self.assertEqual(r['payload']['readiness']['state'],'BLOCKED')
    def test_proposal_must_bind_the_actual_original_subject(self):
        from starbots_security.io import ValidationError
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(ValidationError):self.a.build_review(Path(t)/'out',{},client_id='fixture',project_id='test',as_of='2026-10-18T11:00:00Z',proposal=Path(t)/'absent/subject.json')
    def test_unknown_evidence_cannot_reference_unbound_proof(self):
        from starbots_security.io import load_json,write_bytes,json_bytes,digest,ValidationError
        from starbots_security.contracts import verify_assessment
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)/'out';a=self.a.build_review(root,{},client_id='fixture',project_id='test',as_of='2026-10-18T11:00:00Z')
            s=load_json(root,'subject.json');e=load_json(root,'evidence/SB-AUTH.json')
            proof=(root/'observations/SB-AUTH.json').read_bytes();write_bytes(root,'unbound.json',proof)
            e['payload']['artifact_path']='unbound.json';raw=json_bytes(e);write_bytes(root,'evidence/SB-AUTH.json',raw)
            for refs in (s['payload']['artifacts'],a['payload']['evidence_refs']):
                for r in refs:
                    if r['path']=='evidence/SB-AUTH.json':r['sha256']=digest(raw)
            manifest=load_json(root,'subject-manifest.json');manifest['artifacts']=s['payload']['artifacts'];raw=json_bytes(manifest);write_bytes(root,'subject-manifest.json',raw)
            s['payload']['manifest_sha256']=digest(raw);write_bytes(root,'subject.json',json_bytes(s));a['payload']['subject_ref']=s['payload'];raw=json_bytes(a);write_bytes(root,'security-assessment.json',raw)
            with self.assertRaises(ValidationError):verify_assessment(root,dict(path='security-assessment.json',sha256=digest(raw)),s,as_of='2026-10-18T11:00:00Z',expected_policy_id='starbots-local-review')
if __name__=='__main__':unittest.main()
