import copy
import importlib
from pathlib import Path
import tempfile
import subprocess
import os
import unittest
from test_contracts import evidence

PACKAGE='starbots_security'

class EvidenceChainTests(unittest.TestCase):
    def setUp(self):
        self.c=importlib.import_module(PACKAGE+'.contracts');self.io=importlib.import_module(PACKAGE+'.io')

    def build(self,root):
        raw=b'Local synthetic evidence, never a real customer test.'
        (root/'proof.txt').write_bytes(raw)
        e=evidence();e['id']='proof';e['payload']['artifact_sha256']=self.io.digest(raw)
        eraw=self.io.json_bytes(e);(root/'evidence.json').write_bytes(eraw)
        profile_raw=self.c._protocol().joinpath('control-profile.json').read_bytes();(root/'control-profile.json').write_bytes(profile_raw)
        artifacts=[{'role':'security-control-profile','path':'control-profile.json','sha256':self.io.digest(profile_raw)},{'role':'proof','path':'proof.txt','sha256':self.io.digest(raw)},{'role':'evidence','path':'evidence.json','sha256':self.io.digest(eraw)}]
        manifest={'subject_id':'subject-1','revision':'1','client_id':'fictional','project_id':'workers','artifacts':artifacts}
        mraw=self.io.json_bytes(manifest);(root/'subject-manifest.json').write_bytes(mraw)
        subject=self.c.envelope('SubjectRef','subject',{'subject_id':'subject-1','revision':'1','manifest_path':'subject-manifest.json','manifest_sha256':self.io.digest(mraw),'artifacts':artifacts},client_id='fictional',project_id='workers',created_at='2026-10-17T00:00:00Z')
        assessment=self.c.envelope('SecurityAssessment','assessment',{'subject_ref':subject['payload'],'policy_id':'protocol-demo-review','policy_version':'1.0.0','policy_digest':self.io.digest(self.c._protocol().joinpath('control-profile.json').read_bytes()),'assessed_at':'2026-10-17T00:00:00Z','expires_at':'2026-10-18T00:00:00Z','scope':'Synthetic fixture only','evidence_refs':[{'path':'evidence.json','sha256':self.io.digest(eraw)}],'tool_runs':[],'controls':[{'id':'SB-AUTH','mandatory':True,'state':'PASS','evidence_refs':['proof'],'rationale':'Local synthetic test evidence; no deployment authority','external_refs':[]}],'findings':[],'coverage':{'performed':['SB-AUTH'],'missing':[],'excluded':[]},'readiness':{'state':'READY','reasons':[]}},client_id='fictional',project_id='workers',created_at='2026-10-17T00:00:00Z')
        return subject,assessment

    def save(self,root,assessment):
        raw=self.io.json_bytes(assessment);(root/'assessment.json').write_bytes(raw)
        return {'path':'assessment.json','sha256':self.io.digest(raw)}

    def test_synthetic_chain_only_passes_explicit_demo_validation(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);subject,a=self.build(root);ref=self.save(root,a)
            self.c.verify_assessment(root,ref,subject,as_of='2026-10-17T00:00:00Z',allow_synthetic=True)
            with self.assertRaises(self.io.ValidationError):self.c.verify_assessment(root,ref,subject,as_of='2026-10-17T00:00:00Z')

    def test_false_readiness_uncovered_control_other_client_and_expiry_reject(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);subject,a=self.build(root)
            for field in ('scope','missing','policy','subject','client','expiry','tool_error','required_omitted','required_optional'):
                bad=copy.deepcopy(a)
                if field=='tool_error':bad['payload']['tool_runs']=[{'tool':'required-review','tool_version':'1','rules_digest':None,'advisory_digest':None,'status':'error','output_ref':None}]
                if field=='required_omitted':
                    bad['payload']['controls'][0]['id']='OTHER';bad['payload']['coverage']['performed']=['OTHER']
                if field=='required_optional':
                    bad['payload']['controls'][0]['mandatory']=False;extra=copy.deepcopy(bad['payload']['controls'][0]);extra.update(id='OTHER',mandatory=True);bad['payload']['controls'].append(extra);bad['payload']['coverage']['performed'].append('OTHER')
                if field=='scope':bad['payload']['controls'][0]['evidence_refs']=[]
                if field=='missing':bad['payload']['coverage']['missing']=['SB-AUTH']
                if field=='policy':bad['payload']['policy_digest']='b'*64
                if field=='subject':bad['payload']['subject_ref']['revision']='2'
                if field=='client':bad['client_id']='another-client'
                if field=='expiry':bad['payload']['expires_at']='2026-10-16T00:00:00Z'
                with self.subTest(field=field):
                    with self.assertRaises(self.io.ValidationError):self.c.verify_assessment(root,self.save(root,bad),subject,as_of='2026-10-17T00:00:00Z',allow_synthetic=True)

    def test_symlink_escape_is_denied_when_platform_allows_creation(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);outside=root/'outside';outside.mkdir();inside=root/'inside';inside.mkdir()
            try:(inside/'link').symlink_to(outside,target_is_directory=True)
            except OSError:
                if os.name!='nt': raise
                junction=subprocess.run(['cmd.exe','/c','mklink','/J',str(inside/'link'),str(outside)],capture_output=True,text=True)
                self.assertEqual(junction.returncode,0,'Neither symlink nor junction could be created for the escape regression')
            with self.assertRaises(self.io.ValidationError):self.io.resolve_local(inside,'link/proof.json')

if __name__=='__main__':unittest.main()
