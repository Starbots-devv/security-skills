"""Software-owned fixture orchestration; imported observations never gain authority."""
from importlib.resources import files
from pathlib import Path
import tempfile
from .assessment import build_review, fresh_root, POLICY
from .contracts import validate, verify_assessment
from .io import digest, fail, load_json, read_bytes

def verify_review(root,expected_digest,*,client_id,project_id,as_of):
    root=Path(root);subject=load_json(root,'subject.json')
    validate(subject,expected_kind='SubjectRef',client_id=client_id,project_id=project_id)
    return verify_assessment(root,dict(path='security-assessment.json',sha256=expected_digest),subject,as_of=as_of,expected_policy_id=POLICY)

def execute_fixture(output_dir,*,variant,skill,client_id,project_id,as_of,toolchain_root=None,pg_runtime=None,proposal=None,prior_assessment=None):
    from .application import run_api_fixture,run_rls_fixture
    from .agent_boundary import run_harness
    fresh_root(output_dir)
    observations={};inputs={}
    with tempfile.TemporaryDirectory(prefix='sb-review-') as work:
        work=Path(work)
        if skill in ('all','app-api'):
            observations['SB-AUTH']=run_api_fixture(variant,work/'api')
            runtime=load_json(Path(pg_runtime).parent,Path(pg_runtime).name) if pg_runtime else None
            observations['SB-RLS']=run_rls_fixture(variant,work/'rls',runtime=runtime)
            resource=files(__package__).joinpath('data/application')
            for p in resource.rglob('*'):
                if p.is_file():inputs['application/'+p.relative_to(resource).as_posix()]=p.read_bytes()
        if skill in ('all','supply-chain'):
            from .runner import run_scanner
            if toolchain_root:
                base=files(__package__).joinpath('data/scanners',variant)
                for control,tool,fixture in [('SB-SECRETS','gitleaks','gitleaks'),('SB-IAC','trivy','trivy'),('SB-DEPENDENCIES','osv-scanner','osv-npm')]:
                    observations[control]=run_scanner(tool,base.joinpath(fixture),toolchain_root,as_of=as_of)
                second=run_scanner('osv-scanner',base.joinpath('osv-python'),toolchain_root,as_of=as_of)
                first=observations['SB-DEPENDENCIES'];parts=[first,second]
                observations['SB-DEPENDENCIES']=dict(state='UNKNOWN' if any(p['state']=='UNKNOWN' for p in parts) else ('FAIL' if any(p['state']=='FAIL' for p in parts) else 'PASS'),findings=[f for p in parts for f in p.get('findings',[])],errors=[e for p in parts for e in p.get('errors',[])],coverage=dict(performed=all(p.get('coverage',{}).get('performed') is True for p in parts)),evidence=dict(ecosystems=parts),provenance=dict(tool_version=first.get('provenance',{}).get('actual_version','unknown'),runs=[p.get('provenance',{}) for p in parts]))
                for p in base.rglob('*'):
                    if p.is_file():inputs['scanners/'+p.relative_to(base).as_posix()]=p.read_bytes()
            inputs['toolchain-lock.json']=files(__package__).joinpath('data/toolchain-lock.json').read_bytes()
        if skill in ('all','agent-tools'):
            observations['SB-AGENT-BOUNDARY']=run_harness(work/'harness',client_id,project_id)
            inputs['agent-corpus/note.txt']=read_bytes(work/'harness','artifacts/note.txt')
        for module in ('application.py','runner.py','adapters.py','agent_boundary.py','review.py'):
            inputs['evaluator/'+module]=Path(__file__).with_name(module).read_bytes()
        result=build_review(output_dir,observations,client_id=client_id,project_id=project_id,as_of=as_of,proposal=proposal,inputs=inputs,prior_assessment=prior_assessment)
    return result
