"""Exact-subject local review builder. No execution approval or deployment surface."""
from datetime import timedelta
from pathlib import Path
from .contracts import control_profile, envelope, observation_state, producer, readiness, timestamp, validate, verify_assessment
from .io import digest, fail, json_bytes, load_json, read_bytes, verify_subject, write_bytes

POLICY='starbots-local-review'
TOOLS={'SB-AUTH':'api-fixture','SB-RLS':'postgresql-rls','SB-SECRETS':'gitleaks','SB-DEPENDENCIES':'osv-scanner','SB-IAC':'trivy','SB-AGENT-BOUNDARY':'agent-boundary'}

def fresh_root(path):
    root=Path(path).absolute()
    if any(p.is_symlink() or p.is_junction() for p in (root,*root.parents)):fail('PATH_DENIED','Review roots cannot traverse links or junctions')
    if root.exists() and (not root.is_dir() or any(root.iterdir())):fail('PATH_DENIED','Choose a fresh review output directory')
    return root

def _canonical(value):
    if isinstance(value,float):return str(value)
    if isinstance(value,dict):return {k:_canonical(v) for k,v in value.items()}
    if isinstance(value,list):return [_canonical(v) for v in value]
    return value

def build_review(output_dir,observations,*,client_id,project_id,as_of,proposal=None,inputs=None,prior_assessment=None):
    root=fresh_root(output_dir);profile,profile_raw=control_profile(POLICY);policy_hash=digest(profile_raw)
    expiry=timestamp(as_of)+timedelta(hours=24)
    if observation_state('SB-DEPENDENCIES',observations.get('SB-DEPENDENCIES'))[1]:
        expiry=min(expiry,timestamp(profile['advisory_snapshot_expires_at']))
        if expiry<=timestamp(as_of):fail('EVIDENCE_STALE','Advisory snapshot has expired')
    until=expiry.strftime('%Y-%m-%dT%H:%M:%SZ')
    artifacts=[];paths=set();evidence_refs=[];controls=[];runs=[];findings=[];verified=set();performed=[];missing=[]
    def add(path,raw,role):
        if path in paths:fail('INVALID_SCHEMA','Duplicate review artifact path')
        paths.add(path);write_bytes(root,path,raw);ref=dict(path=path,sha256=digest(raw));artifacts.append(dict(role=role,**ref));return ref
    # Validate the proposal identity and bytes before exporting any input into the review root.
    proposal_files=[]
    if proposal is not None:
        original=Path(proposal);subject=load_json(original.parent,original.name)
        validate(subject,expected_kind='SubjectRef',client_id=client_id,project_id=project_id)
        verify_subject(original.parent,subject,client_id=client_id,project_id=project_id)
        proposal_files=[('proposal/subject.json',read_bytes(original.parent,original.name),'proposal-subject'),('proposal/'+subject['payload']['manifest_path'],read_bytes(original.parent,subject['payload']['manifest_path']),'proposal-manifest')]
        proposal_files.extend(('proposal/'+a['path'],read_bytes(original.parent,a['path']),'proposal-artifact') for a in subject['payload']['artifacts'])
    for path,raw,role in proposal_files:add(path,raw,role)
    add('security-control-profile.json',profile_raw,'security-control-profile')
    for path,raw in (inputs or {}).items():add('inputs/'+path,raw,'evaluated-input')
    add('evaluator/contracts.py',Path(__file__).with_name('contracts.py').read_bytes(),'evaluator-source')
    add('evaluator/assessment.py',Path(__file__).read_bytes(),'evaluator-source')
    for required in profile['required_controls']:
        id=required['id'];obs=_canonical(observations.get(id,dict(state='UNKNOWN',errors=['Required check was not executed'],coverage={'executed':False},evidence={})))
        state,did_run=observation_state(id,obs);proof=dict(control_id=id,observation=obs)
        proof_ref=add('observations/'+id+'.json',json_bytes(proof),'observation')
        provenance=obs.get('provenance',{})
        tool_version=str(provenance.get('actual_version',provenance.get('tool_version','local-fixture-1')))
        records=provenance.get('runs',[provenance])
        rule_records=[{k:v for k,v in r.get('artifact_hashes',{}).items() if not k.startswith('osv-db/')} for r in records]
        db_records=[{k:v for k,v in r.get('artifact_hashes',{}).items() if k.startswith('osv-db/')} for r in records]
        rules_hash=digest(json_bytes(rule_records)) if any(rule_records) else policy_hash
        advisory_hash=digest(json_bytes(db_records)) if any(db_records) else None
        eid='evidence-'+id
        evidence=envelope('Evidence',eid,dict(evidence_type='Executed local synthetic fixture observation' if did_run else 'Missing or incomplete local check',source='tool' if did_run else 'local',source_uri='local://review/observations/'+id,observed_at=as_of,valid_until=until,classification='synthetic',evidence_level='measured' if did_run else 'unknown',artifact_path=proof_ref['path'],artifact_sha256=proof_ref['sha256'],redaction_status='synthetic',collector=TOOLS[id],tool_version=tool_version,rules_digest=rules_hash,authorized_scope_id=project_id),client_id=client_id,project_id=project_id,created_at=as_of)
        validate(evidence);evidence_refs.append(add('evidence/'+id+'.json',json_bytes(evidence),'evidence'))
        if did_run:verified.add(eid);performed.append(id)
        else:missing.append(id)
        rationale=required['description']+'; '+('actual local experiment, only this fixture scope' if did_run else 'missing, failed or incomplete execution; no assurance')
        controls.append(dict(id=id,mandatory=True,state=state,evidence_refs=[eid],rationale=rationale,external_refs=[]))
        runs.append(dict(tool=TOOLS[id],tool_version=evidence['payload']['tool_version'],rules_digest=rules_hash,advisory_digest=advisory_hash,status='executed' if did_run else 'not_run',output_ref=proof_ref))
        raw_findings=list(obs.get('findings',[]))
        if state=='FAIL' and not raw_findings:
            probes=obs.get('evidence',{}).get('probes',obs.get('evidence',{}).get('cases',[]))
            raw_findings=[dict(id=p.get('id','failed-probe'),location=id+'/'+str(p.get('id','failed-probe')),impact='A synthetic authorization or capability assertion failed') for p in probes if not p.get('passed',p.get('matched',True))]
        for f in raw_findings:
            severity=f.get('severity','high')
            if severity not in ('critical','high','medium','low','informational'):severity='informational'
            fid='finding-'+digest((id+str(f.get('id'))+str(f.get('location'))).encode())[:20]
            findings.append(dict(id=fid,location=str(f.get('location',id)),redacted_evidence_ref=eid,impact=str(f.get('impact','Synthetic check violation')),severity=severity,severity_rationale=str(f.get('severity_rationale','Starbots policy: authorization/capability bypass has high potential impact; this fixture contains no real customer data')),confidence='high' if did_run else 'low',disposition='confirmed' if did_run else 'indicator',external_refs=f.get('external_refs',[]),recommendation=str(f.get('recommendation','Correct the fixture defect and rerun the same checks')),regression_check=str(f.get('regression_check','Run the matching vulnerable/corrected pair for '+id)),lifecycle='open'))
    if prior_assessment is not None:
        prior_path=Path(prior_assessment);prior=load_json(prior_path.parent,prior_path.name)
        validate(prior,expected_kind='SecurityAssessment',client_id=client_id,project_id=project_id)
        retained=[f for f in prior['payload']['findings'] if f['severity']=='critical' and f['lifecycle'] in ('open','accepted')]
        if retained:
            pref=add('prior/assessment.json',json_bytes(prior),'prior-unresolved-critical')
            pe=envelope('Evidence','prior-critical',dict(evidence_type='Unresolved prior critical finding; explicit reconciliation pending',source='local',source_uri='local://review/prior',observed_at=as_of,valid_until=until,classification='synthetic',evidence_level='unknown',artifact_path=pref['path'],artifact_sha256=pref['sha256'],redaction_status='synthetic',collector='prior-finding-retention',tool_version='1',rules_digest=policy_hash,authorized_scope_id=project_id),client_id=client_id,project_id=project_id,created_at=as_of)
            evidence_refs.append(add('evidence/prior-critical.json',json_bytes(pe),'evidence'))
            existing={f['id'] for f in findings}
            for f in retained:
                if f['id'] not in existing:findings.append({**f,'redacted_evidence_ref':'prior-critical'});existing.add(f['id'])
    identity=dict(client_id=client_id,project_id=project_id,revision='review-1',artifacts=artifacts)
    subject_id='security-review-'+digest(json_bytes(identity))[:24]
    manifest=dict(subject_id=subject_id,**identity);write_bytes(root,'subject-manifest.json',json_bytes(manifest))
    subject=envelope('SubjectRef','subject-'+digest(json_bytes(manifest))[:24],dict(subject_id=subject_id,revision='review-1',manifest_path='subject-manifest.json',manifest_sha256=digest(json_bytes(manifest)),artifacts=artifacts),client_id=client_id,project_id=project_id,created_at=as_of)
    validate(subject);write_bytes(root,'subject.json',json_bytes(subject))
    coverage=dict(performed=performed,missing=missing,excluded=[])
    verdict=readiness(controls,findings,coverage,verified,runs,policy_id=POLICY)
    assessment=envelope('SecurityAssessment','assessment-'+digest(json_bytes(manifest))[:24],dict(subject_ref=subject['payload'],policy_id=POLICY,policy_version=profile['version'],policy_digest=policy_hash,assessed_at=as_of,expires_at=until,scope=profile['scope'],evidence_refs=evidence_refs,tool_runs=runs,controls=controls,findings=findings,coverage=coverage,readiness=verdict),client_id=client_id,project_id=project_id,created_at=as_of)
    validate(assessment);raw=json_bytes(assessment);write_bytes(root,'security-assessment.json',raw)
    verify_assessment(root,dict(path='security-assessment.json',sha256=digest(raw)),subject,as_of=as_of,expected_policy_id=POLICY)
    lines=['# Starbots local security review','','Scope: '+profile['scope'],'','Readiness: '+verdict['state'],'','Hashes establish integrity, not authorship or execution approval.','No finding does not mean secure. Real model/host evaluations were not performed.','','| Control | State | Evidence |','| --- | --- | --- |']
    lines.extend('| '+c['id']+' | '+c['state']+' | '+c['evidence_refs'][0]+' |' for c in controls)
    lines.extend(['','Findings: '+str(len(findings)),*['- '+r for r in verdict['reasons']]])
    write_bytes(root,'security-report.md',('\n'.join(lines)+'\n').encode())
    return assessment
