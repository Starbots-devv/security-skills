"""Closed versioned JSON contracts and pinned data-only security protocol."""
from datetime import datetime, timezone
from decimal import Decimal
from functools import lru_cache
from importlib.resources import files
import json
from pathlib import Path
import re
import shutil

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource
from . import __version__
from .io import ValidationError, digest, fail, inspect_data, json_bytes, parse_json, read_bytes

DATA=files(__package__).joinpath('data')
VERSION='1.0.0'

def timestamp(value):
    try:
        if not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z',value):raise ValueError()
        return datetime.strptime(value,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except (ValueError,TypeError):fail('INVALID_SCHEMA','Invalid UTC timestamp')

def protocol_digest():
    return parse_json(DATA.joinpath('protocol-pin.json').read_bytes())['manifest_sha256']

def _protocol():
    return DATA.joinpath('protocol',VERSION)

def verify_protocol_path(directory,expected_digest):
    path=Path(directory);raw=read_bytes(path,'manifest.json')
    if digest(raw)!=expected_digest:fail('HASH_MISMATCH','Protocol manifest differs from pinned digest')
    manifest=parse_json(raw)
    if manifest.get('protocol_version')!=VERSION or manifest.get('owner')!='starbots-security-skills':fail('UNSUPPORTED_VERSION','Unsupported security protocol')
    for name,expected in manifest['files'].items():
        if digest(read_bytes(path,name))!=expected:fail('HASH_MISMATCH','Security protocol artifact changed')
    return manifest

def verify_protocol():
    # Wheel resources are normal filesystem data in supported installs.
    return verify_protocol_path(str(_protocol()),protocol_digest())

def export_protocol(output_dir,*,source_commit):
    if not re.fullmatch('[a-f0-9]{40}',source_commit):fail('INVALID_SCHEMA','An explicit source commit is required')
    manifest=verify_protocol();out=Path(output_dir);out.mkdir(parents=True,exist_ok=True)
    names=[*manifest['files'],'manifest.json']
    if any((out/name).exists() for name in names):fail('PATH_DENIED','Protocol export refuses existing files')
    for name in names:(out/name).write_bytes(_protocol().joinpath(name).read_bytes())
    (out/'origin.json').write_bytes(json_bytes({'owner':manifest['owner'],'version':VERSION,'source_commit':source_commit,'manifest_sha256':protocol_digest(),'license':'Apache-2.0'}))
    return out

def _deny_network(uri):
    raise NoSuchResource(ref=uri)

@lru_cache(maxsize=1)
def _schemas():
    verify_protocol();schemas={}
    for folder in (DATA.joinpath('contracts',VERSION),_protocol()):
        if folder.is_dir():
            for p in folder.iterdir():
                if p.name.endswith('.schema.json'):
                    schema=parse_json(p.read_bytes());Draft202012Validator.check_schema(schema);schemas[schema['title']]=schema
    registry=Registry(retrieve=_deny_network).with_resources((s['$id'],Resource.from_contents(s)) for s in schemas.values())
    return schemas,registry

def schema(kind):
    schemas,_=_schemas()
    if kind not in schemas:fail('UNSUPPORTED_VERSION','Unsupported contract kind')
    return schemas[kind]

DECIMAL_KEYS={'quantity','unit_rate','monthly_budget','hours_per_month','maintenance_hours_month','arrival_rate_per_second','service_time_seconds','concurrency','memory_gib','db_connections','queue_depth','inference_cost_monthly','parallel_slots','required_memory_per_job_gib','available_memory_gib','max_db_connections','required_connections','network_capacity_mbps','target_network_mbps','traffic_gb_month','incremental_cost','max_incremental_cost'}
TIME_KEYS={'created_at','observed_at','valid_until','assessed_at','expires_at','issued_at','started_at','ended_at','as_of','cost_valid_until'}

def _semantic_walk(value,key=''):
    if isinstance(value,str):
        if key in TIME_KEYS:timestamp(value)
        if key in DECIMAL_KEYS:
            try:
                number=Decimal(value)
                if number<0 or not number.is_finite() or (number.is_zero() and value.startswith('-')) or len(number.as_tuple().digits)>28 or (number and number.adjusted() not in range(-256,257)):raise ValueError()
            except (ValueError,ArithmeticError):fail('INVALID_SCHEMA','Invalid bounded input decimal')
    elif isinstance(value,dict):
        for k,v in value.items():_semantic_walk(v,k)
    elif isinstance(value,list):
        ids=[x['id'] for x in value if isinstance(x,dict) and 'id' in x]
        if len(ids)!=len(set(ids)):fail('INVALID_SCHEMA','Duplicate logical IDs')
        for v in value:_semantic_walk(v,key)

def validate(document,*,expected_kind=None,client_id=None,project_id=None,as_of=None):
    inspect_data(document)
    if not isinstance(document,dict):fail('INVALID_SCHEMA','Expected a contract object')
    if document.get('schema_version')!=VERSION:fail('UNSUPPORTED_VERSION','Unsupported full schema version')
    kind=document.get('kind')
    if expected_kind is not None and kind!=expected_kind:fail('INVALID_SCHEMA','Unexpected contract kind')
    schemas,registry=_schemas()
    if kind not in schemas:fail('UNSUPPORTED_VERSION','Unsupported contract kind')
    try:
        errors=list(Draft202012Validator(schemas[kind],registry=registry).iter_errors(document))
    except Exception as exc:
        if isinstance(exc,ValidationError):raise
        fail('INVALID_SCHEMA','Schema reference could not be resolved locally')
    if errors:
        location='/'.join(str(x) for x in errors[0].absolute_path)
        fail('INVALID_SCHEMA','Contract validation failed at '+(location or 'root'))
    _semantic_walk(document)
    if client_id is not None and document['client_id']!=client_id:fail('IDENTITY_MISMATCH','Client does not match authorized scope')
    if project_id is not None and document['project_id']!=project_id:fail('IDENTITY_MISMATCH','Project does not match authorized scope')
    if as_of is not None:
        now=timestamp(as_of)
        if timestamp(document['created_at'])>now:fail('EVIDENCE_STALE','Document is from the future')
        p=document['payload']
        start=p.get('observed_at',p.get('assessed_at'))
        end=p.get('valid_until',p.get('expires_at'))
        if start and timestamp(start)>now:fail('EVIDENCE_STALE','Evidence is from the future')
        if kind in ('Evidence','SecurityAssessment'):
            if end is None or now>=timestamp(end):fail('EVIDENCE_STALE','Evidence validity is unknown or expired')
            if start and (now-timestamp(start)).total_seconds()>7*86400:fail('EVIDENCE_STALE','Evidence exceeds analysis age policy')
    return document

def control_profile(policy_id='protocol-demo-review'):
    if policy_id=='protocol-demo-review':return parse_json(_protocol().joinpath('control-profile.json').read_bytes()),_protocol().joinpath('control-profile.json').read_bytes()
    if policy_id!='starbots-local-review':fail('UNSUPPORTED_VERSION','Unsupported software-owned control profile')
    raw=DATA.joinpath('local-review-policy.json').read_bytes();pin=parse_json(DATA.joinpath('local-review-policy-pin.json').read_bytes())
    if digest(raw)!=pin['sha256'] or pin['owner']!='starbots-security-skills':fail('HASH_MISMATCH','Local review profile differs from trusted pin')
    return parse_json(raw),raw

def observation_state(control_id,observation):
    if not isinstance(observation,dict) or observation.get('errors'):return 'UNKNOWN',False
    coverage=observation.get('coverage',{});evidence=observation.get('evidence',{})
    state=observation.get('state','UNKNOWN');performed=False
    if control_id=='SB-AGENT-BOUNDARY':
        cases=evidence.get('cases',[])
        performed=evidence.get('evaluation_type')=='deterministic-policy-harness; no model invoked' and len(cases)>=12 and any(c.get('allowed') for c in cases) and evidence.get('mutating_calls')==0
        if performed:state='PASS' if all(c.get('matched') is True for c in cases) else 'FAIL'
    elif isinstance(coverage,dict):
        performed=coverage.get('performed') is True or coverage.get('executed') is True
        if control_id in ('SB-AUTH','SB-RLS'):
            probes=evidence.get('probes',[]);performed=performed and bool(probes) and bool(evidence.get('fixture_sha256'))
            if performed:state='PASS' if all(p.get('passed') is True for p in probes) else 'FAIL'
        elif observation.get('findings') and performed:state='FAIL'
    if state not in ('PASS','FAIL') or not performed:return 'UNKNOWN',False
    return state,True

def readiness(controls,findings,coverage,verified_evidence_ids,tool_runs=(),*,policy_id='protocol-demo-review'):
    verify_protocol();table=parse_json(_protocol().joinpath('readiness-table.json').read_bytes());reasons=[]
    profile,_=control_profile(policy_id)
    declared={c['id']:c for c in controls}
    for required in profile['required_controls']:
        if required['id'] not in declared or declared[required['id']]['mandatory'] is not True:reasons.append(required['id']+': required policy control is missing or downgraded')
    if table['require_mandatory'] and not any(c['mandatory'] for c in controls):reasons.append('No mandatory control coverage')
    runs={r['tool']:r for r in tool_runs}
    for tool in profile['required_tools']:
        if tool not in runs:reasons.append(tool+': required tool run is absent')
    for run in tool_runs:
        if run['status'] in table['blocking_tool_statuses']:reasons.append(run['tool']+': tool did not complete successfully')
    if table['missing_coverage_blocks'] and coverage['missing']:reasons.append('Required coverage is missing')
    for c in controls:
        if not c['mandatory']:continue
        rule=table['mandatory'].get(c['state'])
        if rule is None or not rule['allow']:reasons.append(c['id']+': control does not pass');continue
        if rule['requires_evidence'] and (not c['evidence_refs'] or not set(c['evidence_refs']).issubset(verified_evidence_ids)):reasons.append(c['id']+': missing verified evidence')
        if not c['rationale'].strip():reasons.append(c['id']+': missing justification')
        if c['state']=='PASS' and table['require_performed_for_pass'] and c['id'] not in coverage['performed']:reasons.append(c['id']+': check was not performed')
    for finding in findings:
        if finding['severity'] in table['blocking_severities'] and finding['disposition'] in table['blocking_dispositions'] and finding['lifecycle'] in table['blocking_lifecycles']:reasons.append(finding['id']+': unresolved critical finding')
    return {'state':'BLOCKED' if reasons else 'READY','reasons':reasons}

def producer():
    build=DATA.joinpath('build.json')
    commit=parse_json(build.read_bytes())['source_commit'] if build.is_file() else 'UNRELEASED'
    return {'name':__package__,'version':__version__,'source_commit':commit}

def envelope(kind,identifier,payload,*,client_id,project_id,created_at):
    return {'schema_version':VERSION,'kind':kind,'id':identifier,'client_id':client_id,'project_id':project_id,'created_at':created_at,'producer':producer(),'payload':payload}

def verify_assessment(root,ref,subject,*,as_of,allow_synthetic=False,expected_policy_id='protocol-demo-review'):
    from .io import load_json, verify_ref, verify_subject
    if subject is None:fail('INCOMPLETE_COVERAGE','An exact subject is required')
    validate(subject,expected_kind='SubjectRef')
    verify_subject(root,subject,client_id=subject['client_id'],project_id=subject['project_id'])
    doc=parse_json(verify_ref(root,ref))
    validate(doc,expected_kind='SecurityAssessment',client_id=subject['client_id'],project_id=subject['project_id'],as_of=as_of)
    p=doc['payload']
    if p['subject_ref']!=subject['payload']:fail('HASH_MISMATCH','Assessment does not bind this exact proposal')
    profile,profile_raw=control_profile(expected_policy_id);profile_digest=digest(profile_raw)
    if p['policy_version']!=profile['version'] or p['policy_id']!=profile['id'] or p['policy_digest']!=profile_digest:fail('HASH_MISMATCH','Assessment policy does not match the canonical control profile')
    policy_refs=[a for a in subject['payload']['artifacts'] if a['role']=='security-control-profile']
    if len(policy_refs)!=1 or policy_refs[0]['sha256']!=profile_digest:fail('HASH_MISMATCH','Subject does not bind the trusted required-control profile')
    if verify_ref(root,policy_refs[0])!=profile_raw:fail('HASH_MISMATCH','Required-control profile differs from trusted bytes')
    bound={a['path']:a['sha256'] for a in subject['payload']['artifacts']};verified=set()
    for item in p['evidence_refs']:
        if bound.get(item['path'])!=item['sha256']:fail('HASH_MISMATCH','Evidence was not part of the reviewed proposal')
        e=parse_json(verify_ref(root,item))
        validate(e,expected_kind='Evidence',client_id=doc['client_id'],project_id=doc['project_id'],as_of=as_of)
        ep=e['payload']
        if bound.get(ep['artifact_path'])!=ep['artifact_sha256']:fail('HASH_MISMATCH','Underlying proof is not bound to the subject')
        verify_ref(root,{'path':ep['artifact_path'],'sha256':ep['artifact_sha256']})
        if ep['evidence_level'] in ('unknown','assumption','inventory'):
            if expected_policy_id=='starbots-local-review':continue
            fail('INCOMPLETE_COVERAGE','Evidence does not demonstrate the control')
        if ep['evidence_level']=='synthetic' and not allow_synthetic:fail('INCOMPLETE_COVERAGE','Synthetic evidence cannot demonstrate real security')
        if ep['redaction_status']=='incomplete':fail('INCOMPLETE_COVERAGE','Evidence redaction is incomplete')
        if bound.get(ep['artifact_path'])!=ep['artifact_sha256']:fail('HASH_MISMATCH','Underlying proof is not bound to the subject')
        verify_ref(root,{'path':ep['artifact_path'],'sha256':ep['artifact_sha256']})
        if e['id'] in verified:fail('INVALID_SCHEMA','Duplicate evidence IDs')
        verified.add(e['id'])
    if expected_policy_id=='starbots-local-review':
        if any(r['tool']=='osv-scanner' and r['status']=='executed' for r in p['tool_runs']) and timestamp(p['expires_at'])>timestamp(profile['advisory_snapshot_expires_at']):fail('EVIDENCE_STALE','Assessment exceeds trusted advisory snapshot validity')
        evidence_by_id={}
        for item in p['evidence_refs']:
            e=parse_json(verify_ref(root,item));evidence_by_id[e['id']]=e
        for control in p['controls']:
            for evidence_id in control['evidence_refs']:
                if evidence_id not in evidence_by_id:fail('INCOMPLETE_COVERAGE','Control references missing evidence')
                e=evidence_by_id[evidence_id];ep=e['payload']
                proof=parse_json(verify_ref(root,{'path':ep['artifact_path'],'sha256':ep['artifact_sha256']}))
                if proof.get('control_id')!=control['id']:fail('IDENTITY_MISMATCH','Evidence applies to another control')
                state,performed=observation_state(control['id'],proof.get('observation'))
                if control['state']!=state:fail('INCOMPLETE_COVERAGE','Control contradicts executed observation')
                if control['state']=='PASS' and (not performed or evidence_id not in verified):fail('INCOMPLETE_COVERAGE','PASS lacks measured execution')
        for run in p['tool_runs']:
            if run['output_ref'] is not None:
                if bound.get(run['output_ref']['path'])!=run['output_ref']['sha256']:fail('HASH_MISMATCH','Tool output is not bound to the exact review')
                verify_ref(root,run['output_ref'])
        if any(f['redacted_evidence_ref'] not in evidence_by_id for f in p['findings']):fail('INCOMPLETE_COVERAGE','Finding has no bound evidence')
    expected=readiness(p['controls'],p['findings'],p['coverage'],verified,p['tool_runs'],policy_id=expected_policy_id)
    if expected!=p['readiness']:fail('INCOMPLETE_COVERAGE','Declared readiness disagrees with verified evidence and canonical policy')
    return doc
