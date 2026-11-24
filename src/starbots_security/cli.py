"""Local contracts and explicitly scoped synthetic security experiments."""
import argparse
import json
from pathlib import Path
from . import __version__
from .contracts import validate, export_protocol, protocol_digest
from .io import ValidationError, digest, load_json, read_bytes, verify_subject

def main(argv=None):
    parser=argparse.ArgumentParser(prog='sb-security',description='Local versioned contracts; imported data is never execution authority.')
    parser.add_argument('--version',action='version',version=__version__)
    sub=parser.add_subparsers(dest='command')
    check=sub.add_parser('validate',help='Validate a JSON contract without network access')
    check.add_argument('--input',required=True);check.add_argument('--kind');check.add_argument('--as-of')
    check.add_argument('--client-id');check.add_argument('--project-id')
    subject=sub.add_parser('verify-subject',help='Verify every byte bound to a subject manifest')
    subject.add_argument('--input',required=True);subject.add_argument('--client-id',required=True);subject.add_argument('--project-id',required=True)
    export=sub.add_parser('export-protocol',help='Export the pinned data-only security protocol')
    export.add_argument('--output-dir',required=True);export.add_argument('--source-commit',required=True)
    assess=sub.add_parser('assess-fixture',help='Execute owned synthetic fixtures; never scan a remote target')
    assess.add_argument('--variant',choices=['vulnerable','corrected'],required=True)
    assess.add_argument('--skill',choices=['all','app-api','supply-chain','agent-tools'],default='all')
    assess.add_argument('--output-dir',required=True);assess.add_argument('--client-id',required=True);assess.add_argument('--project-id',required=True);assess.add_argument('--as-of',required=True)
    assess.add_argument('--toolchain-root');assess.add_argument('--pg-runtime');assess.add_argument('--proposal');assess.add_argument('--prior-assessment')
    verify=sub.add_parser('verify-assessment',help='Verify against a separately trusted assessment SHA-256')
    verify.add_argument('--review-dir',required=True);verify.add_argument('--assessment-sha256',required=True);verify.add_argument('--client-id',required=True);verify.add_argument('--project-id',required=True);verify.add_argument('--as-of',required=True)
    imported=sub.add_parser('import-result',help='Inspect untrusted scanner output; cannot mint measured PASS')
    imported.add_argument('--tool',choices=['gitleaks','osv-scanner','trivy'],required=True);imported.add_argument('--input',required=True)
    for command in ('install-skills','uninstall-skills'):
        host_install=sub.add_parser(command,help='Manage only Starbots skills in an explicitly selected local project')
        host_install.add_argument('--host',choices=['codex','kiro','claude'],required=True)
        host_install.add_argument('--project-root',required=True)
    args=parser.parse_args(argv)
    try:
        if args.command in ('validate','verify-subject'):
            p=Path(args.input);doc=load_json(p.parent,p.name)
            validate(doc,expected_kind=getattr(args,'kind',None),client_id=args.client_id,project_id=args.project_id,as_of=getattr(args,'as_of',None))
            if args.command=='verify-subject':verify_subject(p.parent,doc,client_id=args.client_id,project_id=args.project_id)
            print(json.dumps({'valid':True,'kind':doc['kind'],'id':doc['id'],'protocol_sha256':protocol_digest()}))
        elif args.command=='export-protocol':
            export_protocol(args.output_dir,source_commit=args.source_commit)
            print(json.dumps({'exported':True,'protocol_sha256':protocol_digest()}))
        elif args.command=='assess-fixture':
            from .review import execute_fixture
            result=execute_fixture(args.output_dir,variant=args.variant,skill=args.skill,client_id=args.client_id,project_id=args.project_id,as_of=args.as_of,toolchain_root=args.toolchain_root,pg_runtime=args.pg_runtime,proposal=args.proposal,prior_assessment=args.prior_assessment)
            print(json.dumps(dict(generated=True,assessment_sha256=digest(read_bytes(args.output_dir,'security-assessment.json')),readiness=result['payload']['readiness']['state'],execution_eligible=False)))
            selected={'app-api':{'api-fixture','postgresql-rls'},'supply-chain':{'gitleaks','osv-scanner','trivy'},'agent-tools':{'agent-boundary'}}
            requested=selected.get(args.skill,set().union(*selected.values()))
            if any(r['tool'] in requested and r['status']!='executed' for r in result['payload']['tool_runs']):return 4
            return 3 if result['payload']['readiness']['state']=='BLOCKED' else 0
        elif args.command=='verify-assessment':
            from .review import verify_review
            result=verify_review(args.review_dir,args.assessment_sha256,client_id=args.client_id,project_id=args.project_id,as_of=args.as_of)
            print(json.dumps(dict(valid=True,readiness=result['payload']['readiness']['state'],execution_eligible=False)))
            return 3 if result['payload']['readiness']['state']=='BLOCKED' else 0
        elif args.command=='import-result':
            from .adapters import normalize
            p=Path(args.input);print(json.dumps(normalize(args.tool,read_bytes(p.parent,p.name))))
        elif args.command in ('install-skills','uninstall-skills'):
            from .skill_install import install_skills, uninstall_skills
            action=install_skills if args.command=='install-skills' else uninstall_skills
            print(json.dumps(action(args.project_root,args.host)))
        else:parser.print_help()
        return 0
    except (ValidationError,OSError) as exc:
        print(json.dumps({'valid':False,'error':getattr(exc,'code','LOCAL_IO_ERROR'),'message':str(exc) if isinstance(exc,ValidationError) else 'Local operation failed'}))
        return 2

if __name__=='__main__':raise SystemExit(main())
