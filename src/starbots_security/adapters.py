"""Bounded scanner importers. Imported silence is UNKNOWN, never execution proof."""
import json
from .io import ValidationError, _pairs, fail, inspect_data

CONTROLS={'gitleaks':'SB-SECRETS','osv-scanner':'SB-DEPENDENCIES','trivy':'SB-IAC'}

def normalize(tool,raw,*,executed=False,exit_code=None,target_files=0):
    result=dict(check_id=CONTROLS.get(tool,'UNSUPPORTED'),tool=tool,state='UNKNOWN',findings=[],coverage=dict(target_files=target_files,performed=False,missing=[]),errors=[])
    try:
        if tool not in CONTROLS:fail('UNSUPPORTED_TOOL','Unsupported scanner')
        if len(raw)>10*1024*1024:fail('RESOURCE_LIMIT','Scanner output exceeds limit')
        data=json.loads(raw.decode('utf-8'),object_pairs_hook=_pairs,parse_float=str,parse_constant=lambda _:fail('INVALID_SCHEMA','Nonfinite scanner value'))
        inspect_data(data)
        count=0
        def finding(id,location,severity,impact):
            if not all(isinstance(v,str) for v in (id,location,severity,impact)):fail('INVALID_SCHEMA','Malformed scanner finding')
            severity=severity.lower()
            known=severity in ('critical','high','medium','low','informational')
            if not known:severity='informational'
            # Do not retain secret/match/snippet/description fields or imported instructions.
            result['findings'].append(dict(id=id[:128],location=location[:500],severity=severity,severity_rationale='Scanner classification within the declared rule/advisory scope',confidence='high' if executed else 'medium',impact=impact,recommendation='Correct the affected fixture and rerun the identical pinned check',regression_check='Known vulnerable and corrected fixture pair',external_refs=[]))
            if not known:result['findings'][-1]['severity_rationale']='Severity unavailable in scanner output; informational is an unknown-severity placeholder requiring review'
        if tool=='gitleaks':
            if not isinstance(data,list):fail('INVALID_SCHEMA','Expected Gitleaks JSON array')
            for f in data:
                if not isinstance(f,dict) or not isinstance(f.get('StartLine'),int):fail('INVALID_SCHEMA','Malformed Gitleaks finding')
                finding(f['RuleID'],f['File']+':'+str(f['StartLine']),'high','Potential credential exposure; secret values omitted')
                result['findings'][-1]['severity_rationale']='Starbots policy: potential credential exposure has high impact; Gitleaks supplies the rule match, not a severity rating'
            count=target_files
        elif tool=='osv-scanner':
            if not isinstance(data,dict) or not isinstance(data.get('results'),list):fail('INVALID_SCHEMA','Expected OSV result object')
            for source in data['results']:
                identity=source.get('source')
                if not isinstance(identity,dict) or not isinstance(identity.get('path'),str) or not identity['path']:fail('INVALID_SCHEMA','Missing OSV source identity')
                packages=source.get('packages')
                if not isinstance(packages,list):fail('INVALID_SCHEMA','Missing OSV package coverage')
                for p in packages:
                    package=p['package'];count+=1
                    if not isinstance(package.get('name'),str) or not isinstance(package.get('version'),str):fail('INVALID_SCHEMA','Missing resolved package identity')
                    if 'source=LOCAL' in package.get('purl',''):result['coverage']['missing'].append('Local dependency was omitted by the advisory matcher')
                    for v in p.get('vulnerabilities',[]):
                        severity=v.get('database_specific',{}).get('severity','').lower()
                        if severity=='moderate':severity='medium'
                        known=severity in ('critical','high','medium','low')
                        finding(v['id'],source['source']['path'],severity if known else 'informational','Known advisory affecting declared '+package['name']+' '+package['version']+'; consult the pinned advisory for exact affected range')
                        result['findings'][-1]['severity_rationale']='Pinned advisory database_specific severity' if known else 'Severity unavailable in the pinned advisory; informational is an unknown-severity placeholder requiring review'
        else:
            if not isinstance(data,dict) or data.get('SchemaVersion')!=2 or not isinstance(data.get('Results'),list):fail('INVALID_SCHEMA','Unsupported Trivy result format')
            for source in data['Results']:
                if source.get('Class')!='config':continue
                summary=source.get('MisconfSummary',{});count+=summary.get('Successes',0)+summary.get('Failures',0)
                # Pinned 0.76.0 MisconfSummary defines Successes and Failures,
                # not Exceptions (verified pkg/types/report.go). If supplied,
                # an exception count must still be bounded and reviewed.
                if not isinstance(source.get('Target'),str) or not source['Target'] or any(type(summary.get(k)) is not int or summary[k]<0 for k in ('Successes','Failures')) or ('Exceptions' in summary and (type(summary['Exceptions']) is not int or summary['Exceptions']<0)):fail('INVALID_SCHEMA','Missing Trivy source or coverage counts')
                misconfigs=source.get('Misconfigurations',[])
                if not isinstance(misconfigs,list) or summary['Failures']!=sum(1 for f in misconfigs if isinstance(f,dict) and f.get('Status','FAIL')=='FAIL'):fail('INVALID_SCHEMA','Trivy failure summary contradicts findings')
                if any(not isinstance(f,dict) or f.get('Status','FAIL')!='FAIL' for f in misconfigs) or source.get('ExperimentalModifiedFindings'):result['coverage']['missing'].append('Suppressed, modified or unsupported IaC findings require review')
                if summary.get('Exceptions',0):result['coverage']['missing'].append('Excepted IaC checks require review')
                for f in source.get('Misconfigurations',[]):
                    if f.get('Status','FAIL')!='FAIL':continue
                    finding(f.get('AVDID') or f['ID'],source['Target']+':'+str(f.get('CauseMetadata',{}).get('StartLine','unknown')),f.get('Severity',''),'IaC rule violation; no provider was queried or changed')
        valid_run=executed and exit_code in (0,1) and target_files>0 and count>0 and not result['coverage']['missing']
        if executed and exit_code not in (0,1):result['errors'].append('Scanner failed or did not complete')
        if not count:result['coverage']['missing'].append('No applicable package/file/rule coverage was reported')
        result['coverage']['performed']=bool(valid_run)
        if valid_run:result['state']='FAIL' if result['findings'] else ('PASS' if exit_code==0 else 'UNKNOWN')
        elif result['findings'] and not executed:result['state']='FAIL';result['errors'].append('Imported indications; execution provenance is unverified')
        else:result['errors'].append('Execution or coverage is incomplete')
    except (ValidationError,ValueError,TypeError,KeyError,AttributeError,UnicodeError,RecursionError,OverflowError):
        result.update(state='UNKNOWN',findings=[]);result['errors'].append('Malformed, unsupported or oversized scanner output')
    return result
