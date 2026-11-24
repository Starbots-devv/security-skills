import importlib
import importlib.util
import json
import unittest

class ScannerImports(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('starbots_security.adapters'),'Scanner adapters are not implemented')
        self.a=importlib.import_module('starbots_security.adapters')
    def parse(self,tool,data,**kw):return self.a.normalize(tool,json.dumps(data).encode(),**kw)
    def test_imported_clean_json_is_unknown_and_malformed_never_passes(self):
        for raw in (b'[]',b'{}',b'bad',b'{"x":1,"x":2}'):
            self.assertNotEqual(self.a.normalize('gitleaks',raw)['state'],'PASS')
    def test_gitleaks_finding_is_redacted_and_failure_cannot_be_pass(self):
        r=self.parse('gitleaks',[dict(RuleID='fictional-rule',File='sample.env',StartLine=2,Secret='INERT_SECRET_DO_NOT_COPY',Match='token=INERT_SECRET_DO_NOT_COPY')],executed=True,exit_code=1,target_files=1)
        self.assertEqual(r['state'],'FAIL');self.assertNotIn('INERT_SECRET_DO_NOT_COPY',json.dumps(r))
        self.assertEqual(self.a.normalize('gitleaks',b'[]',executed=True,exit_code=2,target_files=1)['state'],'UNKNOWN')
    def test_clean_empty_scope_never_passes(self):
        self.assertEqual(self.a.normalize('gitleaks',b'[]',executed=True,exit_code=0,target_files=0)['state'],'UNKNOWN')
        self.assertEqual(self.parse('osv-scanner',{'results':[]},executed=True,exit_code=0,target_files=1)['state'],'UNKNOWN')
    def test_policy_severity_and_missing_scanner_severity_are_distinguished(self):
        g=self.parse('gitleaks',[dict(RuleID='synthetic',File='sample.env',StartLine=1)],executed=True,exit_code=1,target_files=1)
        self.assertIn('Starbots policy',g['findings'][0]['severity_rationale'])
        t=self.parse('trivy',{'SchemaVersion':2,'Results':[{'Class':'config','Target':'main.tf','MisconfSummary':{'Successes':0,'Failures':1,'Exceptions':0},'Misconfigurations':[{'ID':'test','Status':'FAIL'}]}]},executed=True,exit_code=1,target_files=1)
        self.assertEqual(t['findings'][0]['severity'],'informational')
        self.assertIn('unavailable',t['findings'][0]['severity_rationale'])
    def test_osv_advisory_and_trivy_misconfiguration_are_findings(self):
        osv={'results':[{'source':{'path':'package-lock.json'},'packages':[{'package':{'name':'lodash','version':'4.17.20','ecosystem':'npm'},'vulnerabilities':[{'id':'GHSA-35jh-r3h4-6jhm'}]}]}]}
        self.assertEqual(self.parse('osv-scanner',osv,executed=True,exit_code=1,target_files=1)['state'],'FAIL')
        trivy={'SchemaVersion':2,'Results':[{'Target':'main.tf','Class':'config','Type':'terraform','MisconfSummary':{'Successes':0,'Failures':1,'Exceptions':0},'Misconfigurations':[{'ID':'AVD-AWS-0089','Severity':'HIGH','Status':'FAIL','CauseMetadata':{'StartLine':1}}]}]}
        self.assertEqual(self.parse('trivy',trivy,executed=True,exit_code=1,target_files=1)['state'],'FAIL')
    def test_executed_clean_scope_is_narrow_pass(self):
        self.assertEqual(self.a.normalize('gitleaks',b'[]',executed=True,exit_code=0,target_files=1)['state'],'PASS')
    def test_failed_or_unperformed_scan_cannot_be_clean(self):
        for code in (None,2,124,137):self.assertEqual(self.a.normalize('gitleaks',b'[]',executed=True,exit_code=code,target_files=1)['state'],'UNKNOWN')
    def test_osv_uses_advisory_severity_and_marks_missing_severity(self):
        data={'results':[{'source':{'path':'requirements.txt'},'packages':[{'package':{'name':'requests','version':'2.30.0'},'vulnerabilities':[{'id':'GHSA-test','database_specific':{'severity':'MODERATE'}},{'id':'PYSEC-test'}]}]}]}
        r=self.parse('osv-scanner',data,executed=True,exit_code=1,target_files=1)
        self.assertEqual([f['severity'] for f in r['findings']],['medium','informational'])
        self.assertIn('unavailable',r['findings'][1]['severity_rationale'])
    def test_osv_skipped_local_package_cannot_pass(self):
        data={'results':[{'source':{'path':'package-lock.json'},'packages':[{'package':{'name':'lodash','version':'4.17.20','purl':'pkg:npm/lodash@4.17.20?source=LOCAL'}}]}]}
        r=self.parse('osv-scanner',data,executed=True,exit_code=0,target_files=1)
        self.assertEqual(r['state'],'UNKNOWN')
        self.assertTrue(r['coverage']['missing'])
    def test_malformed_nested_objects_are_unknown(self):
        for tool,data in [('osv-scanner',{'results':[None]}),('trivy',{'SchemaVersion':2,'Results':[None]})]:
            try:r=self.parse(tool,data,executed=True,exit_code=0,target_files=1)
            except Exception as exc:self.fail('Malformed scanner structure escaped as '+type(exc).__name__)
            self.assertEqual(r['state'],'UNKNOWN')
    def test_incomplete_or_inconsistent_coverage_cannot_pass(self):
        examples=[('trivy',{'SchemaVersion':2,'Results':[{'Class':'config','Target':'main.tf','MisconfSummary':{'Successes':0,'Failures':1,'Exceptions':0}}]}),('osv-scanner',{'results':[{'packages':[{'package':{'name':'requests','version':'2.33.0'}}]}]})]
        for tool,data in examples:
            with self.subTest(tool=tool):
                r=self.parse(tool,data,executed=True,exit_code=0,target_files=1)
                self.assertEqual(r['state'],'UNKNOWN');self.assertFalse(r['coverage']['performed'])
    def test_actual_trivy_076_summary_has_no_exceptions_field(self):
        data={'SchemaVersion':2,'Results':[{'Class':'config','Target':'.','MisconfSummary':{'Successes':70,'Failures':0}},{'Class':'config','Target':'main.tf','MisconfSummary':{'Successes':0,'Failures':1},'Misconfigurations':[{'ID':'AWS-0107','Status':'FAIL','Severity':'HIGH'}]}]}
        r=self.parse('trivy',data,executed=True,exit_code=1,target_files=1)
        self.assertEqual(r['state'],'FAIL');self.assertTrue(r['coverage']['performed']);self.assertEqual(len(r['findings']),1)
    def test_suppressed_or_modified_trivy_findings_cannot_pass(self):
        for status in ['IGNORED','SUPPRESSED','EXCEPTION','UNKNOWN']:
            data={'SchemaVersion':2,'Results':[{'Class':'config','Target':'main.tf','MisconfSummary':{'Successes':70,'Failures':0},'Misconfigurations':[{'ID':'synthetic','Status':status}]}]}
            r=self.parse('trivy',data,executed=True,exit_code=0,target_files=1)
            self.assertEqual(r['state'],'UNKNOWN');self.assertFalse(r['coverage']['performed'])
        data['Results'][0]['Misconfigurations']=[];data['Results'][0]['ExperimentalModifiedFindings']=[{'FindingType':'misconfiguration'}]
        self.assertEqual(self.parse('trivy',data,executed=True,exit_code=0,target_files=1)['state'],'UNKNOWN')
if __name__=='__main__':unittest.main()
