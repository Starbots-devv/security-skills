import importlib
import importlib.util
import json
import hashlib
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


class ApplicationTests(unittest.TestCase):
    def test_descendant_held_pipe_cannot_extend_total_deadline_or_succeed(self):
        import sys,time
        app=self.application()
        script="import subprocess,sys;subprocess.Popen([sys.executable,'-c','import time;time.sleep(2)'])"
        started=time.monotonic()
        with self.assertRaisesRegex(RuntimeError,'timeout|drain'):
            app._rls_process([sys.executable,'-c',script],timeout=.2)
        self.assertLess(time.monotonic()-started,1.5)
    def application(self):
        self.assertIsNotNone(importlib.util.find_spec('starbots_security.application'),
                             'Application probe implementation is missing')
        return importlib.import_module('starbots_security.application')

    def test_corrected_real_http_probes_pass_and_write_bound_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.application().run_api_fixture('corrected', directory)
            self.assertEqual(result['state'], 'PASS', result)
            self.assertEqual(result['check_id'], 'api-authorization')
            self.assertFalse(result['errors'])
            probes = result['evidence']['probes']
            self.assertGreaterEqual(len(probes), 20)
            self.assertTrue(all(p['passed'] for p in probes), probes)
            self.assertTrue(all(p['transport'] == 'loopback-http' for p in probes))
            self.assertEqual(len(result['evidence']['fixture_sha256']), 64)
            self.assertEqual(json.loads((Path(directory) / 'api-observation.json').read_text()), result)
            by_id = {p['id']: p for p in probes}
            for identifier in ['a-denied-write-unchanged', 'b-denied-write-unchanged',
                               'a2-denied-write-unchanged']:
                self.assertIn(identifier, by_id, 'Denied writes need a subsequent legitimate read proving no mutation')

    def test_vulnerable_fixture_is_detected_in_each_control_family(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.application().run_api_fixture('vulnerable', directory)
            self.assertEqual(result['state'], 'FAIL')
            failed = {p['control'] for p in result['evidence']['probes'] if not p['passed']}
            self.assertTrue({'object-read', 'object-write', 'function-role', 'mass-assignment',
                             'bulk-export', 'forged-tenant', 'session'} <= failed, failed)

    def test_unknown_variant_is_rejected_before_starting_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                self.application().run_api_fixture('../../external', directory)

    def test_rls_missing_runtime_is_explicit_unknown_with_error(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.application().run_rls_fixture('corrected', directory, runtime=None)
            self.assertEqual(result['state'], 'UNKNOWN')
            self.assertTrue(result['errors'])
            self.assertFalse(result['coverage']['executed'])

    def test_rls_binds_sql_even_when_runtime_is_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.application().run_rls_fixture('corrected', directory, runtime=None)
            self.assertEqual(len(result['evidence'].get('fixture_sha256', '')), 64)
            self.assertIn('WITH CHECK', result['evidence'].get('fixture_sql', ''))
            self.assertFalse(result['evidence']['probes'])

    def test_rls_rejects_relative_or_unpinned_executable_before_any_process(self):
        app = self.application()
        for executable, digest in [('relative.exe', 'a'*64), (str(Path(sys.executable).resolve()), None),
                                   (str(Path(sys.executable).resolve()), 'a'*64)]:
            runtime = {'docker_executable': executable, 'docker_executable_sha256': digest,
                       'container_id': 'a'*64, 'image_digest': 'sha256:'+'b'*64}
            with self.subTest(executable=executable, digest=digest), tempfile.TemporaryDirectory() as directory:
                with patch.object(app.subprocess, 'Popen') as process:
                    result = app.run_rls_fixture('corrected', directory, runtime=runtime)
                process.assert_not_called()
                self.assertEqual(result['state'], 'UNKNOWN')
                self.assertTrue(result['errors'])

    def test_rls_boundary_uses_clean_environment_local_endpoint_and_bounded_output(self):
        app = self.application()
        self.assertTrue(hasattr(app, '_docker_command'), 'Validated Docker execution boundary required')
        self.assertTrue(hasattr(app, '_rls_process'), 'Bounded stdin/stdout PostgreSQL executor required')
        for error in [RuntimeError('Process timeout'), RuntimeError('Process output limit exceeded')]:
            with tempfile.TemporaryDirectory() as directory, patch.object(app, '_docker_command', return_value=['reviewed-docker']):
                with patch.object(app, '_rls_process', side_effect=error):
                    result = app.run_rls_fixture('corrected', directory, runtime={'container_id':'a'*64})
                self.assertEqual(result['state'], 'UNKNOWN')
                self.assertTrue(result['errors'])

    def test_actual_bounded_executor_times_out_and_limits_combined_pipes(self):
        app=self.application()
        self.assertTrue(hasattr(app,'_rls_process'),'Bounded execution is required')
        with self.assertRaisesRegex(RuntimeError,'timeout'):
            app._rls_process([sys.executable,'-c','import time;time.sleep(5)'],timeout=0.1)
        with self.assertRaisesRegex(RuntimeError,'output limit'):
            app._rls_process([sys.executable,'-c',"import sys;sys.stdout.write('a'*8192);sys.stderr.write('b'*8192)"],max_output=1024)
        output=app._rls_process([sys.executable,'-c','import sys;print(sys.stdin.read())'],sql='bounded SQL')
        self.assertEqual(output.strip(),'bounded SQL')

    def test_operator_pin_and_endpoint_ignore_hostile_docker_environment(self):
        app=self.application()
        self.assertTrue(hasattr(app,'_docker_command'),'Operator pin boundary required')
        executable=Path(sys.executable).resolve()
        digest=hashlib.sha256(executable.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            runtime={'docker_executable':str(executable),'docker_executable_sha256':digest,
                     'docker_config':'hostile-config'}
            with patch.object(app,'DOCKER_EXECUTABLE',executable),patch.object(app,'DOCKER_EXECUTABLE_SHA256',digest):
                with patch.dict(os.environ,{'DOCKER_HOST':'tcp://external.invalid:2375','DOCKER_CONTEXT':'external'}):
                    command=app._docker_command(runtime,directory)
                    output=app._rls_process([sys.executable,'-c',"import os,json;print(json.dumps(dict(os.environ)))"])
            self.assertNotIn('external',str(command))
            self.assertEqual(command[1:3],['--config',directory])
            self.assertEqual(command[3],'--host')
            self.assertEqual(command[4], 'npipe:////./pipe/docker_engine' if os.name=='nt' else 'unix:///var/run/docker.sock')
            self.assertEqual(json.loads((Path(directory)/'config.json').read_text()),{})
            self.assertNotIn('DOCKER_HOST',json.loads(output))
            self.assertNotIn('DOCKER_CONTEXT',json.loads(output))

    def test_operator_path_with_changed_binary_bytes_is_rejected_before_process(self):
        app=self.application()
        with tempfile.TemporaryDirectory() as directory:
            executable=Path(directory)/'reviewed-docker.exe'
            approved=hashlib.sha256(b'reviewed-original').hexdigest()
            executable.write_bytes(b'tampered-after-review')
            runtime={'docker_executable':str(executable),'docker_executable_sha256':approved}
            with patch.object(app,'DOCKER_EXECUTABLE',executable),patch.object(app,'DOCKER_EXECUTABLE_SHA256',approved):
                with patch.object(app.subprocess,'Popen') as process:
                    with self.assertRaisesRegex(ValueError,'bytes do not match'):
                        app._docker_command(runtime,directory)
                process.assert_not_called()

    def test_ambiguous_create_reconciles_only_attempted_resources_and_never_passes(self):
        app = self.application()
        self.assertTrue(hasattr(app, '_rls_process'), 'Reconciliation requires bounded execution')
        inspected = {'Id':'a'*64,'Image':'sha256:'+'b'*64,'Mounts':[],
                     'Config':{'User':'70:70','Labels':{'starbots.review.synthetic':'true'}},
                     'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'CapDrop':['ALL'],
                                   'SecurityOpt':['no-new-privileges'],'PidsLimit':64,'Memory':536870912,
                                   'NanoCpus':1000000000,'Privileged':False}}
        calls = []
        present=[]
        def execute(argv, sql=None):
            calls.append((argv,sql))
            if 'inspect' in argv: return json.dumps([inspected])
            if sql and 'CREATE ROLE' in sql:
                present.extend(re.findall(r'CREATE ROLE (sb_\w+)',sql))
                raise RuntimeError('Process timeout after commit')
            if sql and 'pg_database' in sql:
                return json.dumps({'database_present':False,'database_owned':False,
                                   'roles':[{'name':r,'owned':True} for r in present]})
            if sql and 'DROP ROLE' in sql:
                present.remove(sql.split('IF EXISTS ')[1].removesuffix(';'))
            return ''
        runtime={'container_id':'a'*64,'image_digest':'sha256:'+'b'*64}
        with tempfile.TemporaryDirectory() as directory, patch.object(app, '_docker_command', return_value=['reviewed-docker']):
            with patch.object(app, '_rls_process', side_effect=execute):
                result=app.run_rls_fixture('corrected',directory,runtime=runtime)
        self.assertEqual(result['state'],'UNKNOWN')
        self.assertTrue(any(sql and 'DROP ROLE' in sql for _,sql in calls), calls)
        self.assertTrue(any(sql and 'pg_roles' in sql for _,sql in calls), calls)
        self.assertTrue(result['evidence']['cleanup']['completed'])
        self.assertFalse(present)

    def test_cleanup_failure_keeps_unknown_and_records_remaining_owned_resources(self):
        app=self.application()
        inspected={'Id':'a'*64,'Image':'sha256:'+'b'*64,'Mounts':[],
                   'Config':{'User':'70:70','Labels':{'starbots.review.synthetic':'true'}},
                   'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'CapDrop':['ALL'],
                                 'SecurityOpt':['no-new-privileges'],'PidsLimit':64,'Memory':536870912,
                                 'NanoCpus':1000000000,'Privileged':False}}
        present=[]
        def execute(argv,sql=None):
            if 'inspect' in argv:return json.dumps([inspected])
            if sql and 'CREATE ROLE' in sql:
                present.extend(re.findall(r'CREATE ROLE (sb_\w+)',sql))
                raise RuntimeError('Ambiguous creation timeout')
            if sql and 'pg_database' in sql:
                return json.dumps({'database_present':False,'database_owned':False,
                                   'roles':[{'name':r,'owned':True} for r in present]})
            if sql and 'DROP ROLE' in sql:raise RuntimeError('Injected cleanup timeout')
            return ''
        with tempfile.TemporaryDirectory() as directory,patch.object(app,'_docker_command',return_value=['reviewed-docker']):
            with patch.object(app,'_rls_process',side_effect=execute):
                result=app.run_rls_fixture('corrected',directory,runtime={'container_id':'a'*64,'image_digest':'sha256:'+'b'*64})
        self.assertEqual(result['state'],'UNKNOWN')
        self.assertFalse(result['evidence']['cleanup']['completed'])
        self.assertEqual(len(result['evidence']['cleanup']['after']['roles']),3)
        self.assertTrue(any('cleanup failed' in e for e in result['errors']))

    def test_container_capability_addition_is_rejected_before_sql(self):
        app=self.application()
        inspected={'Id':'a'*64,'Image':'sha256:'+'b'*64,'Mounts':[],
                   'Config':{'User':'70:70','Labels':{'starbots.review.synthetic':'true'}},
                   'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'CapDrop':['ALL'],
                                 'CapAdd':['SYS_ADMIN'],'SecurityOpt':['no-new-privileges'],
                                 'PidsLimit':64,'Memory':536870912,'NanoCpus':1000000000,'Privileged':False}}
        with tempfile.TemporaryDirectory() as directory,patch.object(app,'_docker_command',return_value=['reviewed-docker']):
            with patch.object(app,'_rls_process',side_effect=[json.dumps([inspected]),RuntimeError('SQL must not run'),RuntimeError('No cleanup'),RuntimeError('No cleanup')]) as execute:
                result=app.run_rls_fixture('corrected',directory,runtime={'container_id':'a'*64,'image_digest':'sha256:'+'b'*64})
        self.assertEqual(result['state'],'UNKNOWN')
        self.assertFalse(result['evidence']['attempted']['roles'],'Added capabilities must be rejected before any SQL')
        self.assertEqual(execute.call_count,1)
