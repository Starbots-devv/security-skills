import importlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch, Mock


class RunnerSafety(unittest.TestCase):
    def test_inline_iac_suppressions_are_rejected_before_execution(self):
        self.assertTrue(hasattr(self.r,'validate_iac_scope'))
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);p=root/'main.tf'
            for marker in ['# trivy:ignore:AVD-AWS-0107','# tfsec:ignore:aws-s3-enable-bucket-logging']:
                p.write_text(marker+'\nresource "aws_s3_bucket" "synthetic" {}\n')
                with self.assertRaisesRegex(ValueError,'suppression'):self.r.validate_iac_scope(root,self.r.input_manifest(root))
            p.write_text('resource "aws_s3_bucket" "synthetic" {}\n')
            self.r.validate_iac_scope(root,self.r.input_manifest(root))
            self.assertIn('--show-suppressed',self.r.scanner_arguments('trivy',self.r.input_manifest(root)))
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('starbots_security.runner'), 'Bounded runner is missing')
        self.r = importlib.import_module('starbots_security.runner')

    def test_missing_runtime_or_toolchain_is_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, 'sample.txt').write_text('synthetic')
            result = self.r.run_scanner('gitleaks', d, d, as_of='2026-10-18T11:30:00Z', docker_executable='missing-runtime')
            self.assertEqual(result['state'], 'UNKNOWN')
            self.assertFalse(result['coverage']['performed'])
            self.assertTrue(result['errors'])

    def test_input_manifest_rejects_links_unsafe_mounts_and_limits(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'a.txt').write_text('synthetic')
            manifest = self.r.input_manifest(p)
            self.assertEqual(manifest[0]['path'], 'a.txt')
            self.assertEqual(manifest[0]['size'], 9)
            self.assertEqual(len(manifest[0]['sha256']), 64)
            with self.assertRaises(ValueError): self.r.input_manifest(p, max_bytes=1)
            with self.assertRaises(ValueError): self.r.safe_mount_path(p / 'bad,source=x')
            with self.assertRaises(ValueError): self.r.safe_mount_path(p / 'bad\npath')

    def test_real_directory_link_or_windows_junction_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);target=root/'real';target.mkdir();(target/'inert.txt').write_text('synthetic')
            link=root/'linked'
            if os.name=='nt':
                result=subprocess.run([str(Path(os.environ['SYSTEMROOT'])/'System32/cmd.exe'),'/c','mklink','/J',str(link),str(target)],capture_output=True)
                self.assertEqual(result.returncode,0,'Cannot create local junction prerequisite')
            else:link.symlink_to(target,target_is_directory=True)
            with self.assertRaises(ValueError):self.r.input_manifest(root)
            with self.assertRaises(ValueError):self.r.safe_mount_path(link)

    def test_process_timeout_and_output_limit_are_enforced(self):
        with self.assertRaises(self.r.RunnerFailure):
            self.r.bounded_process([sys.executable, '-c', 'import time; time.sleep(5)'], timeout=.1)
        with self.assertRaises(self.r.RunnerFailure):
            self.r.bounded_process([sys.executable, '-c', 'print("x"*200000)'], timeout=5, max_output=1024)

    def test_only_pinned_tools_fixed_commands_and_sandbox(self):
        plan = self.r.sandbox_arguments('sbr-' + 'a'*32, [('/tmp/input', '/input')], ['--version'])
        text = ' '.join(plan)
        for required in ('--pull=never', '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--user=65534:65534', '--pids-limit=64', '--memory=1073741824', '--cpus=1', 'readonly', 'size=16777216'):
            self.assertIn(required, text)
        self.assertNotIn('docker.sock', text)
        with self.assertRaises(ValueError): self.r.scanner_arguments('arbitrary', [])
        with self.assertRaises(ValueError): self.r.sandbox_arguments('not-owned', [], [])

    def test_tampered_toolchain_never_executes(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, 'sample.txt').write_text('synthetic')
            result = self.r.run_scanner('gitleaks', d, d, as_of='2026-10-18T11:30:00Z')
            self.assertEqual(result['state'], 'UNKNOWN')
            self.assertIsNone(result['exit_code'])

    def test_clean_environment_excludes_credentials_and_remote_hosts(self):
        env = self.r.clean_environment()
        self.assertFalse(any(k in env for k in ('DOCKER_HOST','HTTP_PROXY','HTTPS_PROXY','AWS_SECRET_ACCESS_KEY','GITHUB_TOKEN')))

    def test_docker_client_is_fixed_absolute_hash_pinned_before_execution(self):
        self.assertTrue(hasattr(self.r, 'trusted_runtime'), 'Runtime trust enforcement is missing')
        with self.assertRaises(self.r.RunnerFailure): self.r.trusted_runtime('docker')
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, 'docker.exe'); p.write_bytes(b'not the reviewed Docker binary')
            with self.assertRaises(self.r.RunnerFailure): self.r.trusted_runtime(p)

    def test_mount_probes_verify_mount_flags_instead_of_windows_access_bits(self):
        self.assertNotIn('test ! -w /input', self.r.WRAPPER)
        self.assertIn('/proc/mounts', self.r.WRAPPER)

    def test_deadline_includes_pipe_eof_after_parent_process_exits(self):
        child='import time; time.sleep(3)'
        code='import subprocess,sys; subprocess.Popen([sys.executable,"-c",'+repr(child)+'])'
        started=time.monotonic()
        with self.assertRaises(self.r.RunnerFailure):
            self.r.bounded_process([sys.executable,'-c',code],timeout=.2)
        self.assertLess(time.monotonic()-started,1.5)

    def test_osv_requires_receipt_of_each_offline_database_being_loaded(self):
        self.assertTrue(hasattr(self.r,'verify_offline_receipt'), 'Offline execution receipt validation is missing')
        manifest=[{'path':'package-lock.json'}]
        with self.assertRaises(self.r.RunnerFailure): self.r.verify_offline_receipt(manifest,b'No issues found')
        self.r.verify_offline_receipt(manifest,b'Loaded npm local db from /db/osv-scalibr/npm/all.zip')

    def test_actual_inspection_rejects_changed_tmpfs_or_image(self):
        document={'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],'PidsLimit':64,'Memory':1073741824,'NanoCpus':1000000000,'Tmpfs':{'/tmp':'rw,nosuid,nodev,noexec,size=536870912,mode=1777','/out':'rw,nosuid,nodev,noexec,size=16777216,mode=1777'}},'Config':{'User':'65534:65534','Image':self.r.IMAGE},'Mounts':[]}
        self.r._inspect(document,[])
        document['HostConfig']['Tmpfs']['/out']='size=999999999'
        with self.assertRaises(self.r.RunnerFailure): self.r._inspect(document,[])
        document['HostConfig']['Tmpfs']['/out']='rw,nosuid,nodev,noexec,size=16777216,mode=1777'
        document['Config']['Image']='untrusted:latest'
        with self.assertRaises(self.r.RunnerFailure): self.r._inspect(document,[])

    def test_acquisition_helper_defaults_to_offline_hash_verification(self):
        helper=Path(__file__).resolve().parents[1]/'tools/acquire_toolchain.py'
        self.assertTrue(helper.is_file(), 'Reproducible pinned toolchain preparation is missing')
        spec=importlib.util.spec_from_file_location('acquire_toolchain_helper',helper)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError): module.verify(Path(d))

    def test_create_timeout_still_removes_only_the_owned_uuid_container(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'sample.txt').write_text('synthetic')
            (root/'bin').mkdir();(root/'bin/gitleaks').write_text('inert')
            (root/'license').write_text('inert')
            lock={'review':{'tools':[{'name':'gitleaks','version':'8.30.1','path':'bin/gitleaks','license_path':'license'}]},'files':{'bin/gitleaks':'x','license':'x'}}
            resource=Mock();resource.joinpath.return_value.read_bytes.return_value=json.dumps(lock).encode()
            calls=[]
            def process(args,**kwargs):
                calls.append(args)
                if 'create' in args:raise self.r.RunnerFailure('Process timeout')
                return 0,b'',b''
            with patch.object(self.r,'files',return_value=resource),patch.object(self.r,'_file_sha',return_value='x'),patch.object(self.r,'trusted_runtime',return_value='reviewed-docker'),patch.object(self.r,'bounded_process',side_effect=process):
                result=self.r.run_scanner('gitleaks',root,root,as_of='2026-10-18T12:00:00Z')
            self.assertEqual(result['state'],'UNKNOWN')
            self.assertTrue(any('rm' in args for args in calls),'A timed-out create can leave a created container behind')
            create=next(args for args in calls if 'create' in args)
            owned=create[create.index('--name')+1]
            self.assertRegex(owned,r'^sbr-[a-f0-9]{32}$')
            self.assertEqual(calls[-1][-1],owned)


if __name__ == '__main__': unittest.main()
