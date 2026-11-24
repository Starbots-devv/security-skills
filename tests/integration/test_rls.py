"""Explicit integration gate: absent PostgreSQL is a failure, never a skip."""
import importlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


class PostgreSQLRLSIntegrationTests(unittest.TestCase):
    def test_actual_postgresql_ambiguous_role_and_database_ack_are_reconciled(self):
        runtime_file=os.environ.get('STARBOTS_PG_RUNTIME')
        self.assertTrue(runtime_file,'PostgreSQL prerequisite: reviewed runtime JSON required')
        runtime=json.loads(Path(runtime_file).read_text(encoding='utf-8-sig'))
        app=importlib.import_module('starbots_security.application')
        original=app._rls_process
        for statement in ['CREATE ROLE','CREATE DATABASE']:
            injected=False
            def lose_ack(argv,sql=None):
                nonlocal injected
                output=original(argv,sql)
                if not injected and sql and statement in sql:
                    injected=True
                    raise RuntimeError('Injected acknowledgement loss after actual committed SQL')
                return output
            with self.subTest(statement=statement), tempfile.TemporaryDirectory() as directory:
                with patch.object(app,'_rls_process',side_effect=lose_ack):
                    result=app.run_rls_fixture('corrected',directory,runtime=runtime)
                self.assertTrue(injected,result)
                self.assertEqual(result['state'],'UNKNOWN',result)
                self.assertTrue(result['errors'])
                self.assertTrue(result['evidence']['cleanup']['completed'],result)
                self.assertEqual(result['evidence']['cleanup']['after']['roles'],[])
                self.assertFalse(result['evidence']['cleanup']['after']['database_present'])

    def test_actual_postgresql_tenant_rls_and_unsafe_service_bypass(self):
        runtime_file = os.environ.get('STARBOTS_PG_RUNTIME')
        self.assertTrue(runtime_file, 'PostgreSQL prerequisite: set STARBOTS_PG_RUNTIME to the operator-reviewed isolated Docker runtime JSON')
        runtime = json.loads(Path(runtime_file).read_text(encoding='utf-8-sig'))
        app = importlib.import_module('starbots_security.application')
        for variant, expected in [('vulnerable', 'FAIL'), ('corrected', 'PASS')]:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                result = app.run_rls_fixture(variant, directory, runtime=runtime)
                self.assertEqual(result['state'], expected, result)
                self.assertFalse(result['errors'], result)
                self.assertTrue(result['coverage']['executed'])
                self.assertGreaterEqual(len(result['evidence']['probes']), 15)
                service = next(p for p in result['evidence']['probes'] if p['id'] == 'service-bypass')
                self.assertTrue(service['unsafe'])
                self.assertEqual(service['observed'], 3)
                self.assertTrue(result['evidence']['cleanup']['completed'])
