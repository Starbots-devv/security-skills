"""Synthetic local HTTP and isolated PostgreSQL access-control experiments.

Results describe only executed probes. They are not a production assessment.
"""
from __future__ import annotations

import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from importlib.resources import files
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading
import uuid


EXAMPLES = files(__package__).joinpath('data/application')
# Explicit operator-reviewed host-runtime identity. Runtime observations cannot
# supply or replace this authority. A different host requires operator repinning.
DOCKER_EXECUTABLE = Path('C:/Program Files/Docker/Docker/resources/bin/docker.exe')
DOCKER_EXECUTABLE_SHA256 = 'cd1516f39176339abb686b1e5f3de41de10b805314054f88c5476ade7b9310bb'
MAX_RLS_OUTPUT = 10 * 1024 * 1024


def _docker_command(runtime, config_dir):
    executable = Path(runtime.get('docker_executable', ''))
    expected = runtime.get('docker_executable_sha256')
    if (not executable.is_absolute() or executable != DOCKER_EXECUTABLE
            or expected != DOCKER_EXECUTABLE_SHA256 or not executable.is_file()):
        raise ValueError('Docker executable must match the absolute operator-reviewed path and SHA-256 pin')
    if any(p.is_symlink() or (hasattr(p, 'is_junction') and p.is_junction())
           for p in [executable, *executable.parents]):
        raise ValueError('Docker executable path must not traverse links or junctions')
    digest = hashlib.sha256()
    with executable.open('rb') as stream:
        for block in iter(lambda: stream.read(1024*1024), b''):
            digest.update(block)
    if digest.hexdigest() != expected:
        raise ValueError('Docker executable bytes do not match the operator-reviewed SHA-256')
    Path(config_dir, 'config.json').write_text('{}', encoding='utf-8')
    endpoint = 'npipe:////./pipe/docker_engine' if os.name == 'nt' else 'unix:///var/run/docker.sock'
    return [str(executable), '--config', str(config_dir), '--host', endpoint]


def _rls_process(argv, sql=None, *, timeout=60, max_output=MAX_RLS_OUTPUT):
    """One deadline includes process exit, input and pipe EOF; no blocking drain."""
    import time
    data = sql.encode('utf-8') if sql is not None else b''
    if len(data) > 1024 * 1024:
        raise ValueError('Synthetic SQL input exceeds 1 MiB')
    env = {key: os.environ[key] for key in ('SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP') if key in os.environ}
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=env, bufsize=0)
    streams=[process.stdout,process.stderr];chunks=[bytearray(),bytearray()]
    eof=set();sent=0;deadline=time.monotonic()+timeout
    try:
        for stream in [process.stdin,*streams]:os.set_blocking(stream.fileno(),False)
        while len(eof)<2 or process.poll() is None:
            if time.monotonic()>=deadline:
                raise RuntimeError('Process timeout or incomplete pipe drain; SQL acknowledgement may be ambiguous')
            progress=False
            if not process.stdin.closed:
                if sent==len(data):process.stdin.close()
                else:
                    try:sent+=os.write(process.stdin.fileno(),data[sent:sent+8192]);progress=True
                    except BlockingIOError:pass
                    except BrokenPipeError:process.stdin.close()
            for index,stream in enumerate(streams):
                if index in eof:continue
                try:block=os.read(stream.fileno(),8192)
                except BlockingIOError:continue
                if not block:eof.add(index);continue
                progress=True;chunks[index].extend(block)
                if sum(map(len,chunks))>max_output:raise RuntimeError('Process output limit exceeded (combined stdout/stderr)')
            if not progress:time.sleep(min(.005,max(0,deadline-time.monotonic())))
        if process.returncode:raise RuntimeError(f'Local PostgreSQL command failed ({process.returncode})')
        return bytes(chunks[0]).decode('utf-8',errors='strict')
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=1)
        # Unbuffered pipes and no reader threads: closure cannot wait for a child
        # that retained a pipe. Such a child never makes incomplete output PASS.
        for stream in [process.stdin,*streams]:stream.close()


def _variant(value):
    if value not in {'vulnerable', 'corrected'}:
        raise ValueError('Only vulnerable/corrected local synthetic fixtures are supported')
    return value


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _save(result, output_dir, filename):
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / filename).write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    return result


def run_api_fixture(variant, output_dir):
    """Start an ephemeral 127.0.0.1 server, exercise it, stop it, save observations."""
    variant = _variant(variant)
    raw = (EXAMPLES / 'tenant-api' / f'{variant}.json').read_bytes()
    corrected = json.loads(raw)['enforce_authorization']
    users = {
        'a-token': {'id': 'alice', 'tenant': 'a', 'role': 'member'},
        'a2-token': {'id': 'alex', 'tenant': 'a', 'role': 'member'},
        'b-token': {'id': 'bob', 'tenant': 'b', 'role': 'member'},
        'admin-token': {'id': 'admin', 'tenant': 'a', 'role': 'admin'},
        'expired-token': {'id': 'alice', 'tenant': 'a', 'role': 'member'},
    }
    rows = {
        'a': {'id': 'a', 'tenant': 'a', 'owner': 'alice', 'value': 'A'},
        'a2': {'id': 'a2', 'tenant': 'a', 'owner': 'alex', 'value': 'A2'},
        'b': {'id': 'b', 'tenant': 'b', 'owner': 'bob', 'value': 'B'},
    }

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def reply(self, status, body):
            encoded = json.dumps(body, sort_keys=True).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self):
            self.handle_request()

        def do_PATCH(self):
            self.handle_request()

        def handle_request(self):
            token = self.headers.get('Authorization', '').removeprefix('Bearer ')
            user = users.get(token)
            if corrected and (user is None or token == 'expired-token'):
                self.reply(401, {'error': 'session-required'})
                return
            user = user or users['a-token']
            # Deliberately unsafe variant trusts a caller-supplied tenant header.
            tenant = user['tenant'] if corrected else self.headers.get('X-Tenant', user['tenant'])
            length = int(self.headers.get('Content-Length', '0'))
            body = json.loads(self.rfile.read(length)) if length else {}
            if self.path == '/me':
                if self.command == 'PATCH':
                    if corrected and set(body) - {'display_name'}:
                        self.reply(400, {'error': 'field-not-writable'})
                        return
                    user.update(body)
                self.reply(200, dict(user))
                return
            if self.path == '/admin':
                self.reply(200 if not corrected or user['role'] == 'admin' else 403,
                           {'function': 'admin'})
                return
            if self.path in {'/bulk', '/export'}:
                if corrected and user['role'] != 'admin':
                    self.reply(403, {'error': 'admin-required'})
                    return
                visible = [dict(row) for row in rows.values()
                           if not corrected or row['tenant'] == tenant]
                self.reply(200, {'rows': visible})
                return
            if self.path == '/tenant-rows':
                self.reply(200, {'rows': [dict(row) for row in rows.values() if row['tenant'] == tenant]})
                return
            row = rows.get(self.path.removeprefix('/objects/'))
            if row is None:
                self.reply(404, {'error': 'missing'})
                return
            if corrected and (row['tenant'] != tenant or row['owner'] != user['id']):
                self.reply(403, {'error': 'object-forbidden'})
                return
            if self.command == 'PATCH':
                if corrected and set(body) - {'value'}:
                    self.reply(400, {'error': 'field-not-writable'})
                    return
                row.update(body)
            self.reply(200, dict(row))

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    probes, errors = [], []

    def probe(identifier, control, token, method, path, expected_status, body=None, headers=None,
              expected_fields=None, expected_row_ids=None):
        request_headers = {'Content-Type': 'application/json'}
        if token:
            request_headers['Authorization'] = 'Bearer ' + token
        request_headers.update(headers or {})
        connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
        try:
            connection.request(method, path, json.dumps(body) if body is not None else None,
                               request_headers)
            response = connection.getresponse()
            payload = json.loads(response.read())
            passed = response.status == expected_status
            if expected_fields:
                passed = passed and all(payload.get(k) == v for k, v in expected_fields.items())
            if expected_row_ids is not None:
                passed = passed and sorted(r['id'] for r in payload.get('rows', [])) == sorted(expected_row_ids)
            probes.append({'id': identifier, 'control': control, 'transport': 'loopback-http',
                           'request': {'identity': token, 'method': method, 'path': path,
                                       'body': body, 'headers': headers or {}},
                           'expected_status': expected_status, 'status': response.status,
                           'response': payload, 'expected_fields': expected_fields,
                           'expected_row_ids': expected_row_ids, 'passed': passed})
        except (OSError, ValueError, http.client.HTTPException) as exc:
            errors.append({'probe': identifier, 'error': str(exc)})
        finally:
            connection.close()

    try:
        for who, other in [('a', 'b'), ('b', 'a')]:
            probe(f'{who}-legitimate-read', 'legitimate', f'{who}-token', 'GET', f'/objects/{who}',
                  200, expected_fields={'owner': 'alice' if who == 'a' else 'bob'})
            probe(f'{who}-read-{other}', 'object-read', f'{who}-token', 'GET', f'/objects/{other}', 403)
            probe(f'{who}-write-{other}', 'object-write', f'{who}-token', 'PATCH', f'/objects/{other}',
                  403, {'value': 'unauthorized'})
        probe('same-tenant-other-user', 'object-read', 'a-token', 'GET', '/objects/a2', 403)
        probe('same-tenant-other-user-write', 'object-write', 'a-token', 'PATCH', '/objects/a2',
              403, {'value': 'unauthorized'})
        for object_id, token, value in [('a', 'a-token', 'A'), ('b', 'b-token', 'B'),
                                         ('a2', 'a2-token', 'A2')]:
            probe(object_id + '-denied-write-unchanged', 'object-write', token, 'GET',
                  '/objects/' + object_id, 200, expected_fields={'value': value})
        probe('wrong-role', 'function-role', 'a-token', 'GET', '/admin', 403)
        probe('legitimate-admin', 'legitimate', 'admin-token', 'GET', '/admin', 200)
        for endpoint in ['bulk', 'export']:
            probe(f'{endpoint}-member', 'bulk-export', 'a-token', 'GET', '/' + endpoint, 403)
            probe(f'{endpoint}-admin', 'bulk-export', 'admin-token', 'GET', '/' + endpoint,
                  200, expected_row_ids=['a', 'a2'])
        probe('forged-header', 'forged-tenant', 'a-token', 'GET', '/tenant-rows', 200,
              headers={'X-Tenant': 'b'}, expected_row_ids=['a', 'a2'])
        probe('unauthenticated', 'session', None, 'GET', '/objects/a', 401)
        probe('expired', 'session', 'expired-token', 'GET', '/objects/a', 401)
        probe('object-sensitive-fields', 'mass-assignment', 'a-token', 'PATCH', '/objects/a',
              400, {'owner': 'bob', 'tenant': 'b'})
        probe('sensitive-field', 'mass-assignment', 'a-token', 'PATCH', '/me',
              400, {'role': 'admin', 'tenant': 'b'})
        probe('role-unchanged', 'mass-assignment', 'a-token', 'GET', '/me', 200,
              expected_fields={'role': 'member', 'tenant': 'a'})
        for who in ['a', 'b']:
            probe(f'{who}-legitimate-write', 'legitimate', f'{who}-token', 'PATCH', f'/objects/{who}',
                  200, {'value': who + '-updated'}, expected_fields={'value': who + '-updated'})
            probe(f'{who}-write-persisted', 'legitimate', f'{who}-token', 'GET', f'/objects/{who}',
                  200, expected_fields={'value': who + '-updated'})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    result = {'check_id': 'api-authorization',
              'state': 'UNKNOWN' if errors else ('PASS' if all(p['passed'] for p in probes) else 'FAIL'),
              'evidence': {'variant': variant, 'fixture_sha256': _sha(raw),
                           'implementation_sha256': _sha(Path(__file__).read_bytes()), 'probes': probes},
              'coverage': {'executed': bool(probes), 'scope': 'synthetic-loopback-only',
                           'controls': sorted({p['control'] for p in probes}),
                           'limitations': ['Fixed synthetic identities; no JWT/identity-provider validation',
                                           'Only enumerated routes and request cases were tested']},
              'errors': errors}
    return _save(result, output_dir, 'api-observation.json')


def run_rls_fixture(variant, output_dir, runtime=None):
    """Measure RLS on an operator-reviewed, isolated Docker PostgreSQL container."""
    variant = _variant(variant)
    raw = (EXAMPLES / 'tenant-rls' / f'{variant}.sql').read_bytes()
    result = {'check_id': 'rls-isolation', 'state': 'UNKNOWN',
              'evidence': {'variant': variant, 'fixture_sha256': _sha(raw),
                           'fixture_sql': raw.decode(),
                           'implementation_sha256': _sha(Path(__file__).read_bytes()), 'probes': []},
              'coverage': {'executed': False, 'scope': 'synthetic-isolated-postgresql-only'},
              'errors': ['PostgreSQL integration prerequisite missing: operator-reviewed isolated runtime required']}
    if runtime is None:
        return _save(result, output_dir, 'rls-observation.json')
    result['errors'] = []
    attempted = {'roles': False, 'database': False}
    config = tempfile.TemporaryDirectory(prefix='sb-review-pg-docker-')
    suffix = uuid.uuid4().hex[:16]
    database = 'sb_db_' + suffix
    roles = {name: f'sb_{name}_{suffix}' for name in ['role_a', 'role_b', 'role_service']}
    marker = 'starbots-review-run:' + suffix
    setup_sql = raw.decode().format(**roles)
    role_sql = '\n'.join(f'CREATE ROLE {role} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
                         + ('BYPASSRLS;' if name == 'role_service' else 'NOBYPASSRLS;')
                         for name, role in roles.items())
    role_sql += '\n' + '\n'.join(f"COMMENT ON ROLE {role} IS '{marker}';" for role in roles.values())
    result['evidence'].update({'database': database, 'roles': roles, 'setup_sql': setup_sql,
                               'setup_sha256': _sha(setup_sql.encode()), 'role_sql': role_sql,
                               'role_sql_sha256': _sha(role_sql.encode()),
                               'ownership_marker': marker, 'attempted': attempted,
                               'cleanup': {'completed': False}})
    try:
        container = runtime.get('container_id', '')
        if not re.fullmatch(r'[a-f0-9]{12,64}', container):
            raise ValueError('Runtime requires an exact inspected Docker container ID')
        docker = _docker_command(runtime, config.name)

        def execute(arguments, sql=None):
            return _rls_process(docker + arguments, sql)

        inspected = json.loads(execute(['inspect', container]))[0]
        if (inspected['HostConfig']['NetworkMode'] != 'none'
                or inspected['HostConfig'].get('PortBindings')
                or inspected.get('Mounts')
                or inspected['Config'].get('Labels', {}).get('starbots.review.synthetic') != 'true'):
            raise ValueError('Runtime must be labeled synthetic, network none, no mounts/host ports')
        host, container_config = inspected['HostConfig'], inspected['Config']
        if (not host.get('ReadonlyRootfs') or host.get('CapDrop') != ['ALL'] or host.get('CapAdd')
                or 'no-new-privileges' not in host.get('SecurityOpt', [])
                or host.get('PidsLimit') != 64 or host.get('Memory') != 536870912
                or host.get('NanoCpus') != 1000000000 or host.get('Privileged')
                or host.get('Devices') or host.get('Binds') or container_config.get('User') != '70:70'):
            raise ValueError('PostgreSQL runtime isolation differs from reviewed read-only/nonroot/resource policy')
        if not runtime.get('image_digest', '').startswith('sha256:') or inspected['Image'] != runtime['image_digest']:
            raise ValueError('Container image must match the operator-reviewed immutable image ID')
        result['evidence']['runtime'] = {'container_id': inspected['Id'],
                                          'image_digest': inspected['Image'], 'network': 'none',
                                          'docker_executable_sha256': runtime.get('docker_executable_sha256'),
                                          'isolation': {key: host[key] for key in ['ReadonlyRootfs','CapDrop','PidsLimit','Memory','NanoCpus']},
                                          'user': container_config['User'],
                                          'environment': 'minimal-system-only; fresh empty config; fixed local endpoint',
                                          'max_output_bytes': MAX_RLS_OUTPUT, 'timeout_seconds': 60}

        def psql(db, sql):
            return execute(['exec', '-i', container, 'psql', '-X', '-q', '-A', '-t',
                            '-v', 'ON_ERROR_STOP=1', '-h', '/tmp', '-U', 'postgres', '-d', db], sql)

        # Ownership tags commit atomically with roles, even if acknowledgement is lost.
        attempted['roles'] = True
        psql('postgres', 'BEGIN;\n' + role_sql + '\nCOMMIT;')
        attempted['database'] = True
        psql('postgres', f"CREATE DATABASE {database} OWNER {roles['role_a']};")
        psql(database, setup_sql)
        script, expected = [], {}
        script.append("CREATE FUNCTION pg_temp.sb_try(statement text) RETURNS text LANGUAGE plpgsql "
                      "SECURITY INVOKER AS $$ BEGIN EXECUTE statement; RETURN '00000'; "
                      "EXCEPTION WHEN OTHERS THEN RETURN SQLSTATE; END $$;")
        script.append("CREATE FUNCTION pg_temp.sb_count(statement text) RETURNS integer LANGUAGE plpgsql "
                      "SECURITY INVOKER AS $$ DECLARE affected integer; BEGIN EXECUTE statement; "
                      "GET DIAGNOSTICS affected = ROW_COUNT; RETURN affected; END $$;")

        def observe(identifier, expression, value, role, unsafe=False):
            expected[identifier] = {'expected': value, 'expected_role': role, 'unsafe': unsafe}
            script.append("SELECT json_build_object('id', '" + identifier + "', 'observed', "
                          + expression + ", 'role', current_user, 'session_user', session_user, "
                          "'backend_pid', pg_backend_pid(), 'rolsuper', "
                          "(SELECT rolsuper FROM pg_roles WHERE rolname=current_user), "
                          "'rolbypassrls', (SELECT rolbypassrls FROM pg_roles WHERE rolname=current_user));")

        def attempt(statement):
            return "pg_temp.sb_try('" + statement.replace("'", "''") + "')"

        def affected(statement):
            return "pg_temp.sb_count('" + statement.replace("'", "''") + "')"

        for tenant, other, role in [('a', 'b', roles['role_a']), ('b', 'a', roles['role_b'])]:
            script.append(f"BEGIN; SET LOCAL ROLE {role}; SET LOCAL app.tenant_id = '{tenant}';")
            observe(tenant + '-visible', '(SELECT count(*) FROM tenant_objects)', 2 if tenant == 'a' else 1, role)
            observe(tenant + '-read-other', f"(SELECT count(*) FROM tenant_objects WHERE tenant='{other}')", 0, role)
            observe(tenant + '-write-other', affected(f"UPDATE tenant_objects SET value='attack' WHERE tenant='{other}'"), 0, role)
            observe(tenant + '-delete-other', affected(f"DELETE FROM tenant_objects WHERE tenant='{other}'"), 0, role)
            observe(tenant + '-insert-other', attempt(f"INSERT INTO tenant_objects VALUES ('new-{tenant}','{other}','attack')"), '42501', role)
            observe(tenant + '-change-tenant', attempt(f"UPDATE tenant_objects SET tenant='{other}' WHERE id='{tenant}'"), '42501', role)
            observe(tenant + '-legitimate-write', affected(f"UPDATE tenant_objects SET value='good' WHERE id='{tenant}'"), 1, role)
            observe(tenant + '-legitimate-insert', attempt(f"INSERT INTO tenant_objects VALUES ('own-{tenant}','{tenant}','good')"), '00000', role)
            script.append('ROLLBACK;')
        script.append(f"BEGIN; SET LOCAL ROLE {roles['role_a']}; SET LOCAL app.tenant_id='b';")
        observe('forged-tenant-context', '(SELECT count(*) FROM tenant_objects)', 0, roles['role_a'])
        script.append('COMMIT;')
        # Same psql process/backend: a committed SET LOCAL must not survive pool reuse.
        script.append(f"BEGIN; SET LOCAL ROLE {roles['role_b']};")
        observe('pooled-context-cleared', "coalesce(current_setting('app.tenant_id',true),'')", '', roles['role_b'])
        observe('pooled-no-context-read', '(SELECT count(*) FROM tenant_objects)', 0, roles['role_b'])
        script.append("SET LOCAL app.tenant_id='b';")
        observe('pooled-b-read', '(SELECT count(*) FROM tenant_objects)', 1, roles['role_b'])
        script.append('COMMIT;')
        script.append(f"BEGIN; SET LOCAL ROLE {roles['role_service']}; SET LOCAL app.tenant_id='a';")
        observe('service-bypass', '(SELECT count(*) FROM tenant_objects)', 3, roles['role_service'], unsafe=True)
        script.append('ROLLBACK;')
        probe_sql = '\n'.join(script)
        result['evidence'].update({'probe_sql': probe_sql, 'probe_sql_sha256': _sha(probe_sql.encode())})
        output = psql(database, probe_sql)
        result['evidence']['psql_stdout'] = output
        observations = [json.loads(line) for line in output.splitlines() if line.strip()]
        seen = set()
        for observed in observations:
            identifier = observed['id']
            if identifier in seen or identifier not in expected:
                raise ValueError('Unexpected/duplicate SQL probe output')
            seen.add(identifier)
            probe = {**observed, **expected[identifier]}
            identity_ok = observed['role'] == probe['expected_role'] and not observed['rolsuper']
            identity_ok = identity_ok and observed['rolbypassrls'] == probe['unsafe']
            probe['passed'] = observed['observed'] == probe['expected'] and identity_ok
            result['evidence']['probes'].append(probe)
        if seen != set(expected) or len({p['backend_pid'] for p in observations}) != 1:
            raise ValueError('Missing probes or pooled connection was not reused')
        result['coverage'].update({'executed': True, 'controls': ['tenant-read', 'tenant-write',
                                  'using', 'with-check', 'transaction-local-context', 'pooled-reuse'],
                                  'limitations': ['Synthetic SQL only; connection provisioned as local postgres',
                                                  'Service BYPASSRLS identity is explicitly unsafe and excluded from tenant isolation assurance']})
        result['state'] = 'PASS' if all(p['passed'] for p in result['evidence']['probes']) else 'FAIL'
    except (KeyError, ValueError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        result['errors'].append(str(exc))
        result['state'] = 'UNKNOWN'
    finally:
        if any(attempted.values()):
            names = ','.join("'"+role+"'" for role in roles.values())
            reconcile_sql = f"""SELECT json_build_object(
                'database_present', EXISTS(SELECT 1 FROM pg_database WHERE datname='{database}'),
                'database_owned', EXISTS(SELECT 1 FROM pg_database d JOIN pg_roles r ON r.oid=d.datdba
                    WHERE d.datname='{database}' AND r.rolname='{roles['role_a']}'
                    AND shobj_description(r.oid,'pg_authid')='{marker}'),
                'roles', (SELECT coalesce(json_agg(json_build_object('name',rolname,
                    'owned',coalesce(shobj_description(oid,'pg_authid')='{marker}',false))),'[]')
                    FROM pg_roles WHERE rolname IN ({names})));"""

            def reconcile():
                snapshot = json.loads(psql('postgres', reconcile_sql))
                if (not isinstance(snapshot, dict) or not isinstance(snapshot.get('roles'),list)
                        or not isinstance(snapshot.get('database_present'), bool)
                        or not isinstance(snapshot.get('database_owned'), bool)
                        or any(r.get('name') not in roles.values() or not isinstance(r.get('owned'),bool)
                               for r in snapshot['roles'])):
                    raise ValueError('Invalid resource reconciliation output')
                return snapshot

            try:
                before = reconcile()
                result['evidence']['cleanup']['before'] = before
                if before['database_present'] and not before['database_owned']:
                    raise RuntimeError('Refusing cleanup: database ownership does not match this run')
                if before['database_owned']:
                    psql('postgres', f'DROP DATABASE {database} WITH (FORCE);')
                for role in before['roles']:
                    if not role['owned']:
                        raise RuntimeError('Refusing cleanup: role ownership does not match this run')
                    psql('postgres', f"DROP ROLE IF EXISTS {role['name']};")
            except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
                result['errors'].append('Fixture cleanup failed: ' + str(exc))
                result['state'] = 'UNKNOWN'
            finally:
                try:
                    after = reconcile()
                    result['evidence']['cleanup']['after'] = after
                    completed = not after['database_present'] and not after['roles']
                    result['evidence']['cleanup']['completed'] = completed
                    if not completed:
                        result['errors'].append('Fixture resources remain after reconciliation')
                        result['state'] = 'UNKNOWN'
                except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
                    result['errors'].append('Final resource reconciliation failed: ' + str(exc))
                    result['state'] = 'UNKNOWN'
        try:
            config.cleanup()
        except OSError:
            result['errors'].append('Temporary Docker configuration cleanup failed')
            result['state'] = 'UNKNOWN'
    return _save(result, output_dir, 'rls-observation.json')
