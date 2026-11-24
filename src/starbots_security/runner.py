"""Fixed local scanner execution. No host fallback, network, writable host mounts or user argv."""
from datetime import datetime, timezone, timedelta
from importlib.resources import files
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid

from .adapters import normalize

IMAGE = 'docker.io/library/alpine@sha256:d56c381f961d307a21b3ca004cf1e3910f106644aefb1f43e654c8a56c4fd395'
TOOLS = {'gitleaks': 'gitleaks', 'osv-scanner': 'osv', 'trivy': 'trivy'}
MAX_OUTPUT = 10 * 1024 * 1024
DOCKER_PATH = Path('C:/Program Files/Docker/Docker/resources/bin/docker.exe')
DOCKER_SHA256 = 'cd1516f39176339abb686b1e5f3de41de10b805314054f88c5476ade7b9310bb'


class RunnerFailure(RuntimeError):
    pass


def trusted_runtime(value=None):
    path = Path(value) if value is not None else DOCKER_PATH
    if not path.is_absolute() or path != DOCKER_PATH or not path.is_file() or _file_sha(safe_mount_path(path)) != DOCKER_SHA256:
        raise RunnerFailure('Reviewed local Docker client is missing or mismatched')
    return str(path)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _file_sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''): h.update(block)
    return h.hexdigest()


def _linked(path):
    return path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction())


def safe_mount_path(path):
    p = Path(path).absolute()
    if any(c in str(p) for c in (',', '\n', '\r', '\x00')): raise ValueError('Unsafe mount path')
    if any(_linked(x) for x in (p, *p.parents)): raise ValueError('Links and junctions are forbidden')
    return p


def input_manifest(root, *, max_bytes=16 * 1024 * 1024, max_files=1000):
    root = safe_mount_path(root)
    if not root.is_dir(): raise ValueError('Input must be a directory')
    manifest = []; size = 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        for name in dirs + names:
            if _linked(Path(directory, name)): raise ValueError('Links and junctions are forbidden')
        for name in sorted(names):
            p = Path(directory, name)
            if not p.is_file(): raise ValueError('Only regular files are accepted')
            size += p.stat().st_size
            if size > max_bytes or len(manifest) >= max_files: raise ValueError('Input exceeds resource limits')
            manifest.append({'path': p.relative_to(root).as_posix(), 'size': p.stat().st_size, 'sha256': _file_sha(p)})
    return sorted(manifest, key=lambda f: f['path'])


def clean_environment():
    return {k: os.environ[k] for k in ('SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP') if k in os.environ}


def bounded_process(argv, *, timeout, max_output=MAX_OUTPUT, env=None):
    """Nonblocking drains keep process exit and inherited pipe EOF inside one deadline."""
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, stdin=subprocess.DEVNULL)
    chunks = [bytearray(), bytearray()]; total = 0
    streams = [process.stdout, process.stderr]; active = {0, 1}; deadline = time.monotonic() + timeout
    try:
        for stream in streams: os.set_blocking(stream.fileno(), False)
        while active or process.poll() is None:
            if time.monotonic() >= deadline: raise RunnerFailure('Process or pipe EOF timeout')
            progress = False
            for index in list(active):
                try: block = os.read(streams[index].fileno(), 8192)
                except BlockingIOError: continue
                if not block: active.remove(index); continue
                progress = True; total += len(block)
                if total > max_output: raise RunnerFailure('Process output limit exceeded')
                chunks[index].extend(block)
            if not progress: time.sleep(min(.01, max(0, deadline - time.monotonic())))
        return process.returncode, bytes(chunks[0]), bytes(chunks[1])
    finally:
        if process.poll() is None: process.kill()
        try: process.wait(timeout=1)
        except subprocess.TimeoutExpired: pass
        process.stdout.close(); process.stderr.close()


def scanner_arguments(tool, manifest):
    if tool == 'gitleaks':
        return ['dir', '/input', '--config', '/config/gitleaks.toml', '--gitleaks-ignore-path', '/config/empty-ignore', '--ignore-gitleaks-allow', '--redact=100', '--no-banner', '--no-color', '--report-format', 'json', '--report-path', '/out/result.json', '--exit-code', '1', '--timeout', '60']
    if tool == 'osv-scanner':
        allowed = {'package-lock.json', 'requirements.txt'}
        targets = [f['path'] for f in manifest if f['path'] in allowed]
        if not targets: raise ValueError('No supported dependency lockfile')
        args = ['scan', 'source', '--offline', '--no-resolve', '--config', '/config/osv-scanner.toml', '--local-db-path', '/db', '--format', 'json', '--output-file', '/out/result.json', '--all-packages']
        for target in targets: args += ['--lockfile', '/input/' + target]
        return args
    if tool == 'trivy':
        # Limit the IaC domain to standalone HCL, without remote modules or providers.
        if not manifest or any(not f['path'].endswith('.tf') for f in manifest): raise ValueError('Only standalone Terraform HCL is supported')
        return ['fs', '--scanners', 'misconfig', '--config', '/config/trivy.yaml', '--cache-dir', '/tmp/trivy-cache', '--skip-check-update', '--skip-db-update', '--skip-java-db-update', '--skip-version-check', '--disable-telemetry', '--offline-scan', '--show-suppressed', '--ignorefile', '/config/empty-ignore', '--format', 'json', '--output', '/out/result.json', '--exit-code', '1', '--timeout', '60s', '/input']
    raise ValueError('Unsupported scanner')


def verify_offline_receipt(manifest, stderr):
    for file, ecosystem in (('package-lock.json','npm'),('requirements.txt','PyPI')):
        if any(f['path']==file for f in manifest):
            receipt=f'Loaded {ecosystem} local db from /db/osv-scalibr/{ecosystem}/all.zip'.encode()
            if receipt not in stderr: raise RunnerFailure('Offline advisory matching was not demonstrated')


# Every shell token is reviewed static text. Scanner arguments are passed as positional arguments.
WRAPPER = '''set -u
test "$(id -u)" = 65534 || exit 70
awk '$2 == "/input" && $4 ~ /^ro,/ {ok=1} END {exit !ok}' /proc/mounts || exit 70
awk '$2 == "/tool/scanner" && $4 ~ /^ro,/ {ok=1} END {exit !ok}' /proc/mounts || exit 70
test "$(awk '/CapEff/ {print $2}' /proc/self/status)" = 0000000000000000 || exit 70
test "$(cat /sys/fs/cgroup/memory.max)" = 1073741824 || exit 70
test "$(cat /sys/fs/cgroup/pids.max)" = 64 || exit 70
test "$(cat /sys/fs/cgroup/cpu.max)" = '100000 100000' || exit 70
if nc -w 1 1.1.1.1 443 </dev/null >/dev/null 2>&1; then exit 70; fi
printf 'SB_SANDBOX_VERIFIED uid=65534 capeff=0 memory=1073741824 pids=64 cpu=1 network_connect=denied\\n' >&2
/tool/scanner version >/out/version 2>&1
if test $? -ne 0; then /tool/scanner --version >/out/version 2>&1; fi
printf 'SB_VERSION_BEGIN\\n' >&2
cat /out/version >&2
printf '\\nSB_VERSION_END\\n' >&2
/tool/scanner "$@"
rc=$?
test -f /out/result.json && cat /out/result.json
exit "$rc"
'''


def sandbox_arguments(name, mounts, args):
    if not re.fullmatch(r'sbr-[a-f0-9]{32}', name): raise ValueError('Invalid owned container name')
    result = ['create', '--name', name, '--pull=never', '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--user=65534:65534', '--pids-limit=64', '--memory=1073741824', '--memory-swap=1073741824', '--cpus=1', '--env', 'HOME=/tmp', '--env', 'PATH=/usr/bin:/bin', '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=536870912,mode=1777', '--tmpfs', '/out:rw,nosuid,nodev,noexec,size=16777216,mode=1777', '--workdir', '/tmp']
    for source, dest in mounts:
        source = safe_mount_path(source)
        if dest not in ('/input', '/tool/scanner', '/config', '/db/osv-scalibr'): raise ValueError('Unsupported mount destination')
        result += ['--mount', f'type=bind,source={source},target={dest},readonly']
    return result + ['--entrypoint', '/bin/sh', IMAGE, '-c', WRAPPER, 'sb-wrapper', *args]


def _inspect(document, mounts):
    h = document['HostConfig']; c = document['Config']
    expected = {dest for _, dest in mounts}
    actual = document['Mounts']
    tmpfs = {'/tmp':'rw,nosuid,nodev,noexec,size=536870912,mode=1777','/out':'rw,nosuid,nodev,noexec,size=16777216,mode=1777'}
    if h.get('Tmpfs') != tmpfs or c.get('Image') != IMAGE or h.get('CapAdd') or h.get('PidMode') or h.get('IpcMode') == 'host':
        raise RunnerFailure('Actual image, tmpfs or namespace isolation differs from policy')
    if not (h['NetworkMode'] == 'none' and h['ReadonlyRootfs'] and h['CapDrop'] == ['ALL'] and 'no-new-privileges' in h['SecurityOpt'] and h['PidsLimit'] == 64 and h['Memory'] == 1073741824 and h['NanoCpus'] == 1000000000 and c['User'] == '65534:65534' and not h.get('Privileged') and not h.get('PortBindings') and not h.get('Devices') and not h.get('Binds')):
        raise RunnerFailure('Actual container isolation differs from policy')
    if {m['Destination'] for m in actual} != expected or any(m['RW'] or m['Type'] != 'bind' for m in actual): raise RunnerFailure('Unexpected actual mounts')
    return {'network': h['NetworkMode'], 'read_only': h['ReadonlyRootfs'], 'cap_drop': h['CapDrop'], 'security_opt': h['SecurityOpt'], 'user': c['User'], 'memory': h['Memory'], 'nano_cpus': h['NanoCpus'], 'pids': h['PidsLimit'], 'tmpfs': h['Tmpfs'], 'mount_destinations': sorted(expected), 'image': c['Image'], 'host_ports': False}


def validate_iac_scope(root,manifest):
    for f in manifest:
        text=(root/f['path']).read_text(encoding='utf-8')
        if re.search(r'(?i)\b(?:trivy|tfsec)\s*:\s*ignore',text):raise ValueError('Inline IaC suppression is outside the fixed review profile')
        if re.search(r'\b(module|provider|terraform)\s*["{]',text):raise ValueError('Modules, providers and Terraform initialization are outside scope')

def run_scanner(tool, input_root, toolchain_root, *, as_of, timeout=120, docker_executable=None):
    observation = normalize(tool, b'null')
    observation.update(exit_code=None, started_at=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), ended_at=None, evidence_level='synthetic', provenance={}, raw_output_sha256=None, stderr_sha256=None)
    docker = None; name = 'sbr-' + uuid.uuid4().hex; created = False
    try:
        if tool not in TOOLS or not isinstance(timeout, (int, float)) or not 0 < timeout <= 120: raise ValueError('Unsupported tool or timeout')
        now = datetime.strptime(as_of, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        root = safe_mount_path(input_root); toolchain = safe_mount_path(toolchain_root)
        manifest = input_manifest(root)
        if not manifest: raise ValueError('Empty input scope')
        if tool == 'trivy':validate_iac_scope(root,manifest)
        lock_bytes = files(__package__).joinpath('data/toolchain-lock.json').read_bytes()
        lock = json.loads(lock_bytes.decode('utf-8-sig'))
        record = next(r for r in lock['review']['tools'] if r['name'] == TOOLS[tool])
        needed = [record['path'], record['license_path']] + [p for p in lock['files'] if p.startswith('configs/')]
        if tool == 'osv-scanner':
            for snapshot in lock['review']['osv_snapshots']:
                updated = datetime.fromisoformat(snapshot['updated'].replace('Z', '+00:00'))
                if now < updated or now >= updated + timedelta(days=7): raise ValueError('Snapshot is stale or from the future')
                needed.append(snapshot['path'])
        hashes = {}
        for relative in needed:
            p = safe_mount_path(toolchain / relative)
            if not p.is_file() or _file_sha(p) != lock['files'][relative]: raise RunnerFailure('Reviewed toolchain hash mismatch or missing artifact')
            hashes[relative] = lock['files'][relative]
        args = scanner_arguments(tool, manifest)
        docker = trusted_runtime(docker_executable)
        mounts = [(root, '/input'), (toolchain / record['path'], '/tool/scanner'), (toolchain / 'configs', '/config')]
        if tool == 'osv-scanner': mounts.append((toolchain / 'osv-db/osv-scanner', '/db/osv-scalibr'))
        observation['provenance'] = {'tool': record, 'toolchain_lock_sha256': _sha(lock_bytes), 'artifact_hashes': hashes, 'input_manifest': manifest, 'input_manifest_sha256': _sha(json.dumps(manifest, sort_keys=True).encode()), 'wrapper_sha256': _sha(WRAPPER.encode()), 'argv': args, 'image': IMAGE, 'as_of': as_of, 'scope': 'Local synthetic fixtures only; no application or tenant-isolation conclusion'}
        with tempfile.TemporaryDirectory(prefix='sb-review-docker-') as config_dir:
            Path(config_dir, 'config.json').write_text('{}', encoding='utf-8')
            endpoint = 'npipe:////./pipe/docker_engine' if os.name == 'nt' else 'unix:///var/run/docker.sock'
            base = [docker, '--config', config_dir, '--host', endpoint]
            env = clean_environment()
            def call(arguments, seconds=15): return bounded_process(base + arguments, timeout=seconds, env=env)
            try:
                # The daemon may create a container even when its client times out.
                created = True
                code, output, _ = call(sandbox_arguments(name, mounts, args))
                if code: raise RunnerFailure('Container creation failed')
                code, inspected, _ = call(['inspect', name])
                if code: raise RunnerFailure('Container inspection failed')
                observation['provenance']['sandbox'] = _inspect(json.loads(inspected)[0], mounts)
                code, raw, stderr = call(['start', '--attach', name], timeout)
                observation.update(exit_code=code, raw_output_sha256=_sha(raw), stderr_sha256=_sha(stderr))
                if b'SB_SANDBOX_VERIFIED ' not in stderr: raise RunnerFailure('Runtime sandbox probes failed')
                match = re.search(rb'SB_VERSION_BEGIN\n(.*?)\nSB_VERSION_END', stderr, re.S)
                if not match or not re.search(rb'(?<![0-9.])' + re.escape(record['version'].encode()) + rb'(?![0-9.])', match[1]): raise RunnerFailure('Actual version does not match pin')
                observation['provenance']['actual_version'] = record['version']
                observation['provenance']['tool_version'] = record['version']
                if tool == 'osv-scanner': verify_offline_receipt(manifest, stderr)
                observation['provenance']['runtime_probes'] = 'uid, zero capabilities, cgroup memory/pids/cpu, read-only mounts, denied external TCP connection verified'
                if input_manifest(root) != manifest: raise RunnerFailure('Input changed during execution')
                result = normalize(tool, raw, executed=True, exit_code=code, target_files=len(manifest))
                observation.update(result)
            finally:
                if created:
                    cleanup_code, _, _ = call(['rm', '--force', '--volumes', name])
                    observation['provenance']['container_removed'] = cleanup_code == 0
                    if cleanup_code: raise RunnerFailure('Owned container cleanup failed')
    except (OSError, ValueError, KeyError, StopIteration, RunnerFailure) as exc:
        observation.update(state='UNKNOWN')
        observation['coverage']['performed'] = False
        # Deliberately omit exception text, command output and secrets.
        observation['errors'] = ['Execution incomplete: ' + (str(exc) if isinstance(exc, (RunnerFailure, ValueError)) else type(exc).__name__)]
    finally:
        observation['ended_at'] = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    return observation
