"""Install packaged skills only inside an explicitly selected local project."""
from hashlib import sha256
from importlib.resources import files
import json
import os
from pathlib import Path
import shutil
import tempfile

from .io import fail

HOST_PATHS = {'codex': ('.agents', 'skills'),
              'kiro': ('.kiro', 'skills'),
              'claude': ('.claude', 'skills')}
SKILL_NAMES = ('review-app-api', 'review-supply-chain', 'review-agent-tools')
MANIFEST = '.starbots-security-skills-manifest.json'


def _root(project_root, host):
    if host not in HOST_PATHS:
        fail('INVALID_SCHEMA', 'Expected codex, kiro or claude host')
    root = Path(project_root).absolute()
    if not root.is_dir():
        fail('PATH_DENIED', 'An existing project directory is required')
    target = root.joinpath(*HOST_PATHS[host])
    for path in (root, *root.parents, root / HOST_PATHS[host][0], target):
        if path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction()):
            fail('PATH_DENIED', 'Project skill path traverses a link or junction')
    return target


def _packaged():
    source = files('starbots_security').joinpath('data', 'skills')
    contents = {}
    for name in SKILL_NAMES:
        skill = source.joinpath(name)
        if not skill.is_dir():
            fail('INVALID_SCHEMA', 'A packaged skill is missing')
        for entry in skill.iterdir():
            if entry.is_file():
                contents[name + '/' + entry.name] = entry.read_bytes()
            elif entry.is_dir() and entry.name == 'references':
                for reference in entry.iterdir():
                    if not reference.is_file():
                        fail('INVALID_SCHEMA', 'Unsupported packaged skill resource')
                    contents[name + '/references/' + reference.name] = reference.read_bytes()
            else:
                fail('INVALID_SCHEMA', 'Unsupported packaged skill resource')
        if name + '/SKILL.md' not in contents:
            fail('INVALID_SCHEMA', 'A packaged skill has no SKILL.md')
    return contents


def install_skills(project_root, host):
    """Copy three reviewed skill folders; any collision aborts before writing."""
    target = _root(project_root, host)
    contents = _packaged()
    if (target / MANIFEST).exists() or any((target / name).exists() for name in SKILL_NAMES):
        fail('PATH_DENIED', 'A Starbots manifest or skill destination already exists')
    target.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.starbots-stage-', dir=target) as temporary:
        stage = Path(temporary)
        for relative, raw in contents.items():
            destination = stage / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
        moved = []
        try:
            for name in SKILL_NAMES:
                if (target / name).exists():
                    fail('PATH_DENIED', 'A skill destination appeared during installation')
                os.rename(stage / name, target / name)
                moved.append(name)
            manifest = {'format': 'starbots-skill-install-1', 'host': host,
                        'files': {path: sha256(raw).hexdigest() for path, raw in sorted(contents.items())}}
            with (target / MANIFEST).open('x', encoding='utf-8') as stream:
                json.dump(manifest, stream, sort_keys=True, indent=2)
                stream.write('\n')
        except Exception:
            for name in moved:
                shutil.rmtree(target / name)
            (target / MANIFEST).unlink(missing_ok=True)
            raise
    return {'host': host, 'installed': len(SKILL_NAMES), 'project_root': str(Path(project_root).absolute())}


def uninstall_skills(project_root, host):
    """Remove only an intact installation matching this package's named files."""
    target = _root(project_root, host)
    manifest_path = target / MANIFEST
    if manifest_path.is_symlink() or not manifest_path.is_file():
        fail('PATH_DENIED', 'No intact Starbots installation manifest exists')
    try:
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    except (UnicodeError, ValueError):
        fail('INVALID_SCHEMA', 'Invalid installation manifest')
    expected = {path: sha256(raw).hexdigest() for path, raw in _packaged().items()}
    if (not isinstance(manifest, dict) or set(manifest) != {'format', 'host', 'files'}
            or manifest['format'] != 'starbots-skill-install-1' or manifest['host'] != host
            or not isinstance(manifest['files'], dict) or manifest['files'] != expected):
        fail('INVALID_SCHEMA', 'Installation manifest does not match packaged skill paths')
    for name in SKILL_NAMES:
        folder = target / name
        if folder.is_symlink() or not folder.is_dir():
            fail('PATH_DENIED', 'Installed skill folder changed')
        actual = {p.relative_to(target).as_posix() for p in folder.rglob('*') if p.is_file()}
        named = {path for path in expected if path.startswith(name + '/')}
        if actual != named or any(p.is_symlink() or (hasattr(p, 'is_junction') and p.is_junction()) for p in folder.rglob('*')):
            fail('PATH_DENIED', 'Installed skill files or links changed')
    for relative in expected:
        if sha256((target / relative).read_bytes()).hexdigest() != manifest['files'][relative]:
            fail('HASH_MISMATCH', 'An installed skill was edited; preserve it for manual review')
    for name in SKILL_NAMES:
        shutil.rmtree(target / name)
    manifest_path.unlink()
    return {'host': host, 'removed': len(SKILL_NAMES), 'project_root': str(Path(project_root).absolute())}
