"""Project-local host installation never overwrites or silently removes user data."""
import tempfile
import unittest
from pathlib import Path
import json
from hashlib import sha256

from starbots_security.io import ValidationError


class SkillInstallTests(unittest.TestCase):
    def test_packaged_skill_bytes_match_reviewed_source(self):
        from starbots_security.skill_install import _packaged
        source = Path(__file__).resolve().parents[1] / 'skills'
        for relative, raw in _packaged().items():
            with self.subTest(relative=relative):
                self.assertEqual(raw, (source / relative).read_bytes())

    def test_each_host_installs_and_uninstalls_in_unicode_path(self):
        from starbots_security.skill_install import install_skills, uninstall_skills
        for host, relative in [('codex', '.agents/skills'),
                               ('kiro', '.kiro/skills'),
                               ('claude', '.claude/skills')]:
            with self.subTest(host=host), tempfile.TemporaryDirectory(prefix='Starbots résumé ') as temporary:
                project = Path(temporary) / 'Client project ü'
                project.mkdir()
                result = install_skills(project, host)
                self.assertEqual(result['installed'], 3)
                names = {p.name for p in (project / relative).iterdir() if p.is_dir()}
                self.assertEqual(names, {'review-app-api', 'review-supply-chain',
                                         'review-agent-tools'})
                self.assertTrue((project / relative / '.starbots-security-skills-manifest.json').is_file())
                self.assertEqual(uninstall_skills(project, host)['removed'], 3)
                self.assertFalse(any((project / relative).iterdir()))

    def test_existing_skill_collision_is_preserved(self):
        from starbots_security.skill_install import install_skills
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            existing = project / '.agents/skills/review-app-api/SKILL.md'
            existing.parent.mkdir(parents=True)
            existing.write_text('owned by user', encoding='utf-8')
            with self.assertRaises(ValidationError):
                install_skills(project, 'codex')
            self.assertEqual(existing.read_text(encoding='utf-8'), 'owned by user')
            self.assertFalse((project / '.agents/skills/review-supply-chain').exists())

    def test_edited_skill_blocks_uninstall_without_partial_removal(self):
        from starbots_security.skill_install import install_skills, uninstall_skills
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            install_skills(project, 'claude')
            edited = project / '.claude/skills/review-app-api/SKILL.md'
            edited.write_text(edited.read_text(encoding='utf-8') + '\nuser edit\n', encoding='utf-8')
            with self.assertRaises(ValidationError):
                uninstall_skills(project, 'claude')
            self.assertTrue((project / '.claude/skills/review-agent-tools/SKILL.md').exists())
            self.assertIn('user edit', edited.read_text(encoding='utf-8'))

    def test_edited_skill_and_rewritten_manifest_still_block_uninstall(self):
        from starbots_security.skill_install import install_skills, uninstall_skills
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            install_skills(project, 'codex')
            base = project / '.agents/skills'
            edited = base / 'review-app-api/SKILL.md'
            edited.write_bytes(edited.read_bytes() + b'\nuser edit\n')
            manifest_path = base / '.starbots-security-skills-manifest.json'
            manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
            manifest['files']['review-app-api/SKILL.md'] = sha256(edited.read_bytes()).hexdigest()
            manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
            with self.assertRaises(ValidationError):
                uninstall_skills(project, 'codex')
            self.assertTrue(edited.is_file())

    def test_symlinked_destination_is_denied(self):
        from starbots_security.skill_install import install_skills
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / 'project'
            other = Path(temporary) / 'other'
            project.mkdir(); other.mkdir()
            try:
                (project / '.agents').symlink_to(other, target_is_directory=True)
            except OSError:
                self.skipTest('Host cannot create test symlink')
            with self.assertRaises(ValidationError):
                install_skills(project, 'codex')


if __name__ == '__main__':
    unittest.main()
