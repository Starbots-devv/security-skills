# Skill and host compatibility

The three folders under `skills/` follow the Agent Skills format: a `SKILL.md` with `name` and `description` frontmatter plus relative `references/`. They contain no host-specific tool grants, hooks, MCP server configuration or hidden execution directives. Their commands call the separately installed `sb-security` CLI.

| Host | Project-local folder | `install-skills --host` |
| --- | --- | --- |
| Claude Code | `.claude/skills/` | `claude` |
| Codex | `.agents/skills/` | `codex` |
| Kiro | `.kiro/skills/` | `kiro` |

## What the installer guarantees

- It writes only inside the project root you pass, and refuses a project root that does not exist.
- It refuses to overwrite an existing skill folder or installer manifest.
- It records the SHA-256 of every installed file in `.starbots-security-skills-manifest.json`.
- `uninstall-skills` verifies every installed byte first and refuses to remove edited or added files; review those manually instead of forcing deletion.
- It never changes global agent settings or user-level skill folders.

The test suite installs and removes the packaged skills for all three layouts in a temporary directory whose path contains spaces and non-ASCII characters, checks collision and edit protection, and checks that the packaged skill bytes match `skills/`. A symlink-denial test is skipped on hosts where the current account cannot create symlinks.

## What is not measured

File placement is tested; automatic discovery, activation and routing of the skills by Claude Code, Codex or Kiro are not. The agent boundary skill evaluates a deterministic software dispatcher, not how any language model responds to prompt injection.

Format references: [Claude Code skills](https://code.claude.com/docs/en/skills), [Kiro Agent Skills](https://kiro.dev/docs/skills/) and [OpenAI Codex skills](https://learn.chatgpt.com/docs/build-skills).
