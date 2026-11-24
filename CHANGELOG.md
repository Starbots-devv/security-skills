# Changelog

## 0.1.0a0 — first public alpha

- Three portable agent skills: Application & API Security Review, Supply Chain & Dependency Security, and AI Agent, Tools & MCP Security.
- `sb-security` CLI with versioned Evidence, SubjectRef and SecurityAssessment contracts and exact-byte verification against a separately kept SHA-256 receipt.
- Synthetic vulnerable and corrected fixtures for HTTP access control, PostgreSQL row-level security, secrets, npm and PyPI dependencies, Terraform misconfiguration and agent tool boundaries.
- Isolated local execution paths for pinned Gitleaks, OSV-Scanner and Trivy, with explicit UNKNOWN states for failed or missing tools.
- Project-local skill installation and guarded removal for Claude Code, Codex and Kiro directory layouts.
