# Contributing

Thanks for your interest. Issues and pull requests are welcome.

- Work in an isolated Python 3.12 environment installed from the hash-locked requirement files.
- Use synthetic data only. Keep acquired scanner binaries, container images, advisory snapshots, generated reviews, virtual environments and credentials out of Git.
- Add a failing test for a behavior change, then make it pass. Run `python -m unittest discover -s tests -p "test_*.py" -v` before opening a pull request, and the integration suite when your change touches the runners.
- Keep the versioned contracts stable. A change to a contract, control profile or pinned file must update its pins and tests in the same change.
- Keep `skills/` and `src/starbots_security/data/skills/` byte-identical; the test suite checks this.
- Report security issues through [SECURITY.md](SECURITY.md), not in public issues.

By contributing you agree that your contribution is licensed under the Apache License 2.0.
