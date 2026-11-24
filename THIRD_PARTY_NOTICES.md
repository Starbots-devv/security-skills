# Third-party notices

Original Starbots code is licensed under Apache-2.0. Dependencies keep their own licenses; no third-party source is relicensed or vendored.

## Python dependencies (installed from PyPI, not bundled)

Exact versions and SHA-256 hashes are in `requirements-runtime.lock` and `requirements-dev.lock`.

| Package | Use | License |
| --- | --- | --- |
| jsonschema, attrs, jsonschema-specifications, referencing, rpds-py | Runtime | MIT |
| typing-extensions | Runtime | PSF-2.0 |
| setuptools, wheel | Build | MIT |
| packaging | Build | Apache-2.0 OR BSD-2-Clause |

The locks target CPython 3.12 on Windows x64 (including a platform-specific rpds-py wheel hash). Other platforms need their own reviewed hashes.

## Optional local scanner toolchain (not bundled)

`tools/acquire_toolchain.py` downloads these only when you pass `--download`. Exact source URLs, upstream commits and hashes are in `src/starbots_security/data/toolchain-lock.json`.

| Tool | Version | License |
| --- | --- | --- |
| Gitleaks (engine and default rules) | 8.30.1 | MIT |
| OSV-Scanner | 2.7.0 | Apache-2.0 |
| Trivy (engine) / embedded trivy-checks | 0.76.0 | Apache-2.0 / MIT |

OSV advisory data has its own licenses, which the engine license does not cover: CC-BY-4.0 (GitHub Security Advisories, PyPA, OSS-Fuzz, EEF), Apache-2.0 (malicious-packages) and CC0-1.0 (GSD). The PostgreSQL and Alpine container images are pulled by digest from Docker Hub by the user and are not redistributed. Publisher signatures and complete transitive notices of these binaries and images have not been verified; do not redistribute them from this repository.

## References

The Application & API skill cites selected OWASP ASVS 5.0.0 requirement IDs. OWASP text is not included; it is licensed separately under CC-BY-SA-4.0.
