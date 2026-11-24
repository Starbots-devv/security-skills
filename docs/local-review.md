# Local review: controls and reproduction

A full local review evaluates six mandatory controls defined by the `starbots-local-review` profile (`controls/local-review-policy.json`, pinned by SHA-256 inside the package). Every control must be executed and pass with bound evidence for the review to be READY. Anything missing, failed or stale is UNKNOWN and keeps the review BLOCKED.

| Control | What is executed | Scope |
| --- | --- | --- |
| `SB-AUTH` | 27 HTTP requests per variant | Synthetic loopback API: cross-tenant and cross-user access, roles, fields, sessions, bulk/export and positive controls |
| `SB-RLS` | 21 PostgreSQL assertions per variant | Real PostgreSQL 18.6 roles, `USING` / `WITH CHECK`, forged tenant context, pooled-connection reset; the privileged bypass role is reported as unsafe and excluded |
| `SB-SECRETS` | Gitleaks 8.30.1 | Pinned rules over a synthetic directory; secret values are redacted |
| `SB-DEPENDENCIES` | OSV-Scanner 2.7.0 | Complete pinned npm and PyPI offline snapshots; nothing is resolved or installed; the snapshot expiry caps the assessment expiry |
| `SB-IAC` | Trivy 0.76.0 | Embedded checks over local Terraform only; no provider or module access |
| `SB-AGENT-BOUNDARY` | 14 deterministic dispatcher cases | One permitted read and thirteen denied capability, identity and path requests; no model or MCP transport |

## Prerequisites

- The package installed as described in the [README](../README.md).
- Docker Desktop on Windows. The runner accepts only the Docker client at `C:/Program Files/Docker/Docker/resources/bin/docker.exe` whose SHA-256 matches the pin in `runner.py` and `application.py`. A different client returns UNKNOWN until you review and update that pin.
- The pinned container images, pulled explicitly (the runner never pulls):

```powershell
docker pull docker.io/library/alpine@sha256:d56c381f961d307a21b3ca004cf1e3910f106644aefb1f43e654c8a56c4fd395
docker pull docker.io/library/postgres@sha256:d8703cd7fba306b9fec9268ecedfa8a966846c053036a60e3635791957eb2f66
```

- The scanner toolchain, acquired explicitly (see [tools/TOOLCHAIN.md](../tools/TOOLCHAIN.md)):

```powershell
.venv/Scripts/python.exe tools/acquire_toolchain.py .local-output/toolchain --download
```

## Run a full review

The pinned OSV snapshots are valid from 2026-10-18 to 2026-10-25, so a review that includes `SB-DEPENDENCIES` must use an `--as-of` inside that window. Use a new output directory for every run.

```powershell
.venv/Scripts/python.exe tools/postgres_fixture.py --start-runtime .local-output/pg-runtime.json
.venv/Scripts/sb-security.exe assess-fixture --variant vulnerable --skill all --client-id synthetic-demo --project-id local-review --as-of 2026-10-18T22:00:00Z --toolchain-root .local-output/toolchain --pg-runtime .local-output/pg-runtime.json --output-dir .local-output/vulnerable
.venv/Scripts/sb-security.exe assess-fixture --variant corrected --skill all --client-id synthetic-demo --project-id local-review --as-of 2026-10-18T22:00:00Z --toolchain-root .local-output/toolchain --pg-runtime .local-output/pg-runtime.json --output-dir .local-output/corrected
.venv/Scripts/sb-security.exe verify-assessment --review-dir .local-output/corrected --assessment-sha256 <separately-kept-sha256> --client-id synthetic-demo --project-id local-review --as-of 2026-10-18T22:00:00Z
.venv/Scripts/python.exe tools/postgres_fixture.py --stop-runtime .local-output/pg-runtime.json
```

`postgres_fixture.py` starts one container with no network, no published ports, a read-only root filesystem, a non-root user, all capabilities dropped and an in-memory data directory, and removes only the container it created. Scanner containers run with no network, read-only inputs, UID 65534, zero capabilities and memory, CPU, PID, output and time limits. A failed cleanup can never produce PASS.

To bind a review to another artifact, add `--proposal <path>/subject.json` (for example the `subject.json` of a Starbots Hybrid Infrastructure report). The `--client-id` and `--project-id` must match that subject.

## What a review contains

- `security-assessment.json` — controls, findings, coverage, tool runs and the recomputed readiness.
- `evidence/` and `observations/` — one Evidence document and one raw observation per control.
- `subject.json` / `subject-manifest.json` — the SHA-256 of every file in the review.
- `security-report.md` — a short human summary.
- `inputs/` and `evaluator/` — the fixtures and evaluator sources that were executed.

Keep the assessment SHA-256 printed by `assess-fixture` outside the review directory. `verify-assessment` re-hashes every bound file, re-validates every contract, checks freshness and recomputes readiness from the evidence. Verifying a valid BLOCKED review returns exit code 3.

Exit codes: `0` READY within the fixture scope · `3` valid BLOCKED review · `4` a requested check could not run completely · `2` invalid input, integrity failure or local I/O error. `import-result` only inspects scanner output you supply and can never produce a measured PASS.

## Verify a review from Hybrid Infrastructure

Starbots Hybrid Infrastructure verifies a Security review without importing this package:

```powershell
sb-hybrid verify-security --review-dir <review> --proposal <report>/subject.json --assessment-sha256 <separately-kept-sha256> --client-id <client> --project-id <project> --as-of <UTC>
```

It checks the original proposal bytes, identity, every evidence hash, the pinned control profile, freshness and readiness. Its result always reports `execution_eligible: false`.

## Integration tests

```powershell
$env:STARBOTS_PG_RUNTIME = (Resolve-Path .local-output/pg-runtime.json).Path
$env:STARBOTS_TOOLCHAIN = (Resolve-Path .local-output/toolchain).Path
.venv/Scripts/python.exe -m unittest discover -s tests/integration -p "test_*.py" -v
```

Optionally set `STARBOTS_SCANNER_EVIDENCE` to a directory to keep the normalized scanner observations. Missing prerequisites fail these tests; they are never skipped silently. The scanner test uses a fixed date inside the snapshot window.

## Limits

Only the bundled fixtures and finite probes are measured. A PASS is not a security guarantee, certification, production assessment or approval to deploy. API identities are synthetic tokens, not a JWT or identity-provider audit. PostgreSQL superusers and `BYPASSRLS` roles are not tenant-safe. Dependencies are never installed or executed, so no runtime exploitability or SBOM completeness claim is made. Terraform modules, providers and container image scanning are out of scope. Inline Trivy/tfsec suppression comments are rejected before execution, and suppressed or inconsistent scanner output is UNKNOWN. The agent harness measures software capability checks, not language-model behavior or MCP transports.

Acquired binaries, images and advisory snapshots are not redistributed by this repository. Their hashes and licenses are pinned, but publisher signatures and complete transitive notices have not been verified.
