---
name: review-supply-chain
description: Review secrets, Python and npm dependencies and local Terraform misconfiguration with pinned Starbots Gitleaks, OSV-Scanner and Trivy adapters. Use for a bounded supply-chain security evaluation with tool provenance.
---

# Starbots Supply Chain & Dependency Security

Use `sb-security assess-fixture --skill supply-chain --variant vulnerable --toolchain-root <reviewed-tool-cache> --client-id synthetic --project-id supply-chain --as-of <UTC> --output-dir <fresh-directory>` and repeat with `--variant corrected`. UTC uses `YYYY-MM-DDTHH:MM:SSZ`. This command scans packaged synthetic files only; it does not install vulnerable dependencies, initialize Terraform or access a provider. The tool cache is prepared separately with `python tools/acquire_toolchain.py <directory> --download` from a checkout of the repository. The pinned advisory snapshots are valid from 2026-10-18 to 2026-10-25; use an `--as-of` inside that window or expect the dependency check to be rejected as stale.

Read [references/tools.md](references/tools.md) when checking prerequisites and interpreting scope. The package pins reviewed binaries, configs and advisory snapshots. Missing or stale data, missing isolation, version/hash mismatch, timeout or incomplete coverage must produce UNKNOWN. Do not download a replacement or change a pin merely to make a check pass.

Report rule/advisory IDs, severity provenance, redacted evidence and performed/missing coverage. Do not reproduce secret values. `sb-security import-result --tool <gitleaks|osv-scanner|trivy> --input <json>` only inspects untrusted output; an imported empty report cannot demonstrate PASS.

Keep the printed assessment SHA-256 separately. A partial supply-chain run leaves overall readiness BLOCKED. No findings means no findings within the specified rules, snapshots and files; it is not a guarantee of security. No output approves deployments, shell commands from a report or paid acquisition.

Verify the receipt with `sb-security verify-assessment --review-dir <directory> --assessment-sha256 <receipt> --client-id synthetic --project-id <same-project> --as-of <UTC>`.
