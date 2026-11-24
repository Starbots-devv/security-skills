# Reviewed execution scope

Gitleaks 8.30.1: tagged MIT rules/config, full redaction, local directory mode, no repository ignore annotations. OSV-Scanner 2.7.0: Apache-2.0 engine, complete pinned npm/PyPI ecosystem snapshots, offline and no resolution. Trivy 0.76.0: Apache-2.0 engine, embedded MIT checks; misconfiguration only, no database/check updates or telemetry. Data licenses remain separate.

All binaries run in a digest-pinned local Linux container with network none, read-only inputs, no socket or credentials, nonroot UID, dropped capabilities and process/memory/CPU/output/deadline limits. Acquisition is explicit and verified before execution. Publisher signature authentication and complete transitive notices remain pending; acquired third-party binaries/data are not redistributed.

The fixtures compare lodash 4.17.20 with 4.18.0 and requests 2.30.0 with 2.33.0 against the recorded 2026-10-18 snapshots. Those versions are synthetic review inputs, not a permanent recommendation or assertion that any entire application is safe. Dependencies are not installed. IaC includes local resources only; modules, remote providers and production configurations are outside this gate.
