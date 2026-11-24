# Scanner toolchain preparation

The supply-chain checks run pinned Linux builds of Gitleaks, OSV-Scanner and Trivy inside a local container. Their binaries, configs, licenses and OSV advisory snapshots are not part of this repository or the wheel. The package carries only their source URLs, upstream commits and SHA-256 values in `src/starbots_security/data/toolchain-lock.json`. Never commit acquired binaries, archives or snapshot ZIPs.

From the repository root, with the package installed:

```powershell
.venv/Scripts/python.exe tools/acquire_toolchain.py .local-output/toolchain --download
.venv/Scripts/python.exe tools/acquire_toolchain.py .local-output/toolchain
```

The first command explicitly permits HTTPS downloads from the URLs in the lock and verifies every file. The second is offline and only re-verifies the 12 pinned executable, config, license and database files. The helper checks complete archives before extracting two named members, never executes an acquired program, and rejects existing files whose hash differs. If upstream no longer serves a pinned object, preparation fails; do not substitute a different snapshot without updating and reviewing the lock.

## Runtime prerequisites

- Docker Desktop on Windows with the client at `C:/Program Files/Docker/Docker/resources/bin/docker.exe` matching the SHA-256 pinned in `src/starbots_security/runner.py`.
- The image `docker.io/library/alpine@sha256:d56c381f961d307a21b3ca004cf1e3910f106644aefb1f43e654c8a56c4fd395`, pulled by you beforehand. The runner never pulls images.

The runner uses a fixed local engine endpoint and an empty temporary Docker configuration, and returns UNKNOWN when any prerequisite differs. Every scanner invocation uses a fixed argument list, no network, no writable host mount, 1 GiB memory, one CPU, 64 PIDs, a read-only root filesystem, no Linux capabilities, UID/GID 65534 and bounded temporary storage. Before the scanner starts, the container checks its own user, capabilities, limits and that an outbound TCP connection is denied.

## Snapshot validity

The pinned OSV snapshots were taken on 2026-10-18 and are accepted for seven days, until 2026-10-25. A dependency check with a later `--as-of` is rejected as stale. Older evidence stays verifiable as historical synthetic evidence.

OSV-Scanner 2.7.0 reads its offline databases from the `osv-scalibr` cache path, so the runner mounts the verified ecosystem ZIPs read-only at `/db/osv-scalibr` and requires proof that each selected ecosystem database was loaded. The npm fixtures include registry `resolved` metadata so packages are not skipped as local; no registry request is made.

## Integration test

```powershell
$env:STARBOTS_TOOLCHAIN = (Resolve-Path .local-output/toolchain).Path
$env:STARBOTS_SCANNER_EVIDENCE = (Join-Path (Get-Location) '.local-output/scanner-evidence')   # optional
.venv/Scripts/python.exe -m unittest discover -s tests/integration -p test_scanners.py -v
```

The test runs all eight vulnerable and corrected fixture cases, checks the inspected isolation and version receipts, keeps raw-output hashes and checks container cleanup. Missing prerequisites fail the test instead of skipping it. Findings, failed tools and missing coverage stay separate states; a scanner PASS covers only the selected rules, snapshots and files.
