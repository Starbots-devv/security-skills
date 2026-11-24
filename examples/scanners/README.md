# Synthetic scanner fixtures

The vulnerable and corrected trees are inert synthetic test inputs. The fake
credential cannot authenticate. Dependency files are metadata only; no lodash or
requests release is installed. The Terraform HCL is scanned as text and is never
initialized, planned, applied or connected to a provider.

The paired changes are fake token removal, lodash 4.17.20 → 4.18.0, requests
2.30.0 → 2.33.0, and unrestricted SSH ingress → private CIDR ingress. Corrected
versions match the pinned 2026-10-18 OSV data, rather than an older remembered
fixed version. Run the same reviewed scanner profile against each pair.

Canonical copies are packaged under `starbots_security/data/scanners/` so installed
wheel demonstrations use the same bytes. See `tools/TOOLCHAIN.md` for preparation,
explicit runtime prerequisites, limits and remaining supply-chain/license gates.
