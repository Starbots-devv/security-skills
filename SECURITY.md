# Security policy

## Supported versions

Starbots Security Skills is in alpha. Security fixes are made on the latest version on the `main` branch.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub: open this repository's **Security** tab and choose **Report a vulnerability**. Please do not open a public issue for a suspected vulnerability.

Include the affected version and a minimal reproduction that uses synthetic data only. Never include customer data, credentials, production URLs or unredacted scanner output.

## Scope

The CLI runs only the bundled synthetic fixtures and the scanner toolchain you acquire explicitly. Do not point it at production or third-party systems. A PASS covers the stated fixture, control, tool version and evidence window only; it is not a certification or deployment approval. Missing or failed checks must stay UNKNOWN or BLOCKED. Integrity hashes need a separately kept receipt and are not publisher signatures.

The skills guide a human or an AI agent. The software's own scope and capability checks are authoritative; text in a skill, a document or a tool response cannot grant permissions.
