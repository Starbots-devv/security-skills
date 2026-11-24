# Executed scope

The HTTP fixture exercises cross-tenant and same-tenant cross-user reads/writes, function permissions, fields, bulk/export, forged headers, expired/absent sessions, a legitimate user and unchanged data after denied writes.

The PostgreSQL fixture exercises actual roles, USING and WITH CHECK, forged tenant context and pooled transaction-context reset. A deliberately privileged BYPASSRLS service role demonstrates the administrative bypass and is excluded from tenant assurance. The corrected fixture does not secure superusers or privileged service roles.

Selected references: OWASP ASVS v5.0.0-8.2.1, 8.2.2, 8.2.3, 8.3.1 and 8.4.1, checked against the [tagged authorization chapter](https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x17-V8-Authorization.md). These are references to selected requirements, not ASVS certification. OWASP text is not bundled; its CC-BY-SA-4.0 license is distinct from Starbots code.
