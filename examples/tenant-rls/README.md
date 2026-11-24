# Synthetic PostgreSQL RLS fixtures

`application.run_rls_fixture(variant, output_dir, runtime=runtime)` uses actual
PostgreSQL via `docker exec -i ... psql`. A missing runtime returns UNKNOWN with an
explicit prerequisite error. The integration test fails when the runtime is
missing; it never skips or infers a PASS from SQL text.

The operator-reviewed runtime JSON contains `docker_executable`,
`docker_executable_sha256`, an exact hexadecimal `container_id`, and `image_digest` equal to
the immutable Docker image ID (`docker inspect .Image`). The container must have
label `starbots.review.synthetic=true`, network mode `none`, no host port bindings and
no mounts, a read-only filesystem, UID/GID 70, all capabilities dropped,
no-new-privileges, 64 PIDs, 512 MiB memory and one CPU. The executable path/hash
must also match the explicit operator-reviewed identity in `application.py`;
imported runtime observations cannot change that authority. A fresh empty Docker
config and fixed local socket override caller config and inherited Docker context.
Only minimal system environment variables are passed. Combined stdout/stderr is
bounded to 10 MiB, SQL input to 1 MiB, and each command to 60 seconds.
Do not point this adapter at an existing application database.

Set `STARBOTS_PG_RUNTIME` to the runtime JSON path and run from the product
checkout with `PYTHONPATH=src`:

```powershell
.venv/Scripts/python.exe -m unittest discover -s tests/integration -p test_rls.py -v
```

Every run creates a random database and three random NOLOGIN/NOSUPERUSER roles;
tenant A/B have NOBYPASSRLS, the deliberately unsafe service role has BYPASSRLS.
It tests both tenant directions, USING/WITH CHECK, forbidden reads/updates/deletes/
inserts, legitimate writes, forged tenant context, transaction-local reset and
connection reuse in one PostgreSQL backend. The service role bypass is observed
and explicitly marked unsafe; tenant isolation PASS excludes service identities.
Role ownership comments commit with creation; the new database is owned by its
tagged role. Attempted names are reconciled even if creation committed but client
acknowledgement was lost. Cleanup drops only positively tagged random resources
and verifies their absence afterward. Errors always yield UNKNOWN. No other
database or container is stopped or deleted.

Evidence binds exact setup, role and probe SQL bytes, hashes, runtime image ID,
observed role flags, backend PID, SQL results and cleanup state. This is synthetic
evidence, not a production RLS assessment. SQL and JSON fixture resources ship in
the wheel; its integration also exercises actual PostgreSQL when
`STARBOTS_PG_RUNTIME` is supplied.
