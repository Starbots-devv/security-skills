# Synthetic HTTP access-control fixtures

`application.run_api_fixture(variant, output_dir)` starts an ephemeral stdlib HTTP
server on `127.0.0.1`, sends actual HTTP requests, closes the server and saves
`api-observation.json`. Run from this source checkout with `PYTHONPATH=src` and the
product `.venv` Python. Resources also ship inside the wheel and installed
packages resolve them with `importlib.resources`; a checkout is not required.
Accepted variants: `vulnerable`, `corrected`.

The 27 requests cover A/B object reads and writes, another user in the same
tenant, post-denial mutation checks, function roles, sensitive fields, bulk and
export, forged tenant headers, absent/expired sessions and legitimate operations.
Tokens and rows are fixed fictional data. The vulnerable fixture deliberately
omits controls; the corrected fixture applies them to these routes only.

The observation contains the fixture and implementation SHA-256, request/response
details, expected outcomes and coverage limits. A corrected PASS is limited to
these requests; there is no real identity provider, JWT parser or deployment.
