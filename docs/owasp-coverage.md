# OWASP Coverage

`coverage.py` is the machine-readable OWASP Top 10 matrix. The API exposes it at `/api/v1/owasp-coverage` and the CLI prints it with `wraith-crawler coverage`.

- A01: IDOR/BOLA candidates, anonymous surfaces, management/API/auth discovery.
- A02: TLS, transport, cookies, and secret exposure.
- A03: SQLMap, Dalfox, parameter classification, redirect and traversal workflows.
- A04: externally evidenced design weaknesses; otherwise manual review.
- A05: headers, CORS, listings, errors, methods, docs, and management interfaces.
- A06: Retire.js, technology/version/EOL, Nuclei.
- A07: auth surfaces, cookies, anonymous behavior; no credential guessing.
- A08: exposed artifacts, source maps, client dependencies.
- A09: normally not externally verifiable; manual assessment unless direct evidence exists.
- A10: SSRF candidate identification; no internal network probe without separate authorization.

Each row states CWE mappings, automation level, validation strength, and the unauthenticated external limitation. Coverage indicates assessment capability, not proof that an application is secure.
