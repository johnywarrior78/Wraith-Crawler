# OWASP Coverage

`coverage.py` defines the machine-readable OWASP Top 10 capability matrix. The API exposes the general matrix at `/api/v1/owasp-coverage`, the CLI prints it with `wraith-crawler coverage`, and `/api/v1/assessments/{id}/owasp-coverage` returns the persisted scan-specific result.

- A01: IDOR/BOLA candidates, anonymous surfaces, management/API/auth discovery.
- A02: TLS, transport, session-cookie controls, and secret exposure.
- A03: SQLMap, Dalfox, parameter classification, redirect and traversal workflows.
- A04: externally evidenced design weaknesses; otherwise manual review.
- A05: headers, CORS, bounded directory-listing checks, errors, methods, docs, and management interfaces.
- A06: Retire.js, passive CMS and technology/version/EOL detection, Nuclei.
- A07: auth surfaces, session-cookie discovery and controls, anonymous behavior; no credential guessing.
- A08: exposed artifacts, source maps, client dependencies.
- A09: normally not externally verifiable; manual assessment unless direct evidence exists.
- A10: SSRF candidate identification; no internal network probe without separate authorization.

Each assessment row records the plugins actually selected, tests attempted and completed, findings, execution-derived status, limitations, and manual-review needs. A blocked, missing, failed, or timed-out plugin therefore cannot silently appear as complete. Coverage indicates assessment capability, not proof that an application is secure.
