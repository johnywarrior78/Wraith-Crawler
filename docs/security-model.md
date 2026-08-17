# Security and Scope Model

Wraith Crawler is for explicit operator-authorized targets. The seed host is in scope; subdomains, third-party hosts, additional ports, and excluded paths are not implicitly authorized. All discovered URLs pass through `ScopeManager` before inventory or active work.

Default behavior prohibits denial-of-service payloads, uncontrolled wordlists, destructive writes, brute force, credential stuffing, database dumping, persistence, lateral movement, and automatic credential use. SSRF handling classifies candidates and never probes loopback, private, link-local, multicast, or reserved address space without a separate authorization workflow.

Secrets use redacted fingerprints and are never validated against unrelated or third-party services. HTTP snapshots are bounded in size. External tools run without a shell, with explicit arguments, rate, concurrency, timeout, retry, depth, and candidate limits.

Application passwords use Argon2id. Sessions use random opaque tokens stored only as SHA-256 digests, expire, support logout/revocation, and use Secure/HttpOnly/SameSite cookies. Cookie-authenticated mutations require a CSRF token. Failed logins trigger a temporary lock. Admin, analyst, and viewer roles enforce API actions.

Structured logs redact password, authorization, cookie, token, secret, and API-key fields. Runtime database and Metabase secrets are outside source control with restrictive filesystem permissions.

Scanner cookie evidence records names and security attributes only. Cookie values are retained solely in the ephemeral in-memory response snapshot needed by the active scan and are redacted before response headers or observations are persisted.
