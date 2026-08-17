# Plugins

Plugins declare required/produced data capabilities, profiles, external-tool identity, OWASP/CWE mappings, automation level, and validation strength. States are `completed`, `partial`, `failed`, `timed_out`, `not_applicable`, and `blocked`; failures use the structured reason taxonomy in `enums.py`.

Built-in capabilities include seed HTTP validation, TLS, HTML/endpoint/forms/JavaScript discovery, JavaScript retrieval and deterministic reference extraction, security headers, cookies, CORS behavior, HTTP methods, technology/CMS fingerprints, directory/error/API/debug exposure, robots/sitemaps, curated sensitive files, source maps, known-format secrets, parameter risk queues, GraphQL introspection, WebSocket discovery, open-redirect validation, and safe traversal/IDOR/BOLA/SSRF manual-review candidates.

External adapters include:

| Plugin | Safety and input contract |
| --- | --- |
| ProjectDiscovery HTTPX | Resolves and identifies the ProjectDiscovery binary; always accepts the seed URL. |
| Katana | Bounded depth, concurrency, rate, timeout; never gates unrelated plugins. |
| Nuclei | Origin-deduplicated automatic mode; excludes DoS, fuzz, brute-force, intrusive, and destructive tags. |
| Nikto | Stable types map to canonical taxonomy; unknown observations enter manual review. |
| Retire.js | Runs only on safely downloaded in-scope JavaScript. |
| Dalfox | Receives prepared XSS parameter candidates only. |
| SQLMap | Level 1/risk 1/single-thread validation; no dumping or destructive actions. |

Valid JSONL preceding a timeout or malformed line is retained as trustworthy partial output. Missing optional binaries disable only their plugin. Tool path/version is stored with each execution and assessment.

To add a plugin, subclass `AssessmentPlugin`, define a unique name and capability contract, return `PluginResult`, register it, add parser fixtures and failure-isolation tests, and document evidence/validation limitations.
