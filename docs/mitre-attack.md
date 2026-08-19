# MITRE ATT&CK Mapping

Wraith Crawler maps canonical findings, attack-path edges, aggregate attack paths, and inferred post-exploitation steps to selected MITRE ATT&CK Enterprise techniques. The authenticated API exposes the referenced catalog at `/api/v1/mitre-attack`.

Mappings are evidence-bounded. A vulnerability is normally an `observed_precondition` or `candidate_for` an ATT&CK technique; it is not proof that an adversary performed that behavior. Downstream path steps remain `inferred`, and impact remains `speculative`. Each finding mapping records the technique ID/name, tactics, relationship, confidence, classification, rationale, official MITRE URL, and catalog version in canonical finding metadata.

Migration `0004` adds deterministic technique IDs to historical findings and paths. The richer relationship and rationale metadata is generated for new or rescanned findings, where current validation context is available.

The deterministic mappings include:

- T1190 for exploitable or candidate public-facing application weaknesses, including SQL injection, SSRF, and authorization bypass;
- T1189 for confirmed or candidate XSS/browser compromise paths;
- T1552.001 and T1552.004 for credentials in files and private keys;
- T1528 for exposed application/API access tokens;
- T1539 and T1550.004 for session-cookie theft and reuse opportunities;
- T1133 for exposed external management or debug service boundaries;
- T1590.004 for publicly disclosed backend topology;
- T1592.002 for externally disclosed software, schema, runtime, and version information;
- T1566.002 and T1204.001 for open-redirect-enabled malicious-link scenarios;
- T1046, T1005, and T1213.006 only where an observed exposure or modeled capability supports discovery or collection.

Unknown findings are not assigned a generic technique merely to increase coverage. Nuclei findings map to T1190 only when they carry a CVE, and exact downstream collection or credential-use techniques remain modeled rather than confirmed.

Technique names, tactics, and URLs are pinned to the official [MITRE ATT&CK Enterprise v19.1 catalog](https://attack.mitre.org/resources/updates/). Review mappings when upgrading the embedded catalog version.
