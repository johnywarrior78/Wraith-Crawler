# Attack Path Analysis

Attack paths are persisted graphs, not report-time prose. The model follows:

```text
external attacker -> entry point -> vulnerability -> capability gained
  -> realistic next step -> chained weakness -> technical impact -> business impact
```

Nodes and edges store type, evidence reference, source plugin, confidence, confirmed/inferred/speculative classification, rationale, and MITRE ATT&CK technique IDs where a defensible mapping exists. Paths aggregate their edge/finding mappings, while inferred post-exploitation steps carry only the techniques associated with the modeled attacker capability. See [MITRE ATT&CK mapping](mitre-attack.md) for relationship and evidence-boundary rules. The engine implements deterministic chain rules for API documentation/BOLA, source maps/secrets/APIs, directory listing/config/credentials, XSS/cookie controls, SQL injection, and other evidence-backed high-value progressions.

Every path records attack scenario, attacker gain, next step, technical and business impact, blast radius, the exact evidence boundary, and a recommended break point. Persisted post-exploitation steps describe the realistic next attacker action as inferred and technical/business impact as speculative. The engine never dumps data, reuses credentials, persists, pivots, or laterally moves. Downstream effects remain inference unless separately demonstrated.

Scoring is separate from individual finding priority and weighs exposure, validation, prerequisites, capability, chain length, sensitive context, and impact. Labels identify most likely, highest impact, shortest to sensitive impact, confirmed, and potential paths. Stable fingerprints support unchanged/broken path state across assessments.
