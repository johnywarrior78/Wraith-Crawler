# Reporting

Reports are generated only from persisted canonical findings, inventories, plugin state, manual review, metrics, and attack paths.

PDF output includes Executive Summary, Scope, Pentest Methodology and phase progress, Reconnaissance Summary, Technology Inventory and EOL status, Attack Surface, scan-specific OWASP Coverage, evidence, attacker narratives, and qualified MITRE ATT&CK mappings for Findings, Critical Attack Paths, Post-Exploitation Reasoning, recommended break points, remediation, plugin execution, and coverage limitations. ReportLab provides deterministic layout and page numbering.

Excel output includes Executive, Reconnaissance, Technologies, Vulnerable Components, Endpoints, Parameters, Findings, OWASP Coverage, Attack Paths, Attack Steps, Post-Exploitation Steps, Manual Review, Plugin Health, Attack Path Findings, and Metrics. ATT&CK IDs and names appear on findings, paths, and relevant steps. Sheets use filters, frozen headers, tables, semantic number/date formats, bounded widths, wrapping, and priority highlighting. Raw JSON is not dumped into cells.

Generate both formats:

```bash
wraith-crawler report ASSESSMENT_ID --format both --output output
```

Each artifact is hashed and recorded in the `reports` table. Sensitive evidence payloads remain redacted; reports can include safe summaries and fingerprints.
