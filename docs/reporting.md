# Reporting

Reports are generated only from persisted canonical findings, inventories, plugin state, manual review, metrics, and attack paths.

PDF output includes a cover, metadata, executive risk summary, OWASP coverage, critical attack paths and evidence boundaries, detailed findings/evidence/remediation/mappings, technologies, plugin health, methodology, and limitations. ReportLab provides deterministic layout and page numbering.

Excel output includes Executive Summary, Findings, Affected Endpoints, OWASP Coverage, Technologies, Vulnerable Components, Plugin Execution, Manual Review, Attack Paths, Attack Steps, Attack Path Findings, and Assessment Metrics. Sheets use filters, frozen headers, tables, semantic number/date formats, bounded widths, wrapping, and priority highlighting. Raw JSON is not dumped into cells.

Generate both formats:

```bash
wraith-crawler report ASSESSMENT_ID --format both --output output
```

Each artifact is hashed and recorded in the `reports` table. Sensitive evidence payloads remain redacted; reports can include safe summaries and fingerprints.
