# Dashboard Metrics

Dashboard definitions derive metrics from reporting views rather than private tables.

| Metric family | Primary views |
| --- | --- |
| Applications assessed/vulnerable, open and critical risk | `vw_executive_kpis`, `vw_application_risk` |
| Severity, priority, status, confirmed/suspected/manual | `vw_findings_current` |
| New, resolved, reopened, age, trends | `vw_finding_history`, `vw_finding_trends_daily` |
| OWASP/CWE distribution and coverage | `vw_owasp_coverage`, `vw_findings_current` |
| CVSS, EPSS, KEV | `vw_findings_current` |
| EOL and vulnerable components | `vw_vulnerable_components` |
| Plugin state, failure reason, timeout, runtime | `vw_plugin_health` |
| Assessment duration and success rate | `vw_assessment_summary`, `vw_scan_history` |
| Critical paths, path state, steps, break points | `vw_attack_paths`, `vw_attack_path_steps` |
| Manual-review backlog and ownership | `vw_manual_review_queue` |

Counts exclude false positives where the view contract says “current findings.” Suspected/manual-review counts must not be combined with confirmed findings without a visible validation dimension.
