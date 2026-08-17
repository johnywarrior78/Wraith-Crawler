# Reporting Views

Alembic creates a dedicated `reporting` schema with stable views:

- `vw_executive_kpis`
- `vw_assessment_summary`
- `vw_application_risk`
- `vw_findings_current`
- `vw_finding_history`
- `vw_finding_trends_daily`
- `vw_owasp_coverage`
- `vw_technology_inventory`
- `vw_vulnerable_components`
- `vw_plugin_health`
- `vw_attack_paths`
- `vw_attack_path_steps`
- `vw_attack_path_findings`
- `vw_manual_review_queue`
- `vw_scan_history`

The installer grants `wraith_metabase_reader` CONNECT on the Wraith database, USAGE on `reporting`, and SELECT on reporting views only. It has no transactional-schema access, DML, DDL, ownership, or role-management rights.

View definitions live in `persistence/reporting_views.py`, are versioned by Alembic, and are exercised by doctor. Add indexes to underlying tables before introducing materialized views. Any future materialized view must expose its refresh timestamp.
