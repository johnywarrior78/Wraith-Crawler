from __future__ import annotations

from sqlalchemy import Connection, text

REPORTING_SCHEMA = "reporting"

VIEW_DEFINITIONS: dict[str, str] = {
    "vw_executive_kpis": """
        SELECT a.id AS assessment_id, a.application_id, a.status AS assessment_status,
               COUNT(DISTINCT f.id) AS findings_total,
               COUNT(DISTINCT f.id) FILTER (WHERE f.status IN ('new','open','reopened','recurring')) AS findings_open,
               COUNT(DISTINCT f.id) FILTER (WHERE f.priority_level = 'critical') AS critical_findings,
               COUNT(DISTINCT ap.id) FILTER (WHERE ap.priority = 'critical') AS critical_attack_paths,
               COUNT(DISTINCT m.id) FILTER (WHERE m.status = 'open') AS manual_review_backlog
        FROM assessments a
        LEFT JOIN findings f ON f.assessment_id = a.id AND f.false_positive = FALSE
        LEFT JOIN attack_paths ap ON ap.assessment_id = a.id
        LEFT JOIN manual_review_items m ON m.assessment_id = a.id
        GROUP BY a.id, a.application_id, a.status
    """,
    "vw_assessment_summary": """
        SELECT a.id AS assessment_id, a.application_id, app.name AS application_name,
               app.seed_url, a.status, a.profile, a.started_at, a.completed_at,
               EXTRACT(EPOCH FROM (a.completed_at - a.started_at)) AS duration_seconds,
               COUNT(DISTINCT f.id) AS finding_count,
               COUNT(DISTINCT p.id) AS plugin_count
        FROM assessments a
        JOIN applications app ON app.id = a.application_id
        LEFT JOIN findings f ON f.assessment_id = a.id
        LEFT JOIN plugin_executions p ON p.assessment_id = a.id
        GROUP BY a.id, a.application_id, app.name, app.seed_url, a.status, a.profile,
                 a.started_at, a.completed_at
    """,
    "vw_application_risk": """
        SELECT app.id AS application_id, app.name, app.normalized_origin,
               MAX(a.completed_at) AS last_assessed_at,
               COALESCE(MAX(f.priority_score), 0) AS maximum_priority_score,
               COUNT(DISTINCT f.id) FILTER (WHERE f.status IN ('new','open','reopened','recurring')) AS open_findings,
               COUNT(DISTINCT ap.id) FILTER (WHERE ap.status NOT IN ('broken','resolved')) AS active_attack_paths
        FROM applications app
        LEFT JOIN assessments a ON a.application_id = app.id
        LEFT JOIN findings f ON f.application_id = app.id
        LEFT JOIN attack_paths ap ON ap.application_id = app.id
        GROUP BY app.id, app.name, app.normalized_origin
    """,
    "vw_findings_current": """
        SELECT f.id AS finding_id, f.assessment_id, f.application_id, f.fingerprint,
               f.finding_type, f.family, f.title, f.asset, f.severity, f.confidence,
               f.validation_status, f.status, f.priority_score, f.priority_level,
               f.cvss, f.epss, f.kev, f.owasp, f.cwe, f.cve, f.first_seen, f.last_seen,
               f.manual_review, f.attack_path_participation
        FROM findings f
        WHERE f.false_positive = FALSE
    """,
    "vw_finding_history": """
        SELECT h.id, h.finding_id, h.application_id, h.assessment_id,
               h.previous_status, h.status, h.changed_at, h.rationale,
               f.finding_type, f.title, f.severity, f.priority_level
        FROM finding_history h
        JOIN findings f ON f.id = h.finding_id
    """,
    "vw_finding_trends_daily": """
        SELECT date_trunc('day', h.changed_at)::date AS day, h.application_id, h.status,
               COUNT(*) AS finding_events
        FROM finding_history h
        GROUP BY date_trunc('day', h.changed_at)::date, h.application_id, h.status
    """,
    "vw_owasp_coverage": """
        SELECT f.assessment_id, f.application_id, owasp_category,
               COUNT(DISTINCT f.id) AS findings,
               COUNT(DISTINCT f.id) FILTER (WHERE f.validation_status = 'confirmed') AS confirmed_findings
        FROM findings f
        CROSS JOIN LATERAL jsonb_array_elements_text(f.owasp::jsonb) AS owasp_category
        WHERE f.false_positive = FALSE
        GROUP BY f.assessment_id, f.application_id, owasp_category
    """,
    "vw_technology_inventory": """
        SELECT t.id AS technology_id, t.assessment_id, t.application_id, t.product,
               t.version, t.category, t.confidence, t.source_plugin, t.eol_state,
               t.first_seen, t.last_seen
        FROM technologies t
    """,
    "vw_vulnerable_components": """
        SELECT t.id AS technology_id, t.assessment_id, t.application_id, t.product,
               t.version, t.category, t.eol_state, t.vulnerability_references,
               jsonb_array_length(t.vulnerability_references::jsonb) AS vulnerability_count
        FROM technologies t
        WHERE t.eol_state IS NOT NULL OR jsonb_array_length(t.vulnerability_references::jsonb) > 0
    """,
    "vw_plugin_health": """
        SELECT p.id AS plugin_execution_id, p.assessment_id, p.plugin_name, p.state,
               p.failure_reason, p.started_at, p.completed_at, p.duration_ms,
               p.tool_path, p.tool_version
        FROM plugin_executions p
    """,
    "vw_attack_paths": """
        SELECT ap.id AS attack_path_id, ap.assessment_id, ap.application_id, ap.title,
               ap.confidence, ap.classification, ap.score, ap.priority, ap.status,
               ap.attacker_gain, ap.technical_impact, ap.business_impact,
               ap.blast_radius, ap.recommended_break_point, ap.first_seen, ap.last_seen
               , ap.critical_path_labels
        FROM attack_paths ap
    """,
    "vw_attack_path_steps": """
        SELECT e.attack_path_id, e.id AS edge_id, s.node_type AS source_type,
               s.label AS source_label, e.relationship, d.node_type AS destination_type,
               d.label AS destination_label, e.confidence, e.classification, e.rationale
        FROM attack_path_edges e
        JOIN attack_path_nodes s ON s.id = e.source_node_id
        JOIN attack_path_nodes d ON d.id = e.destination_node_id
    """,
    "vw_attack_path_findings": """
        SELECT apf.attack_path_id, apf.finding_id, apf.role, f.application_id,
               f.finding_type, f.title, f.severity, f.priority_level, f.validation_status
        FROM attack_path_findings apf
        JOIN findings f ON f.id = apf.finding_id
    """,
    "vw_manual_review_queue": """
        SELECT m.id AS review_id, m.assessment_id, m.application_id, m.finding_id,
               m.endpoint, m.parameter, m.candidate_type, m.reason, m.source_plugin,
               m.confidence, m.priority, m.attack_path_relevance, m.status,
               m.assigned_to_id, m.created_at, m.updated_at
        FROM manual_review_items m
    """,
    "vw_scan_history": """
        SELECT a.id AS assessment_id, a.application_id, app.name AS application_name,
               a.status, a.profile, a.started_at, a.completed_at,
               COUNT(DISTINCT f.id) AS findings,
               COUNT(DISTINCT p.id) FILTER (WHERE p.state = 'completed') AS plugins_completed,
               COUNT(DISTINCT p.id) FILTER (WHERE p.state IN ('failed','timed_out')) AS plugins_failed
        FROM assessments a
        JOIN applications app ON app.id = a.application_id
        LEFT JOIN findings f ON f.assessment_id = a.id
        LEFT JOIN plugin_executions p ON p.assessment_id = a.id
        GROUP BY a.id, a.application_id, app.name, a.status, a.profile, a.started_at, a.completed_at
    """,
}


def create_reporting_views(connection: Connection) -> None:
    if connection.dialect.name != "postgresql":
        return
    connection.execute(text(f"CREATE SCHEMA IF NOT EXISTS {REPORTING_SCHEMA}"))
    for name, query in VIEW_DEFINITIONS.items():
        connection.execute(text(f"CREATE OR REPLACE VIEW {REPORTING_SCHEMA}.{name} AS {query}"))


def drop_reporting_views(connection: Connection) -> None:
    if connection.dialect.name != "postgresql":
        return
    for name in reversed(VIEW_DEFINITIONS):
        connection.execute(text(f"DROP VIEW IF EXISTS {REPORTING_SCHEMA}.{name}"))


def verify_reporting_views(connection: Connection) -> dict[str, bool]:
    if connection.dialect.name != "postgresql":
        return {name: False for name in VIEW_DEFINITIONS}
    results: dict[str, bool] = {}
    for name in VIEW_DEFINITIONS:
        try:
            # Schema and view names come exclusively from module constants above.
            connection.execute(
                text(f"SELECT 1 FROM {REPORTING_SCHEMA}.{name} LIMIT 1")  # noqa: S608
            )
            results[name] = True
        except Exception:
            results[name] = False
    return results
