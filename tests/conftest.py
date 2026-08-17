from __future__ import annotations

from datetime import UTC, datetime

import pytest

from wraith_crawler.config import AppConfig, DatabaseConfig, MetabaseConfig
from wraith_crawler.enums import RoleName
from wraith_crawler.persistence.database import Database
from wraith_crawler.persistence.models import (
    Application,
    Assessment,
    AttackPath,
    AttackPathEdge,
    AttackPathFinding,
    AttackPathNode,
    Endpoint,
    Finding,
    ManualReviewItem,
    PluginExecution,
    ScanMetric,
    Technology,
)
from wraith_crawler.services.auth import AuthService


@pytest.fixture
def config() -> AppConfig:
    return AppConfig(
        environment="test",
        database=DatabaseConfig(url="sqlite+pysqlite:///:memory:"),
        metabase=MetabaseConfig(enabled=False),
        session_cookie_secure=False,
    )


@pytest.fixture
def database(tmp_path) -> Database:
    db = Database(f"sqlite+pysqlite:///{tmp_path / 'test.sqlite3'}")
    db.create_for_tests()
    return db


@pytest.fixture
def admin(database: Database):
    with database.session() as session:
        return AuthService().create_user(
            session, "administrator", "StrongPassword123!", [RoleName.ADMIN]
        )


@pytest.fixture
def populated_assessment(database: Database) -> str:
    now = datetime.now(UTC)
    with database.session() as session:
        app = Application(
            name="Training App",
            seed_url="https://training.example/",
            normalized_origin="https://training.example",
            business_metadata={"criticality": 8},
            scope={},
        )
        session.add(app)
        session.flush()
        assessment = Assessment(
            application_id=app.id,
            status="completed",
            profile="standard",
            started_at=now,
            completed_at=now,
            tool_versions={"nuclei": "3.4.0"},
            configuration_snapshot={},
        )
        session.add(assessment)
        session.flush()
        endpoint = Endpoint(
            assessment_id=assessment.id,
            application_id=app.id,
            url="https://training.example/search?q=test",
            origin="https://training.example",
            path="/search",
            method="GET",
            status_code=200,
            response_metadata={},
            source_plugins=["seed_http"],
            confidence="confirmed",
        )
        session.add(endpoint)
        technology = Technology(
            assessment_id=assessment.id,
            application_id=app.id,
            product="jQuery",
            version="1.8.0",
            category="javascript_library",
            confidence="high",
            evidence=["Retire.js match"],
            source_plugin="retirejs",
            eol_state="eol",
            vulnerability_references=["CVE-2012-6708"],
        )
        session.add(technology)
        finding = Finding(
            assessment_id=assessment.id,
            application_id=app.id,
            fingerprint="a" * 64,
            finding_type="sql_injection",
            family="injection",
            title="SQL injection in search",
            description="Bounded validation found an injectable query parameter.",
            asset="https://training.example",
            affected_endpoints=[endpoint.url],
            method="GET",
            parameters=["q"],
            severity="critical",
            confidence="confirmed",
            validation_status="confirmed",
            source_plugins=["sqlmap"],
            cwe=["CWE-89"],
            cve=[],
            owasp=["A03:2021"],
            capec=["CAPEC-66"],
            mitre_attack=[],
            cvss=9.8,
            epss=0.9,
            kev=False,
            remediation="Use parameterized queries.",
            references=[],
            status="new",
            manual_review=False,
            false_positive=False,
            priority_score=96.0,
            priority_level="critical",
            priority_rationale={"confirmed": 10, "external_exposure": 5},
            attack_path_participation=True,
            metadata_json={"sensitive_context": True},
        )
        session.add(finding)
        session.flush()
        path = AttackPath(
            assessment_id=assessment.id,
            application_id=app.id,
            fingerprint="b" * 64,
            title="SQL injection to sensitive data impact",
            summary="A confirmed injection could expose application data.",
            confidence="confirmed",
            classification="confirmed",
            score=95,
            priority="critical",
            status="new",
            attack_scenario="External attacker -> search -> SQL injection",
            attacker_gain="Database query manipulation",
            next_step="Model data access without dumping data",
            technical_impact="Sensitive data disclosure",
            business_impact="Regulatory and customer harm",
            blast_radius="Training application database",
            evidence_boundary="Injection is confirmed; data access is modeled.",
            recommended_break_point="Use parameterized queries.",
        )
        session.add(path)
        session.flush()
        n1 = AttackPathNode(
            attack_path_id=path.id,
            node_key="attacker",
            node_type="attacker",
            label="External attacker",
            confidence="confirmed",
            classification="confirmed",
            metadata_json={},
        )
        n2 = AttackPathNode(
            attack_path_id=path.id,
            node_key="finding",
            node_type="vulnerability",
            label=finding.title,
            confidence="confirmed",
            classification="confirmed",
            evidence_reference=finding.id,
            metadata_json={},
        )
        session.add_all([n1, n2])
        session.flush()
        session.add(
            AttackPathEdge(
                attack_path_id=path.id,
                source_node_id=n1.id,
                destination_node_id=n2.id,
                relationship="exploits",
                evidence_reference=finding.id,
                source_plugin="sqlmap",
                confidence="confirmed",
                classification="confirmed",
                rationale="SQLMap validation",
                mitre_attack=[],
            )
        )
        session.add(AttackPathFinding(attack_path_id=path.id, finding_id=finding.id, role="chain_step"))
        session.add(
            PluginExecution(
                assessment_id=assessment.id,
                plugin_name="sqlmap",
                state="completed",
                started_at=now,
                completed_at=now,
                duration_ms=1234,
                metrics={"candidates": 1},
            )
        )
        session.add(
            ManualReviewItem(
                assessment_id=assessment.id,
                application_id=app.id,
                endpoint=endpoint.url,
                parameter="id",
                candidate_type="idor_bola",
                reason="Requires multi-user authorization context",
                evidence_summary="Identifier parameter observed",
                source_plugin="parameter_analysis",
                confidence="low",
                priority="medium",
                suggested_steps=["Use approved test identities"],
                attack_path_relevance="Could expose other users' records",
            )
        )
        session.add(
            ScanMetric(
                assessment_id=assessment.id,
                metric_name="findings_total",
                metric_value=1,
                dimensions={},
            )
        )
        return assessment.id
