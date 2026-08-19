"""Add MITRE ATT&CK mappings to paths and post-exploitation reasoning.

Revision ID: 0004
Revises: 0003
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from wraith_crawler.mitre import (
    technique_ids_for_capability,
    technique_ids_for_finding_type,
)
from wraith_crawler.persistence.models import JSON_VALUE
from wraith_crawler.persistence.reporting_views import (
    create_reporting_views,
    drop_reporting_views,
)

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def _add_column(table: str, column: sa.Column[object]) -> None:
    bind = op.get_bind()
    existing = {item["name"] for item in sa.inspect(bind).get_columns(table)}
    if column.name not in existing:
        op.add_column(table, column)


def _merge_ids(existing: object, additions: tuple[str, ...] | list[str]) -> list[str]:
    current = existing if isinstance(existing, list) else []
    return sorted({str(item) for item in [*current, *additions] if item})


def _backfill_mappings(bind: sa.Connection) -> None:
    findings = sa.table(
        "findings",
        sa.column("id", sa.String()),
        sa.column("finding_type", sa.String()),
        sa.column("mitre_attack", JSON_VALUE),
    )
    attack_paths = sa.table(
        "attack_paths",
        sa.column("id", sa.String()),
        sa.column("mitre_attack", JSON_VALUE),
    )
    path_findings = sa.table(
        "attack_path_findings",
        sa.column("attack_path_id", sa.String()),
        sa.column("finding_id", sa.String()),
    )
    post_steps = sa.table(
        "post_exploitation_steps",
        sa.column("id", sa.String()),
        sa.column("capability", sa.String()),
        sa.column("classification", sa.String()),
        sa.column("mitre_attack", JSON_VALUE),
    )

    finding_techniques: dict[str, list[str]] = {}
    for row in bind.execute(
        sa.select(findings.c.id, findings.c.finding_type, findings.c.mitre_attack)
    ).mappings():
        mappings = _merge_ids(
            row["mitre_attack"], technique_ids_for_finding_type(str(row["finding_type"]))
        )
        finding_techniques[str(row["id"])] = mappings
        if mappings != (row["mitre_attack"] or []):
            bind.execute(
                sa.update(findings)
                .where(findings.c.id == row["id"])
                .values(mitre_attack=mappings)
            )

    techniques_by_path: dict[str, set[str]] = {}
    for row in bind.execute(
        sa.select(path_findings.c.attack_path_id, path_findings.c.finding_id)
    ).mappings():
        techniques_by_path.setdefault(str(row["attack_path_id"]), set()).update(
            finding_techniques.get(str(row["finding_id"]), [])
        )
    for row in bind.execute(
        sa.select(attack_paths.c.id, attack_paths.c.mitre_attack)
    ).mappings():
        mappings = _merge_ids(
            row["mitre_attack"], sorted(techniques_by_path.get(str(row["id"]), set()))
        )
        if mappings != (row["mitre_attack"] or []):
            bind.execute(
                sa.update(attack_paths)
                .where(attack_paths.c.id == row["id"])
                .values(mitre_attack=mappings)
            )

    for row in bind.execute(
        sa.select(
            post_steps.c.id,
            post_steps.c.capability,
            post_steps.c.classification,
            post_steps.c.mitre_attack,
        )
    ).mappings():
        additions = (
            technique_ids_for_capability(str(row["capability"]))
            if row["classification"] == "inferred"
            else ()
        )
        mappings = _merge_ids(row["mitre_attack"], additions)
        if mappings != (row["mitre_attack"] or []):
            bind.execute(
                sa.update(post_steps)
                .where(post_steps.c.id == row["id"])
                .values(mitre_attack=mappings)
            )


def upgrade() -> None:
    bind = op.get_bind()
    drop_reporting_views(bind)
    _add_column(
        "attack_paths",
        sa.Column("mitre_attack", JSON_VALUE, nullable=False, server_default="[]"),
    )
    _add_column(
        "post_exploitation_steps",
        sa.Column("mitre_attack", JSON_VALUE, nullable=False, server_default="[]"),
    )
    _backfill_mappings(bind)
    create_reporting_views(bind)


def downgrade() -> None:
    # Preserve ATT&CK mappings and reporting data during application rollback.
    pass
