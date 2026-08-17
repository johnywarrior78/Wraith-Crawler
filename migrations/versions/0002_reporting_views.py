"""Create stable read-only reporting views.

Revision ID: 0002
Revises: 0001
"""
from __future__ import annotations

from alembic import op

from wraith_crawler.persistence.reporting_views import create_reporting_views, drop_reporting_views

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    create_reporting_views(op.get_bind())


def downgrade() -> None:
    drop_reporting_views(op.get_bind())
