"""Create authentication and authorization tables.

Revision ID: 20261006_0001
Revises:
Create Date: 2026-10-06
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261006_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "permissions",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_permissions"),
        sa.UniqueConstraint("name", name="uq_permissions_name"),
    )
    op.create_table(
        "principals",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("actor_type", sa.String(length=16), nullable=False),
        sa.Column("identifier", sa.String(length=254), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "actor_type IN ('human', 'agent')",
            name="ck_principals_actor_type",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_principals"),
        sa.UniqueConstraint(
            "actor_type",
            "identifier",
            name="uq_principals_actor_type",
        ),
    )
    op.create_table(
        "roles",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_roles"),
        sa.UniqueConstraint("name", name="uq_roles_name"),
    )
    op.create_table(
        "auth_tokens",
        sa.Column("jti", sa.String(length=36), nullable=False),
        sa.Column("principal_id", sa.String(length=36), nullable=False),
        sa.Column("family_id", sa.String(length=36), nullable=False),
        sa.Column("token_type", sa.String(length=16), nullable=False),
        sa.Column("issued_at", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.Integer(), nullable=False),
        sa.Column("revoked_at", sa.Integer(), nullable=True),
        sa.Column("replaced_by_jti", sa.String(length=36), nullable=True),
        sa.CheckConstraint(
            "token_type IN ('access', 'refresh')",
            name="ck_auth_tokens_token_type",
        ),
        sa.ForeignKeyConstraint(
            ["principal_id"],
            ["principals.id"],
            name="fk_auth_tokens_principal_id_principals",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("jti", name="pk_auth_tokens"),
    )
    op.create_index(
        "ix_auth_tokens_expires_at",
        "auth_tokens",
        ["expires_at"],
        unique=False,
    )
    op.create_index(
        "ix_auth_tokens_family_id",
        "auth_tokens",
        ["family_id"],
        unique=False,
    )
    op.create_index(
        "ix_auth_tokens_principal_id",
        "auth_tokens",
        ["principal_id"],
        unique=False,
    )
    op.create_table(
        "principal_roles",
        sa.Column("principal_id", sa.String(length=36), nullable=False),
        sa.Column("role_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["principal_id"],
            ["principals.id"],
            name="fk_principal_roles_principal_id_principals",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name="fk_principal_roles_role_id_roles",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "principal_id",
            "role_id",
            name="uq_principal_roles_principal_id",
        ),
    )
    op.create_table(
        "role_permissions",
        sa.Column("role_id", sa.Integer(), nullable=False),
        sa.Column("permission_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["permission_id"],
            ["permissions.id"],
            name="fk_role_permissions_permission_id_permissions",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name="fk_role_permissions_role_id_roles",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "role_id",
            "permission_id",
            name="uq_role_permissions_role_id",
        ),
    )


def downgrade() -> None:
    op.drop_table("role_permissions")
    op.drop_table("principal_roles")
    op.drop_index("ix_auth_tokens_principal_id", table_name="auth_tokens")
    op.drop_index("ix_auth_tokens_family_id", table_name="auth_tokens")
    op.drop_index("ix_auth_tokens_expires_at", table_name="auth_tokens")
    op.drop_table("auth_tokens")
    op.drop_table("roles")
    op.drop_table("principals")
    op.drop_table("permissions")
