"""first_initialisation

Revision ID: d1469d156d48
Revises:
Create Date: 2026-05-24 17:36:18.889272

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "d1469d156d48"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "xauth_tenants",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False),
        sa.Column("settings", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=True),
    )
    op.create_index("ix_xauth_tenant_slug", "xauth_tenants", ["slug"], unique=True)

    op.create_table(
        "xauth_users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("mfa_enabled", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("mfa_secret", sa.String(64), nullable=True),
        sa.Column("mfa_backup_codes", sa.String(1024), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.UniqueConstraint("email"),
    )
    op.create_index("ix_xauth_user_email", "xauth_users", ["email"])

    op.create_table(
        "xauth_roles",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("xauth_tenants.id"), nullable=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("description", sa.String(500), nullable=True),
    )

    op.create_table(
        "xauth_permissions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("description", sa.String(500), nullable=True),
        sa.Column("source_plugin", sa.String(100), nullable=True),
        sa.Column("tenant_grantable", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("group", sa.String(100), nullable=True),
        sa.Column("active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.UniqueConstraint("name"),
    )

    op.create_table(
        "xauth_role_permissions",
        sa.Column("role_id", sa.String(36), sa.ForeignKey("xauth_roles.id"), primary_key=True),
        sa.Column("permission_id", sa.String(36), sa.ForeignKey("xauth_permissions.id"), primary_key=True),
    )

    op.create_table(
        "xauth_tenant_members",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("xauth_users.id"), nullable=False),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("xauth_tenants.id"), nullable=False),
        sa.Column("role_id", sa.String(36), sa.ForeignKey("xauth_roles.id"), nullable=True),
        sa.Column("joined_at", sa.DateTime, nullable=True),
        sa.Column("is_owner", sa.Boolean, nullable=False, server_default=sa.false()),
    )

    op.create_table(
        "xauth_member_roles",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("xauth_users.id"), nullable=False),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("xauth_tenants.id"), nullable=False),
        sa.Column("role_id", sa.String(36), sa.ForeignKey("xauth_roles.id"), nullable=False),
        sa.Column("granted_by", sa.String(36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.UniqueConstraint("user_id", "tenant_id", "role_id", name="uq_member_role"),
    )

    op.create_table(
        "xauth_member_permissions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("xauth_users.id"), nullable=False),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("xauth_tenants.id"), nullable=False),
        sa.Column("permission_id", sa.String(36), sa.ForeignKey("xauth_permissions.id"), nullable=False),
        sa.Column("granted_by", sa.String(36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.UniqueConstraint("user_id", "tenant_id", "permission_id", name="uq_member_permission"),
    )

    op.create_table(
        "xauth_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("xauth_users.id"), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.Column("refresh_token", sa.String(255), nullable=False, index=True),
        sa.Column("device_fingerprint", sa.String(255), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_revoked", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("last_jti", sa.String(36), nullable=True),
    )

    op.create_table(
        "xauth_audit_logs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("xauth_tenants.id"), nullable=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("xauth_users.id"), nullable=True),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("resource", sa.String(100), nullable=True),
        sa.Column("resource_id", sa.String(36), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.String(500), nullable=True),
        sa.Column("meta", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=True),
    )

    op.create_table(
        "xauth_invites",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("xauth_tenants.id"), nullable=False),
        sa.Column("role_id", sa.String(36), sa.ForeignKey("xauth_roles.id"), nullable=True),
        sa.Column("invited_by", sa.String(36), sa.ForeignKey("xauth_users.id"), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("token", sa.String(36), nullable=False),
        sa.Column("expires_at", sa.DateTime, nullable=False),
        sa.Column("used_at", sa.DateTime, nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.UniqueConstraint("token"),
    )

    op.create_table(
        "xauth_notifications",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("xauth_users.id"), nullable=False, index=True),
        sa.Column("tenant_id", sa.String(36), nullable=True, index=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("message", sa.Text, nullable=True),
        sa.Column("type", sa.String(32), nullable=False, server_default="SYSTEM"),
        sa.Column("link", sa.String(512), nullable=True),
        sa.Column("is_read", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now(), nullable=True),
    )

    op.create_table(
        "xauth_oauth_accounts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("xauth_users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("provider_user_id", sa.String(255), nullable=False),
        sa.Column("provider_email", sa.String(255), nullable=True),
        sa.Column("provider_name", sa.String(255), nullable=True),
        sa.Column("provider_avatar", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=True),
        sa.UniqueConstraint("provider", "provider_user_id", name="uq_oauth_provider_uid"),
    )
    op.create_index("ix_xauth_oauth_user_id", "xauth_oauth_accounts", ["user_id"])


def downgrade() -> None:
    op.drop_table("xauth_oauth_accounts")
    op.drop_table("xauth_notifications")
    op.drop_table("xauth_invites")
    op.drop_table("xauth_audit_logs")
    op.drop_table("xauth_sessions")
    op.drop_table("xauth_member_permissions")
    op.drop_table("xauth_member_roles")
    op.drop_table("xauth_tenant_members")
    op.drop_table("xauth_role_permissions")
    op.drop_table("xauth_permissions")
    op.drop_table("xauth_roles")
    op.drop_table("xauth_users")
    op.drop_table("xauth_tenants")
