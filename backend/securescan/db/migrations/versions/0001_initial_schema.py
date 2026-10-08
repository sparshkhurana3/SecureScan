"""Initial schema: every table of the design's data model, written out explicitly.

Revision ID: 0001
Revises:
Create Date: 2026-10-07

Enum types are created first (create_type=False on the column types avoids double creation).
Keep this file in step with securescan/db/models/*; tests/unit/test_migrations.py checks that
the tables and columns match the models. Later changes are new revisions, never edits here.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

ENUM_APP_TYPE = postgresql.ENUM("internal", "vendor", name="app_type", create_type=False)
ENUM_TARGET_KIND = postgresql.ENUM(
    "github_repo",
    "vendor_repo",
    "zip",
    "image",
    "url",
    name="target_kind",
    create_type=False,
)
ENUM_TARGET_ENVIRONMENT = postgresql.ENUM(
    "production",
    "uat",
    name="target_environment",
    create_type=False,
)
ENUM_SCAN_KIND = postgresql.ENUM("sast", "dast", name="scan_kind", create_type=False)
ENUM_SCAN_TRIGGER = postgresql.ENUM(
    "user",
    "change",
    "weekly",
    "schedule",
    name="scan_trigger",
    create_type=False,
)
ENUM_SCAN_STATE = postgresql.ENUM(
    "queued",
    "running",
    "completed",
    "completed_partial",
    "failed",
    "cancelled",
    name="scan_state",
    create_type=False,
)
ENUM_JOB_STATE = postgresql.ENUM(
    "queued",
    "preparing",
    "running",
    "completed",
    "completed_partial",
    "failed",
    "cancelled",
    "timed_out",
    name="job_state",
    create_type=False,
)
ENUM_IMPORT_STATE = postgresql.ENUM(
    "pending",
    "imported",
    "failed",
    name="import_state",
    create_type=False,
)
ENUM_REPORT_KIND = postgresql.ENUM("application", "vendor", name="report_kind", create_type=False)
ENUM_VERDICT = postgresql.ENUM(
    "pass",
    "conditional",
    "fail",
    "pending",
    name="verdict",
    create_type=False,
)
ENUM_REVIEW_STATE = postgresql.ENUM("automatic", "reviewed", name="review_state", create_type=False)
ENUM_SEVERITY = postgresql.ENUM(
    "critical",
    "high",
    "medium",
    "low",
    "info",
    name="severity",
    create_type=False,
)
ENUM_USER_ROLE = postgresql.ENUM("Admin", "Analyst", name="user_role", create_type=False)
ENUM_ARTIFACT_KIND = postgresql.ENUM(
    "upload",
    "raw_report",
    "sbom",
    "log",
    "report_file",
    "snapshot",
    "template",
    "document",
    name="artifact_kind",
    create_type=False,
)
ENUM_UPLOAD_STATE = postgresql.ENUM(
    "receiving",
    "complete",
    "aborted",
    name="upload_state",
    create_type=False,
)
ENUM_CREDENTIAL_KIND = postgresql.ENUM(
    "github_app_key",
    "deploy_key",
    "vendor_token",
    "registry",
    "dast_login",
    "nvd_key",
    "defectdojo_token",
    "defectdojo_admin_token",
    "sonarqube_token",
    name="credential_kind",
    create_type=False,
)
ENUM_SCHEDULE_KIND = postgresql.ENUM(
    "weekly",
    "dast",
    "poll",
    name="schedule_kind",
    create_type=False,
)
ENUM_CONTENT_FEED = postgresql.ENUM(
    "semgrep_rules",
    "nuclei_templates",
    "grype_db",
    "nvd_data",
    name="content_feed",
    create_type=False,
)
ENUM_OUTBOX_STATE = postgresql.ENUM(
    "pending",
    "processing",
    "done",
    "dead_letter",
    name="outbox_state",
    create_type=False,
)

ENUM_TYPES = [
    ENUM_APP_TYPE,
    ENUM_TARGET_KIND,
    ENUM_TARGET_ENVIRONMENT,
    ENUM_SCAN_KIND,
    ENUM_SCAN_TRIGGER,
    ENUM_SCAN_STATE,
    ENUM_JOB_STATE,
    ENUM_IMPORT_STATE,
    ENUM_REPORT_KIND,
    ENUM_VERDICT,
    ENUM_REVIEW_STATE,
    ENUM_SEVERITY,
    ENUM_USER_ROLE,
    ENUM_ARTIFACT_KIND,
    ENUM_UPLOAD_STATE,
    ENUM_CREDENTIAL_KIND,
    ENUM_SCHEDULE_KIND,
    ENUM_CONTENT_FEED,
    ENUM_OUTBOX_STATE,
]


def upgrade() -> None:
    bind = op.get_bind()
    for enum_type in ENUM_TYPES:
        enum_type.create(bind, checkfirst=True)

    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("oid", sa.String(255), nullable=False),
        sa.Column("name", sa.String(255), nullable=True),
        sa.Column("email", sa.String(320), nullable=True),
        sa.Column("upn", sa.String(320), nullable=True),
        sa.Column("role", ENUM_USER_ROLE, nullable=False),
        sa.Column(
            "roles",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
        sa.Column("dd_user_id", sa.Integer(), nullable=True),
        sa.Column("dd_username", sa.String(150), nullable=True),
        sa.Column("dd_initial_secret", sa.Text(), nullable=True),
        sa.Column("dd_secret_shown_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("dd_disabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("dd_disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        sa.UniqueConstraint("oid", name="uq_users_oid"),
    )
    op.create_index("ix_users_last_login", "users", ["last_login"])

    op.create_table(
        "sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("csrf_token", sa.String(64), nullable=False),
        sa.Column("role", ENUM_USER_ROLE, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ip", sa.String(64), nullable=True),
        sa.Column("user_agent", sa.String(255), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_sessions"),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_sessions_user_id",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("token_hash", name="uq_sessions_token_hash"),
    )
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"])
    op.create_index("ix_sessions_expires_at", "sessions", ["expires_at"])

    op.create_table(
        "vendors",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("contact_name", sa.String(200), nullable=True),
        sa.Column("contact_email", sa.String(320), nullable=True),
        sa.Column("risk_tier", sa.String(32), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_vendors"),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name="fk_vendors_created_by_id",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint("name", name="uq_vendors_name"),
    )
    op.create_index("ix_vendors_created_at", "vendors", ["created_at"])

    op.create_table(
        "applications",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("type", ENUM_APP_TYPE, nullable=False),
        sa.Column("vendor_id", sa.Uuid(), nullable=True),
        sa.Column("vendor_product", sa.String(200), nullable=True),
        sa.Column("hosting", sa.String(16), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("criticality", sa.String(16), nullable=True),
        sa.Column("data_classification", sa.String(32), nullable=True),
        sa.Column(
            "tags",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("confirmed", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("automatic", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("github_repo_id", sa.BigInteger(), nullable=True),
        sa.Column("github_full_name", sa.String(255), nullable=True),
        sa.Column("default_branch", sa.String(255), nullable=True),
        sa.Column("github_removed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("dd_product_id", sa.Integer(), nullable=True),
        sa.Column(
            "cached_counts",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("cached_counts_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_scan_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_scan_id", sa.Uuid(), nullable=True),
        sa.Column("last_verdict", ENUM_VERDICT, nullable=True),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_applications"),
        sa.ForeignKeyConstraint(
            ["vendor_id"],
            ["vendors.id"],
            name="fk_applications_vendor_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name="fk_applications_created_by_id",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint("name", name="uq_applications_name"),
        sa.UniqueConstraint("github_repo_id", name="uq_applications_github_repo_id"),
    )
    op.create_index("ix_applications_type", "applications", ["type"])
    op.create_index("ix_applications_vendor_id", "applications", ["vendor_id"])
    op.create_index("ix_applications_last_scan_at", "applications", ["last_scan_at"])
    op.create_index("ix_applications_created_at", "applications", ["created_at"])

    op.create_table(
        "application_versions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("application_id", sa.Uuid(), nullable=False),
        sa.Column("label", sa.String(255), nullable=False),
        sa.Column("label_kind", sa.String(32), nullable=False, server_default=sa.text("'branch'")),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("commit_sha", sa.String(64), nullable=True),
        sa.Column("dd_engagement_id", sa.Integer(), nullable=True),
        sa.Column("sonar_project_key", sa.String(400), nullable=True),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_application_versions"),
        sa.ForeignKeyConstraint(
            ["application_id"],
            ["applications.id"],
            name="fk_application_versions_application_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name="fk_application_versions_created_by_id",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint(
            "application_id",
            "label",
            name="uq_application_versions_application_id_label",
        ),
    )
    op.create_index("ix_application_versions_created_at", "application_versions", ["created_at"])

    op.create_table(
        "artifacts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("kind", ENUM_ARTIFACT_KIND, nullable=False),
        sa.Column("storage_key", sa.String(512), nullable=False),
        sa.Column("filename", sa.String(255), nullable=True),
        sa.Column("content_type", sa.String(255), nullable=True),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("owner_type", sa.String(64), nullable=True),
        sa.Column("owner_id", sa.Uuid(), nullable=True),
        sa.Column("scan_id", sa.Uuid(), nullable=True),
        sa.Column("job_id", sa.Uuid(), nullable=True),
        sa.Column("created_by_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_artifacts"),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name="fk_artifacts_created_by_id",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint("storage_key", name="uq_artifacts_storage_key"),
    )
    op.create_index("ix_artifacts_scan_id", "artifacts", ["scan_id"])
    op.create_index("ix_artifacts_job_id", "artifacts", ["job_id"])
    op.create_index("ix_artifacts_owner_type_owner_id", "artifacts", ["owner_type", "owner_id"])
    op.create_index("ix_artifacts_kind", "artifacts", ["kind"])

    op.create_table(
        "uploads",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("content_type", sa.String(255), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("received_bytes", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column("chunk_bytes", sa.Integer(), nullable=False),
        sa.Column(
            "state",
            ENUM_UPLOAD_STATE,
            nullable=False,
            server_default=sa.text("'receiving'"),
        ),
        sa.Column("sha256_expected", sa.String(64), nullable=True),
        sa.Column("sha256", sa.String(64), nullable=True),
        sa.Column("partial_key", sa.String(512), nullable=False),
        sa.Column("artifact_id", sa.Uuid(), nullable=True),
        sa.Column("created_by_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_uploads"),
        sa.ForeignKeyConstraint(
            ["artifact_id"],
            ["artifacts.id"],
            name="fk_uploads_artifact_id",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name="fk_uploads_created_by_id",
            ondelete="SET NULL",
        ),
    )
    op.create_index("ix_uploads_state_updated_at", "uploads", ["state", "updated_at"])

    op.create_table(
        "credentials",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("kind", ENUM_CREDENTIAL_KIND, nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("ciphertext", sa.Text(), nullable=False),
        sa.Column("key_id", sa.String(32), nullable=False),
        sa.Column("public_material", sa.Text(), nullable=True),
        sa.Column("application_id", sa.Uuid(), nullable=True),
        sa.Column("version_id", sa.Uuid(), nullable=True),
        sa.Column(
            "extra",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expiry_alert_sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_credentials"),
        sa.ForeignKeyConstraint(
            ["application_id"],
            ["applications.id"],
            name="fk_credentials_application_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["version_id"],
            ["application_versions.id"],
            name="fk_credentials_version_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name="fk_credentials_created_by_id",
            ondelete="SET NULL",
        ),
    )
    op.create_index("ix_credentials_kind", "credentials", ["kind"])
    op.create_index("ix_credentials_expires_at", "credentials", ["expires_at"])
    op.create_index("ix_credentials_version_id", "credentials", ["version_id"])

    op.create_table(
        "targets",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("version_id", sa.Uuid(), nullable=False),
        sa.Column("kind", ENUM_TARGET_KIND, nullable=False),
        sa.Column("name", sa.String(200), nullable=True),
        sa.Column("locator", sa.Text(), nullable=False),
        sa.Column("environment", ENUM_TARGET_ENVIRONMENT, nullable=True),
        sa.Column("environment_set_by_id", sa.Uuid(), nullable=True),
        sa.Column("environment_set_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("credential_id", sa.Uuid(), nullable=True),
        sa.Column("login_profile_id", sa.Uuid(), nullable=True),
        sa.Column("upload_artifact_id", sa.Uuid(), nullable=True),
        sa.Column("default_branch", sa.String(255), nullable=True),
        sa.Column(
            "scope_includes",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "scope_excludes",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("api_spec_type", sa.String(32), nullable=True),
        sa.Column("api_spec_locator", sa.Text(), nullable=True),
        sa.Column("api_spec_artifact_id", sa.Uuid(), nullable=True),
        sa.Column("rate_limit_rps", sa.Integer(), nullable=True),
        sa.Column(
            "blackout_windows",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("dast_cron", sa.String(100), nullable=True),
        sa.Column("host_approved", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("vendor_authorization_artifact_id", sa.Uuid(), nullable=True),
        sa.Column("vendor_authorized_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("vendor_authorized_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("vendor_contact", sa.Text(), nullable=True),
        sa.Column("vendor_authorization_notes", sa.Text(), nullable=True),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_targets"),
        sa.ForeignKeyConstraint(
            ["version_id"],
            ["application_versions.id"],
            name="fk_targets_version_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["environment_set_by_id"],
            ["users.id"],
            name="fk_targets_environment_set_by_id",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["credential_id"],
            ["credentials.id"],
            name="fk_targets_credential_id",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["login_profile_id"],
            ["credentials.id"],
            name="fk_targets_login_profile_id",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["upload_artifact_id"],
            ["artifacts.id"],
            name="fk_targets_upload_artifact_id",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["api_spec_artifact_id"],
            ["artifacts.id"],
            name="fk_targets_api_spec_artifact_id",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["vendor_authorization_artifact_id"],
            ["artifacts.id"],
            name="fk_targets_vendor_authorization_artifact_id",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name="fk_targets_created_by_id",
            ondelete="SET NULL",
        ),
    )
    op.create_index("ix_targets_version_id", "targets", ["version_id"])
    op.create_index("ix_targets_kind_environment", "targets", ["kind", "environment"])
    op.create_index("ix_targets_created_at", "targets", ["created_at"])

    op.create_table(
        "scan_profiles",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("body_yaml", sa.Text(), nullable=False),
        sa.Column(
            "body",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_by_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_scan_profiles"),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name="fk_scan_profiles_created_by_id",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint("name", "version", name="uq_scan_profiles_name_version"),
    )

    op.create_table(
        "policies",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("data_classification", sa.String(32), nullable=True),
        sa.Column("application_id", sa.Uuid(), nullable=True),
        sa.Column("is_default", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column(
            "thresholds",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("version", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_by_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_policies"),
        sa.ForeignKeyConstraint(
            ["application_id"],
            ["applications.id"],
            name="fk_policies_application_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name="fk_policies_created_by_id",
            ondelete="SET NULL",
        ),
    )
    op.create_index("ix_policies_data_classification", "policies", ["data_classification"])
    op.create_index("ix_policies_application_id", "policies", ["application_id"])

    op.create_table(
        "scans",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("application_id", sa.Uuid(), nullable=False),
        sa.Column("version_id", sa.Uuid(), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=True),
        sa.Column("profile_id", sa.Uuid(), nullable=True),
        sa.Column("profile_name", sa.String(100), nullable=False),
        sa.Column("profile_version", sa.Integer(), nullable=False),
        sa.Column("kind", ENUM_SCAN_KIND, nullable=False),
        sa.Column("mode", sa.String(32), nullable=True),
        sa.Column("trigger", ENUM_SCAN_TRIGGER, nullable=False),
        sa.Column("trigger_detail", sa.String(255), nullable=True),
        sa.Column("state", ENUM_SCAN_STATE, nullable=False, server_default=sa.text("'queued'")),
        sa.Column("verdict", ENUM_VERDICT, nullable=False, server_default=sa.text("'pending'")),
        sa.Column(
            "verdict_detail",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("policy_id", sa.Uuid(), nullable=True),
        sa.Column("started_by_id", sa.Uuid(), nullable=True),
        sa.Column("idempotency_key", sa.String(128), nullable=True),
        sa.Column(
            "requested_tools",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "options",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("commit_sha", sa.String(64), nullable=True),
        sa.Column("source_ref", sa.String(255), nullable=True),
        sa.Column("source_digest", sa.String(128), nullable=True),
        sa.Column(
            "counts",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "coverage_notes",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancelled_by_id", sa.Uuid(), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_scans"),
        sa.ForeignKeyConstraint(
            ["application_id"],
            ["applications.id"],
            name="fk_scans_application_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["version_id"],
            ["application_versions.id"],
            name="fk_scans_version_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["target_id"],
            ["targets.id"],
            name="fk_scans_target_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["profile_id"],
            ["scan_profiles.id"],
            name="fk_scans_profile_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["policy_id"],
            ["policies.id"],
            name="fk_scans_policy_id",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["started_by_id"],
            ["users.id"],
            name="fk_scans_started_by_id",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["cancelled_by_id"],
            ["users.id"],
            name="fk_scans_cancelled_by_id",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint("idempotency_key", name="uq_scans_idempotency_key"),
    )
    op.create_index("ix_scans_application_id_created_at", "scans", ["application_id", "created_at"])
    op.create_index("ix_scans_state", "scans", ["state"])
    op.create_index("ix_scans_version_id", "scans", ["version_id"])
    op.create_index("ix_scans_created_at", "scans", ["created_at"])

    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("tool", sa.String(64), nullable=False),
        sa.Column("state", ENUM_JOB_STATE, nullable=False, server_default=sa.text("'queued'")),
        sa.Column(
            "import_state",
            ENUM_IMPORT_STATE,
            nullable=False,
            server_default=sa.text("'pending'"),
        ),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("procrastinate_job_id", sa.BigInteger(), nullable=True),
        sa.Column("container_id", sa.String(128), nullable=True),
        sa.Column("worker_name", sa.String(128), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("image", sa.String(255), nullable=True),
        sa.Column("image_digest", sa.String(160), nullable=True),
        sa.Column("tool_version", sa.String(128), nullable=True),
        sa.Column(
            "content_versions",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("outcome_reason", sa.Text(), nullable=True),
        sa.Column("partial", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column(
            "counts",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("dd_test_id", sa.Integer(), nullable=True),
        sa.Column("dd_imported_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "dd_import_stats",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("log_path", sa.String(512), nullable=True),
        sa.Column(
            "applied_exclusions",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("coverage_note", sa.Text(), nullable=True),
        sa.Column(
            "options",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_scan_jobs"),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            name="fk_scan_jobs_scan_id",
            ondelete="RESTRICT",
        ),
    )
    op.create_index("ix_scan_jobs_state", "scan_jobs", ["state"])
    op.create_index("ix_scan_jobs_scan_id", "scan_jobs", ["scan_id"])
    op.create_index("ix_scan_jobs_import_state", "scan_jobs", ["import_state"])

    op.create_table(
        "finding_history",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("application_id", sa.Uuid(), nullable=False),
        sa.Column("version_id", sa.Uuid(), nullable=False),
        sa.Column("vendor_id", sa.Uuid(), nullable=True),
        sa.Column("started_by_id", sa.Uuid(), nullable=True),
        sa.Column("source_kind", sa.String(32), nullable=True),
        sa.Column("tool", sa.String(64), nullable=False),
        sa.Column("dd_finding_id", sa.BigInteger(), nullable=False),
        sa.Column("hash_code", sa.String(128), nullable=True),
        sa.Column("dd_test_id", sa.Integer(), nullable=True),
        sa.Column("severity", ENUM_SEVERITY, nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("cwe", sa.Integer(), nullable=True),
        sa.Column("cve", sa.String(64), nullable=True),
        sa.Column("cvss", sa.Float(), nullable=True),
        sa.Column("component", sa.String(500), nullable=True),
        sa.Column("component_version", sa.String(255), nullable=True),
        sa.Column("file_path", sa.Text(), nullable=True),
        sa.Column("line", sa.Integer(), nullable=True),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("state_at_scan", sa.String(32), nullable=False),
        sa.Column(
            "flags_at_scan",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("state_now", sa.String(32), nullable=False),
        sa.Column(
            "flags_now",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("state_now_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scanned_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_finding_history"),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            name="fk_finding_history_scan_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["scan_jobs.id"],
            name="fk_finding_history_job_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["application_id"],
            ["applications.id"],
            name="fk_finding_history_application_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["version_id"],
            ["application_versions.id"],
            name="fk_finding_history_version_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["vendor_id"],
            ["vendors.id"],
            name="fk_finding_history_vendor_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["started_by_id"],
            ["users.id"],
            name="fk_finding_history_started_by_id",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint(
            "job_id",
            "dd_finding_id",
            name="uq_finding_history_job_id_dd_finding_id",
        ),
    )
    op.create_index(
        "ix_finding_history_application_id_severity_scanned_at",
        "finding_history",
        ["application_id", "severity", "scanned_at"],
    )
    op.create_index("ix_finding_history_scan_id", "finding_history", ["scan_id"])
    op.create_index("ix_finding_history_dd_finding_id", "finding_history", ["dd_finding_id"])
    op.create_index("ix_finding_history_hash_code", "finding_history", ["hash_code"])
    op.create_index("ix_finding_history_scanned_at", "finding_history", ["scanned_at"])
    op.create_index("ix_finding_history_tool_scanned_at", "finding_history", ["tool", "scanned_at"])

    op.create_table(
        "report_templates",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("builtin", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column(
            "default_for_application",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "default_for_vendor",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("zip_artifact_id", sa.Uuid(), nullable=True),
        sa.Column("directory", sa.String(512), nullable=True),
        sa.Column(
            "entry_file",
            sa.String(100),
            nullable=False,
            server_default=sa.text("'template.html'"),
        ),
        sa.Column("sha256", sa.String(64), nullable=True),
        sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("validation_error", sa.Text(), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_by_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_report_templates"),
        sa.ForeignKeyConstraint(
            ["zip_artifact_id"],
            ["artifacts.id"],
            name="fk_report_templates_zip_artifact_id",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name="fk_report_templates_created_by_id",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint("name", "version", name="uq_report_templates_name_version"),
    )

    op.create_table(
        "reports",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("application_id", sa.Uuid(), nullable=False),
        sa.Column("version_id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=True),
        sa.Column("kind", ENUM_REPORT_KIND, nullable=False),
        sa.Column("ref", sa.String(64), nullable=True),
        sa.Column("title", sa.String(255), nullable=True),
        sa.Column("template_id", sa.Uuid(), nullable=True),
        sa.Column("template_version", sa.Integer(), nullable=True),
        sa.Column("snapshot_artifact_id", sa.Uuid(), nullable=True),
        sa.Column("snapshot_sha256", sa.String(64), nullable=True),
        sa.Column("html_artifact_id", sa.Uuid(), nullable=True),
        sa.Column("pdf_artifact_id", sa.Uuid(), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default=sa.text("'pending'")),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "review_state",
            ENUM_REVIEW_STATE,
            nullable=False,
            server_default=sa.text("'automatic'"),
        ),
        sa.Column("proposed_verdict", ENUM_VERDICT, nullable=True),
        sa.Column("verdict", ENUM_VERDICT, nullable=False, server_default=sa.text("'pending'")),
        sa.Column(
            "verdict_overridden",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("override_reason", sa.Text(), nullable=True),
        sa.Column("reviewer_id", sa.Uuid(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "conditions",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("vendor_copy", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("internal_notes", sa.Text(), nullable=True),
        sa.Column(
            "mapping_versions",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("previous_report_id", sa.Uuid(), nullable=True),
        sa.Column("generated_by_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_reports"),
        sa.ForeignKeyConstraint(
            ["application_id"],
            ["applications.id"],
            name="fk_reports_application_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["version_id"],
            ["application_versions.id"],
            name="fk_reports_version_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            name="fk_reports_scan_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["template_id"],
            ["report_templates.id"],
            name="fk_reports_template_id",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["snapshot_artifact_id"],
            ["artifacts.id"],
            name="fk_reports_snapshot_artifact_id",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["html_artifact_id"],
            ["artifacts.id"],
            name="fk_reports_html_artifact_id",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["pdf_artifact_id"],
            ["artifacts.id"],
            name="fk_reports_pdf_artifact_id",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["reviewer_id"],
            ["users.id"],
            name="fk_reports_reviewer_id",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["previous_report_id"],
            ["reports.id"],
            name="fk_reports_previous_report_id",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["generated_by_id"],
            ["users.id"],
            name="fk_reports_generated_by_id",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint("ref", name="uq_reports_ref"),
    )
    op.create_index("ix_reports_version_id_created_at", "reports", ["version_id", "created_at"])
    op.create_index("ix_reports_scan_id", "reports", ["scan_id"])
    op.create_index("ix_reports_application_id", "reports", ["application_id"])

    op.create_table(
        "schedules",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("kind", ENUM_SCHEDULE_KIND, nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("cron", sa.String(100), nullable=True),
        sa.Column("poll_interval_minutes", sa.Integer(), nullable=True),
        sa.Column(
            "blackout_windows",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "repository_set",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("target_id", sa.Uuid(), nullable=True),
        sa.Column("profile_name", sa.String(100), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(255), nullable=True),
        sa.Column("created_by_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_schedules"),
        sa.ForeignKeyConstraint(
            ["target_id"],
            ["targets.id"],
            name="fk_schedules_target_id",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name="fk_schedules_created_by_id",
            ondelete="SET NULL",
        ),
    )
    op.create_index("ix_schedules_kind_enabled", "schedules", ["kind", "enabled"])
    op.create_index("ix_schedules_target_id", "schedules", ["target_id"])

    op.create_table(
        "github_connections",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("org_login", sa.String(200), nullable=True),
        sa.Column("app_id", sa.String(64), nullable=False),
        sa.Column("client_id", sa.String(128), nullable=False),
        sa.Column("installation_id", sa.String(64), nullable=False),
        sa.Column(
            "api_base_url",
            sa.String(255),
            nullable=False,
            server_default=sa.text("'https://api.github.com'"),
        ),
        sa.Column(
            "git_host",
            sa.String(255),
            nullable=False,
            server_default=sa.text("'github.com'"),
        ),
        sa.Column(
            "api_version",
            sa.String(32),
            nullable=False,
            server_default=sa.text("'2026-03-10'"),
        ),
        sa.Column("key_1_credential_id", sa.Uuid(), nullable=True),
        sa.Column("key_2_credential_id", sa.Uuid(), nullable=True),
        sa.Column("active_key", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("last_test_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_test_ok", sa.Boolean(), nullable=True),
        sa.Column("last_test_message", sa.Text(), nullable=True),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_poll_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_poll_ok", sa.Boolean(), nullable=True),
        sa.Column("last_poll_message", sa.Text(), nullable=True),
        sa.Column("rate_limit_remaining", sa.Integer(), nullable=True),
        sa.Column("rate_limit_reset_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_github_connections"),
        sa.ForeignKeyConstraint(
            ["key_1_credential_id"],
            ["credentials.id"],
            name="fk_github_connections_key_1_credential_id",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["key_2_credential_id"],
            ["credentials.id"],
            name="fk_github_connections_key_2_credential_id",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint("org_login", name="uq_github_connections_org_login"),
    )

    op.create_table(
        "repository_heads",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("application_id", sa.Uuid(), nullable=False),
        sa.Column("repository", sa.String(255), nullable=False),
        sa.Column("branch", sa.String(255), nullable=False),
        sa.Column("last_seen_sha", sa.String(64), nullable=True),
        sa.Column("last_scanned_sha", sa.String(64), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_scanned_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_scan_id", sa.Uuid(), nullable=True),
        sa.Column("last_poll_error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_repository_heads"),
        sa.ForeignKeyConstraint(
            ["application_id"],
            ["applications.id"],
            name="fk_repository_heads_application_id",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "application_id",
            "branch",
            name="uq_repository_heads_application_id_branch",
        ),
    )

    op.create_table(
        "content_versions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("feed", ENUM_CONTENT_FEED, nullable=False),
        sa.Column("version", sa.String(255), nullable=False),
        sa.Column("path", sa.String(512), nullable=True),
        sa.Column("source_commit", sa.String(64), nullable=True),
        sa.Column("built_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "fetched_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "regression_result",
            sa.String(16),
            nullable=False,
            server_default=sa.text("'pending'"),
        ),
        sa.Column(
            "regression_detail",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_content_versions"),
        sa.UniqueConstraint("feed", "version", name="uq_content_versions_feed_version"),
    )
    op.create_index(
        "ix_content_versions_feed_fetched_at",
        "content_versions",
        ["feed", "fetched_at"],
    )
    op.create_index(
        "uq_content_versions_active_feed",
        "content_versions",
        ["feed"],
        unique=True,
        postgresql_where=sa.text("active"),
    )

    op.create_table(
        "image_versions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tool", sa.String(64), nullable=False),
        sa.Column("image", sa.String(255), nullable=False),
        sa.Column("tag", sa.String(128), nullable=True),
        sa.Column("digest", sa.String(160), nullable=False),
        sa.Column("source", sa.String(16), nullable=False, server_default=sa.text("'lock'")),
        sa.Column(
            "regression_result",
            sa.String(16),
            nullable=False,
            server_default=sa.text("'pending'"),
        ),
        sa.Column(
            "regression_detail",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column(
            "proposed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("approved_by_id", sa.Uuid(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_image_versions"),
        sa.ForeignKeyConstraint(
            ["approved_by_id"],
            ["users.id"],
            name="fk_image_versions_approved_by_id",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint("tool", "digest", name="uq_image_versions_tool_digest"),
    )
    op.create_index("ix_image_versions_tool_active", "image_versions", ["tool", "active"])

    op.create_table(
        "sync_outbox",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("state", ENUM_OUTBOX_STATE, nullable=False, server_default=sa.text("'pending'")),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column(
            "next_attempt_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column(
            "payload",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_sync_outbox"),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["scan_jobs.id"],
            name="fk_sync_outbox_job_id",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_sync_outbox_state_next_attempt_at",
        "sync_outbox",
        ["state", "next_attempt_at"],
    )
    op.create_index("ix_sync_outbox_job_id", "sync_outbox", ["job_id"])

    op.create_table(
        "audit_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("actor_id", sa.Uuid(), nullable=True),
        sa.Column("actor_label", sa.String(320), nullable=False),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("object_type", sa.String(64), nullable=True),
        sa.Column("object_id", sa.String(128), nullable=True),
        sa.Column("source_ip", sa.String(64), nullable=True),
        sa.Column("user_agent", sa.String(255), nullable=True),
        sa.Column("request_id", sa.String(64), nullable=True),
        sa.Column(
            "detail",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_audit_events"),
        sa.ForeignKeyConstraint(
            ["actor_id"],
            ["users.id"],
            name="fk_audit_events_actor_id",
            ondelete="RESTRICT",
        ),
    )
    op.create_index("ix_audit_events_created_at", "audit_events", ["created_at"])
    op.create_index(
        "ix_audit_events_actor_id_created_at",
        "audit_events",
        ["actor_id", "created_at"],
    )
    op.create_index("ix_audit_events_action_created_at", "audit_events", ["action", "created_at"])
    op.create_index(
        "ix_audit_events_object_type_object_id",
        "audit_events",
        ["object_type", "object_id"],
    )

    # The audit log is append-only: reject UPDATE and DELETE at the database level.
    op.execute(
        """
        CREATE FUNCTION audit_events_reject_change() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit_events is append-only';
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_events_append_only
        BEFORE UPDATE OR DELETE ON audit_events
        FOR EACH ROW EXECUTE FUNCTION audit_events_reject_change()
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events")
    op.execute("DROP FUNCTION IF EXISTS audit_events_reject_change()")
    op.drop_table("audit_events")
    op.drop_table("sync_outbox")
    op.drop_table("image_versions")
    op.drop_table("content_versions")
    op.drop_table("repository_heads")
    op.drop_table("github_connections")
    op.drop_table("schedules")
    op.drop_table("reports")
    op.drop_table("report_templates")
    op.drop_table("finding_history")
    op.drop_table("scan_jobs")
    op.drop_table("scans")
    op.drop_table("policies")
    op.drop_table("scan_profiles")
    op.drop_table("targets")
    op.drop_table("credentials")
    op.drop_table("uploads")
    op.drop_table("artifacts")
    op.drop_table("application_versions")
    op.drop_table("applications")
    op.drop_table("vendors")
    op.drop_table("sessions")
    op.drop_table("users")
    bind = op.get_bind()
    for enum_type in reversed(ENUM_TYPES):
        enum_type.drop(bind, checkfirst=True)
