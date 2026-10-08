"""Python enums behind the PostgreSQL enum types.

Each enum is stored as a native PostgreSQL enum whose labels are the member *values*.
The name of the PostgreSQL type is listed in ``PG_ENUM_NAMES``. Adding a value later needs an
Alembic revision with ``ALTER TYPE <name> ADD VALUE``; the models and the initial migration are
generated from the same lists, see docs/backend-conventions.md.
"""

from __future__ import annotations

import enum


class AppType(str, enum.Enum):  # noqa: UP042 - str mixin keeps the values plain strings
    INTERNAL = "internal"
    VENDOR = "vendor"


class TargetKind(str, enum.Enum):  # noqa: UP042
    GITHUB_REPO = "github_repo"
    VENDOR_REPO = "vendor_repo"
    ZIP = "zip"
    IMAGE = "image"
    URL = "url"


class TargetEnvironment(str, enum.Enum):  # noqa: UP042
    PRODUCTION = "production"
    UAT = "uat"


class ScanKind(str, enum.Enum):  # noqa: UP042
    SAST = "sast"
    DAST = "dast"


class ScanTrigger(str, enum.Enum):  # noqa: UP042
    USER = "user"
    CHANGE = "change"
    WEEKLY = "weekly"
    SCHEDULE = "schedule"


class ScanState(str, enum.Enum):  # noqa: UP042
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_PARTIAL = "completed_partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobState(str, enum.Enum):  # noqa: UP042
    QUEUED = "queued"
    PREPARING = "preparing"
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_PARTIAL = "completed_partial"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class ImportState(str, enum.Enum):  # noqa: UP042
    PENDING = "pending"
    IMPORTED = "imported"
    FAILED = "failed"


class ReportKind(str, enum.Enum):  # noqa: UP042
    APPLICATION = "application"
    VENDOR = "vendor"


class Verdict(str, enum.Enum):  # noqa: UP042
    PASS = "pass"
    CONDITIONAL = "conditional"
    FAIL = "fail"
    PENDING = "pending"


class ReviewState(str, enum.Enum):  # noqa: UP042
    AUTOMATIC = "automatic"
    REVIEWED = "reviewed"


class Severity(str, enum.Enum):  # noqa: UP042
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class UserRole(str, enum.Enum):  # noqa: UP042
    ADMIN = "Admin"
    ANALYST = "Analyst"


class ArtifactKind(str, enum.Enum):  # noqa: UP042
    UPLOAD = "upload"
    RAW_REPORT = "raw_report"
    SBOM = "sbom"
    LOG = "log"
    REPORT_FILE = "report_file"
    SNAPSHOT = "snapshot"
    TEMPLATE = "template"
    DOCUMENT = "document"


class UploadState(str, enum.Enum):  # noqa: UP042
    RECEIVING = "receiving"
    COMPLETE = "complete"
    ABORTED = "aborted"


class CredentialKind(str, enum.Enum):  # noqa: UP042
    GITHUB_APP_KEY = "github_app_key"
    DEPLOY_KEY = "deploy_key"
    VENDOR_TOKEN = "vendor_token"
    REGISTRY = "registry"
    DAST_LOGIN = "dast_login"
    NVD_KEY = "nvd_key"
    DEFECTDOJO_TOKEN = "defectdojo_token"
    DEFECTDOJO_ADMIN_TOKEN = "defectdojo_admin_token"
    SONARQUBE_TOKEN = "sonarqube_token"


class ScheduleKind(str, enum.Enum):  # noqa: UP042
    WEEKLY = "weekly"
    DAST = "dast"
    POLL = "poll"


class ContentFeed(str, enum.Enum):  # noqa: UP042
    SEMGREP_RULES = "semgrep_rules"
    NUCLEI_TEMPLATES = "nuclei_templates"
    GRYPE_DB = "grype_db"
    NVD_DATA = "nvd_data"


class OutboxState(str, enum.Enum):  # noqa: UP042
    PENDING = "pending"
    PROCESSING = "processing"
    DONE = "done"
    DEAD_LETTER = "dead_letter"


# PostgreSQL type name for every enum above. Keep in sync with the initial migration.
PG_ENUM_NAMES: dict[str, type[enum.Enum]] = {
    "app_type": AppType,
    "target_kind": TargetKind,
    "target_environment": TargetEnvironment,
    "scan_kind": ScanKind,
    "scan_trigger": ScanTrigger,
    "scan_state": ScanState,
    "job_state": JobState,
    "import_state": ImportState,
    "report_kind": ReportKind,
    "verdict": Verdict,
    "review_state": ReviewState,
    "severity": Severity,
    "user_role": UserRole,
    "artifact_kind": ArtifactKind,
    "upload_state": UploadState,
    "credential_kind": CredentialKind,
    "schedule_kind": ScheduleKind,
    "content_feed": ContentFeed,
    "outbox_state": OutboxState,
}

# Job states after which a job never changes again.
JOB_TERMINAL_STATES = frozenset(
    {
        JobState.COMPLETED,
        JobState.COMPLETED_PARTIAL,
        JobState.FAILED,
        JobState.CANCELLED,
        JobState.TIMED_OUT,
    }
)
