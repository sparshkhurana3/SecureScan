"""All models. Importing this package registers every table on ``Base.metadata``.

Every module in this package is imported automatically, so a new model module needs no edit here
(add it to the explicit list below only for the convenience of ``from securescan.db.models import X``).
"""

from __future__ import annotations

import importlib
import pkgutil

from securescan.db.models.applications import Application
from securescan.db.models.artifacts import Artifact, Upload
from securescan.db.models.audit import AuditEvent
from securescan.db.models.content import ContentVersion
from securescan.db.models.credentials import Credential
from securescan.db.models.github import GitHubConnection, RepositoryHead
from securescan.db.models.history import FindingHistory
from securescan.db.models.images import ImageVersion
from securescan.db.models.jobs import ScanJob
from securescan.db.models.outbox import SyncOutbox
from securescan.db.models.policies import Policy
from securescan.db.models.profiles import ScanProfile
from securescan.db.models.reports import Report
from securescan.db.models.scans import Scan
from securescan.db.models.schedules import Schedule
from securescan.db.models.sessions import Session
from securescan.db.models.targets import Target
from securescan.db.models.templates import ReportTemplate
from securescan.db.models.users import User
from securescan.db.models.vendors import Vendor
from securescan.db.models.versions import ApplicationVersion

for _module in pkgutil.iter_modules(__path__):
    importlib.import_module(f"{__name__}.{_module.name}")

__all__ = [
    "Application",
    "ApplicationVersion",
    "Artifact",
    "AuditEvent",
    "ContentVersion",
    "Credential",
    "FindingHistory",
    "GitHubConnection",
    "ImageVersion",
    "Policy",
    "Report",
    "ReportTemplate",
    "RepositoryHead",
    "Scan",
    "ScanJob",
    "ScanProfile",
    "Schedule",
    "Session",
    "SyncOutbox",
    "Target",
    "Upload",
    "User",
    "Vendor",
]
