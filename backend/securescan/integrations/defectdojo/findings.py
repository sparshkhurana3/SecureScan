"""Reading DefectDojo's finding JSON: states, counts and the values SecureScan keeps in history.

This is not a scanner parser. DefectDojo has already parsed, deduplicated and triaged; these helpers
only translate its API shape (booleans, ``vulnerability_ids``, ...) into SecureScan's vocabulary.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import date, datetime, timezone
from typing import Any

from securescan.db.models.enums import Severity

# The booleans DefectDojo keeps on a finding; stored as ``flags_at_scan`` / ``flags_now``.
FLAG_KEYS = (
    "active",
    "verified",
    "duplicate",
    "false_p",
    "out_of_scope",
    "is_mitigated",
    "risk_accepted",
    "under_review",
)

# State vocabulary of finding_history.state_at_scan / state_now (plus "deleted": the finding no longer
# exists in DefectDojo).
STATE_OPEN = "open"
STATE_FALSE_POSITIVE = "false_positive"
STATE_RISK_ACCEPTED = "risk_accepted"
STATE_OUT_OF_SCOPE = "out_of_scope"
STATE_DUPLICATE = "duplicate"
STATE_MITIGATED = "mitigated"
STATE_CLOSED = "closed"
STATE_DELETED = "deleted"

SEVERITY_NAMES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITY_NAMES)}

_SEVERITY_BY_TEXT = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}


def empty_counts() -> dict[str, int]:
    """Counts by severity plus a total, all zero."""
    counts = {name: 0 for name in SEVERITY_NAMES}
    counts["total"] = 0
    return counts


def add_counts(*parts: Mapping[str, Any]) -> dict[str, int]:
    """Sum severity counts (a missing key counts as 0); ``total`` is recomputed."""
    out = empty_counts()
    for part in parts:
        for name in SEVERITY_NAMES:
            out[name] += int(part.get(name, 0) or 0)
    out["total"] = sum(out[name] for name in SEVERITY_NAMES)
    return out


def severity_of(finding: Mapping[str, Any]) -> Severity:
    """DefectDojo writes ``Critical``, ``High``, ``Medium``, ``Low``, ``Info``; unknown text is Info."""
    text = str(finding.get("severity") or "").strip().lower()
    return _SEVERITY_BY_TEXT.get(text, Severity.INFO)


def finding_flags(finding: Mapping[str, Any]) -> dict[str, bool]:
    return {key: bool(finding.get(key)) for key in FLAG_KEYS}


def is_open(flags: Mapping[str, Any]) -> bool:
    """Open = active and not duplicate, false positive, out of scope or risk accepted."""
    return bool(
        flags.get("active")
        and not flags.get("duplicate")
        and not flags.get("false_p")
        and not flags.get("out_of_scope")
        and not flags.get("risk_accepted")
        and not flags.get("is_mitigated")
    )


def state_from_flags(flags: Mapping[str, Any]) -> str:
    """One word for the triage state. False positive wins over everything else, then risk acceptance,
    out of scope, duplicate; a mitigated finding is ``mitigated``; an inactive finding with none of
    these is ``closed``."""
    if flags.get("false_p"):
        return STATE_FALSE_POSITIVE
    if flags.get("risk_accepted"):
        return STATE_RISK_ACCEPTED
    if flags.get("out_of_scope"):
        return STATE_OUT_OF_SCOPE
    if flags.get("duplicate"):
        return STATE_DUPLICATE
    if flags.get("is_mitigated"):
        return STATE_MITIGATED
    if flags.get("active"):
        return STATE_OPEN
    return STATE_CLOSED


def finding_state(finding: Mapping[str, Any]) -> str:
    return state_from_flags(finding_flags(finding))


def severity_counts(findings: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    """Open findings by severity (the verdict's definition of "open")."""
    counts = empty_counts()
    for finding in findings:
        if is_open(finding_flags(finding)):
            counts[severity_of(finding).value] += 1
    counts["total"] = sum(counts[name] for name in SEVERITY_NAMES)
    return counts


def counts_from_statistics(after: Mapping[str, Any]) -> dict[str, int]:
    """Open counts from the ``statistics.after`` block of an import response
    (``{"critical": {"active": 1, ...}, ...}``). Used as a cross-check of the findings read."""
    counts = empty_counts()
    for name in SEVERITY_NAMES:
        block = after.get(name)
        if isinstance(block, Mapping):
            counts[name] = int(block.get("active", 0) or 0)
    counts["total"] = sum(counts[name] for name in SEVERITY_NAMES)
    return counts


def parse_datetime(value: Any) -> datetime | None:
    """DefectDojo sends ISO 8601 date-times (``...Z``) and plain dates; both become aware UTC."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=timezone.utc)
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def closed_by_import(finding: Mapping[str, Any], since: datetime) -> bool:
    """True for a mitigated finding that this import closed.

    ``last_status_update`` (when DefectDojo last changed the status) is compared with the import's
    start; if a release does not send it, the ``mitigated`` date is compared by calendar day.
    """
    if not finding.get("is_mitigated"):
        return False
    changed = parse_datetime(finding.get("last_status_update"))
    if changed is not None:
        return changed >= since
    mitigated = parse_datetime(finding.get("mitigated"))
    if mitigated is not None:
        return mitigated.date() >= since.date()
    return False


def belongs_to_scan(finding: Mapping[str, Any], since: datetime) -> bool:
    """History for a job holds what the Test contains now except findings closed by earlier imports:
    everything not mitigated (open, false positive, accepted, duplicate, ...) plus what this import
    closed."""
    if not finding.get("is_mitigated"):
        return True
    return closed_by_import(finding, since)


def finding_cwe(finding: Mapping[str, Any]) -> int | None:
    """First CWE number; DefectDojo uses 0 for "none" and (3.2+) may send ``cwes``."""
    candidates: list[Any] = [finding.get("cwe")]
    cwes = finding.get("cwes")
    if isinstance(cwes, list):
        candidates.extend(cwes)
    for value in candidates:
        if isinstance(value, bool):
            continue
        if isinstance(value, int) and value > 0:
            return value
        if isinstance(value, str) and value.strip().isdigit() and int(value) > 0:
            return int(value)
    return None


def finding_cve(finding: Mapping[str, Any]) -> str | None:
    """A CVE id from ``vulnerability_ids`` (``[{"vulnerability_id": "CVE-..."}]`` or strings), else
    the legacy ``cve`` field, else the first id of any kind."""
    ids: list[str] = []
    raw = finding.get("vulnerability_ids")
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, str):
                ids.append(item)
            elif isinstance(item, Mapping) and item.get("vulnerability_id"):
                ids.append(str(item["vulnerability_id"]))
    legacy = finding.get("cve")
    if isinstance(legacy, str) and legacy:
        ids.append(legacy)
    for candidate in ids:
        if candidate.upper().startswith("CVE-"):
            return candidate[:64]
    return ids[0][:64] if ids else None


def finding_url(finding: Mapping[str, Any]) -> str | None:
    """Best-effort URL of a DAST finding. DefectDojo 3.0 replaced endpoints by locations, so several
    shapes are accepted: a string, a list of strings, or a list of objects with a url-like key."""
    for key in ("url", "location"):
        value = finding.get(key)
        if isinstance(value, str) and value:
            return value
    for key in ("locations", "endpoints"):
        items = finding.get(key)
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, str) and item:
                return item
            if isinstance(item, Mapping):
                for sub in ("url", "location", "host"):
                    value = item.get(sub)
                    if isinstance(value, str) and value:
                        return value
    return None


def finding_cvss(finding: Mapping[str, Any]) -> float | None:
    for key in ("cvssv3_score", "cvssv4_score"):
        value = finding.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value)
            except ValueError:
                continue
    return None


def _clip(value: Any, limit: int) -> str | None:
    if value is None or value == "":
        return None
    return str(value)[:limit]


def _line(finding: Mapping[str, Any]) -> int | None:
    value = finding.get("line")
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return None


def history_values(finding: Mapping[str, Any]) -> dict[str, Any]:
    """The finding-derived columns of a ``FindingHistory`` row (without ids, scan context or times)."""
    flags = finding_flags(finding)
    state = state_from_flags(flags)
    return {
        "dd_finding_id": int(finding["id"]),
        "hash_code": _clip(finding.get("hash_code"), 128),
        "severity": severity_of(finding),
        "title": str(finding.get("title") or "(no title)"),
        "cwe": finding_cwe(finding),
        "cve": finding_cve(finding),
        "cvss": finding_cvss(finding),
        "component": _clip(finding.get("component_name"), 500),
        "component_version": _clip(finding.get("component_version"), 255),
        "file_path": _clip(finding.get("file_path"), 4000),
        "line": _line(finding),
        "url": _clip(finding_url(finding), 4000),
        "state_at_scan": state,
        "flags_at_scan": flags,
        "state_now": state,
        "flags_now": dict(flags),
    }
