"""The report snapshot: the frozen data one report is rendered from.

``build_snapshot`` turns plain scan facts (the ``Scan`` and ``ScanJob`` rows, the findings read back
from DefectDojo through the finding history, the application, version and vendor) into a pydantic
``Snapshot``. The snapshot is stored as a JSON artifact, its SHA-256 is the report hash, and both
the portal HTML and the PDF are rendered from it, so a report can be reproduced exactly later.

The builder takes duck-typed objects (ORM rows or ``SimpleNamespace`` in tests) and reads only the
attributes named below with ``getattr`` defaults, so it never touches the database and needs no
session. It does not parse scanner output: every finding already came from DefectDojo.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from securescan.domain import mappings
from securescan.logging import scrub

SCHEMA_VERSION = 1

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_LABELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}
VERDICT_LABELS = {
    "pass": "Pass",
    "conditional": "Conditional pass",
    "fail": "Fail",
    "pending": "Pending",
}
STATE_LABELS = {
    "open": "Open",
    "false_positive": "False positive",
    "risk_accepted": "Risk accepted",
    "out_of_scope": "Out of scope",
    "duplicate": "Duplicate",
    "mitigated": "Mitigated",
    "closed": "Closed",
    "deleted": "Deleted in DefectDojo",
}
TOOL_LABELS = {
    "semgrep": "Semgrep CE",
    "sonarqube": "SonarQube Community Build",
    "spotbugs": "SpotBugs with Find Security Bugs",
    "gitleaks": "Gitleaks",
    "syft": "Syft",
    "grype": "Grype",
    "syft-grype": "Syft and Grype",
    "dependency-check": "OWASP Dependency-Check",
    "zap": "ZAP",
    "nuclei": "Nuclei",
}
# Tools that report known vulnerabilities in components: counted under OWASP A06.
# `syft-grype` is the catalogue (and job) name; FindingHistory.tool carries it.
COMPONENT_TOOLS = frozenset({"grype", "syft-grype", "dependency-check"})
# Tools whose finding text may carry a secret: only file, line and rule are shown.
SECRET_TOOLS = frozenset({"gitleaks"})

OWASP_OTHER_ID = "OTHER"
OWASP_OTHER_NAME = "Other CWE, not in the Top 10 mapping"
OWASP_NO_CWE_ID = "NOCWE"
OWASP_NO_CWE_NAME = "No CWE recorded"
COMPONENT_CATEGORY_ID = "A06"

MAX_TEXT_CHARS = 2000
MAX_TRIAGED_ROWS = 500
MAX_DELTA_ROWS = 100
DEFAULT_DETAIL_LIMIT = 300

# Design, "Known limits to state in every report". Keep this text identical to the design.
KNOWN_LIMITS = (
    "Semgrep CE traces taint only within one function, and SonarQube Community Build has no "
    "taint analysis. Find Security Bugs closes that gap for Java bytecode, the .NET analyzers "
    "close it for C# once builds run, and for JavaScript, TypeScript and Python no free, "
    "maintained tool traces taint across files.",
    "Syft and Grype see only the dependencies declared in manifests and lock files when scanning "
    "source. A zip without lock files yields a thin result.",
    "Dependency-Check identifies components by fuzzy matching to NVD entries and produces both "
    "false positives and false negatives by its own account.",
    "Gitleaks is in maintenance mode: security patches only. Its author's successor, Betterleaks, "
    "replaces it once DefectDojo ships a parser for it. The swap is a configuration change.",
    "Semgrep's rules and SonarQube's analyzers are free but not open source. Reports stay internal "
    "by default, and no scanner output is fed to external AI services, which the Sonar licence "
    "forbids.",
)

SONAR_MEASURE_LABELS = {
    "bugs": "Bugs",
    "vulnerabilities": "Vulnerabilities",
    "security_hotspots": "Security hotspots",
    "code_smells": "Code smells",
    "coverage": "Coverage (%)",
    "duplicated_lines_density": "Duplicated lines (%)",
    "ncloc": "Lines of code",
    "reliability_rating": "Reliability rating",
    "security_rating": "Security rating",
    "sqale_rating": "Maintainability rating",
    "sqale_index": "Technical debt (minutes)",
}


# --------------------------------------------------------------------------- models


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0

    @classmethod
    def from_counter(cls, counter: Counter[str]) -> SeverityCounts:
        values = {s: int(counter.get(s, 0)) for s in SEVERITIES}
        return cls(**values, total=sum(values.values()))


class ToolInfo(BaseModel):
    name: str
    label: str
    version: str | None = None
    image: str | None = None
    image_digest: str | None = None
    state: str = ""
    partial: bool = False
    content_versions: dict[str, str] = Field(default_factory=dict)


class VendorInfo(BaseModel):
    name: str
    product: str | None = None
    hosting: str | None = None
    contact_name: str | None = None
    contact_email: str | None = None
    risk_tier: str | None = None


class VendorScope(BaseModel):
    """What was assessed and under which hosting and authorization rules (vendor reports only)."""

    hosting: str = ""
    hosting_label: str = ""
    target_kind: str = ""
    artefacts: list[str] = Field(default_factory=list)
    environment: str = ""
    environment_label: str = ""
    rule: str = ""
    authorization_required: bool = False
    authorization_state: str = ""
    authorized_from: str = ""
    authorized_until: str = ""
    authorization_contact: str = ""
    conditions_rule: str = ""


class Header(BaseModel):
    report_ref: str = ""
    title: str = ""
    kind: str = "application"
    application_name: str = ""
    application_type: str = ""
    criticality: str | None = None
    classification_label: str = ""
    version_label: str = ""
    version_kind: str = ""
    commit_sha: str | None = None
    source_ref: str | None = None
    source_digest: str | None = None
    scan_id: str = ""
    scan_kind: str = ""
    scan_mode: str | None = None
    profile: str = ""
    scan_date: str = ""
    generated_at: str = ""
    tools: list[ToolInfo] = Field(default_factory=list)
    template_name: str = ""
    template_version: int = 0
    mapping_versions: dict[str, str] = Field(default_factory=dict)
    review_state: str = "automatic"
    review_label: str = "Automatic, not yet reviewed"


class ToolCount(BaseModel):
    tool: str
    label: str
    counts: SeverityCounts


class CategoryCount(BaseModel):
    id: str
    name: str
    count: int = 0
    critical: int = 0
    high: int = 0


class Top25Count(BaseModel):
    rank: int
    cwe: int
    name: str
    count: int = 0


class BriefFinding(BaseModel):
    key: str
    severity: str
    severity_label: str
    title: str
    tool: str
    location: str = ""
    note: str = ""


class Delta(BaseModel):
    previous_ref: str = ""
    previous_scan_date: str = ""
    previous_version_label: str = ""
    fixed: int = 0
    remaining: int = 0
    new: int = 0
    fixed_findings: list[BriefFinding] = Field(default_factory=list)
    new_findings: list[BriefFinding] = Field(default_factory=list)
    # Vendor assessments (M10, ``securescan.domain.vendors``): the delta of two versions computed
    # from the finding history by DefectDojo hash code. Empty for application reports.
    reopened: int = 0
    triaged: int = 0
    remaining_findings: list[BriefFinding] = Field(default_factory=list)
    reopened_findings: list[BriefFinding] = Field(default_factory=list)
    triaged_findings: list[BriefFinding] = Field(default_factory=list)
    compared_tools: list[str] = Field(default_factory=list)
    skipped_tools: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class Summary(BaseModel):
    verdict: str = "pending"
    verdict_label: str = "Pending"
    verdict_explanation: str = ""
    overall_risk: str = "None identified"
    counts: SeverityCounts = Field(default_factory=SeverityCounts)
    by_tool: list[ToolCount] = Field(default_factory=list)
    by_owasp: list[CategoryCount] = Field(default_factory=list)
    owasp_max: int = 0
    cwe_top25: list[Top25Count] = Field(default_factory=list)
    cwe_top25_present: int = 0
    triaged_out: int = 0
    top_risks: list[str] = Field(default_factory=list)
    delta: Delta | None = None


class FindingItem(BaseModel):
    key: str
    index: int
    tool: str
    tool_label: str
    severity: str
    severity_label: str
    title: str
    cwe: int | None = None
    cwe_label: str = ""
    owasp_id: str = ""
    owasp_name: str = ""
    top25_rank: int | None = None
    cve: str | None = None
    cvss: float | None = None
    component: str | None = None
    component_version: str | None = None
    file_path: str | None = None
    line: int | None = None
    url: str | None = None
    location: str = ""
    description: str = ""
    mitigation: str = ""
    state: str = "open"
    state_label: str = "Open"
    hash_code: str | None = None
    vs_previous: str = ""  # "", "new" or "remaining"


class TriagedItem(BaseModel):
    key: str
    tool_label: str
    severity: str
    severity_label: str
    title: str
    state: str
    state_label: str
    location: str = ""
    cwe: int | None = None
    hash_code: str | None = None


class QualityMeasure(BaseModel):
    key: str
    label: str
    value: str


class QualityCondition(BaseModel):
    metric: str
    status: str = ""
    actual: str = ""
    threshold: str = ""


class CodeQuality(BaseModel):
    available: bool = False
    quality_gate: str = ""
    quality_gate_label: str = ""
    conditions: list[QualityCondition] = Field(default_factory=list)
    measures: list[QualityMeasure] = Field(default_factory=list)
    note: str = ""


class SbomFile(BaseModel):
    artifact_id: str
    filename: str = ""
    sha256: str = ""
    size_bytes: int = 0


class Components(BaseModel):
    available: bool = False
    count: int | None = None
    sbom_files: list[SbomFile] = Field(default_factory=list)
    note: str = ""


class CoverageEntry(BaseModel):
    tool: str
    label: str
    status: str  # ran | partial | failed | timed out | cancelled | skipped | not finished
    reason: str = ""
    exclusions: list[str] = Field(default_factory=list)


class Coverage(BaseModel):
    entries: list[CoverageEntry] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    complete: bool = True


class Methodology(BaseModel):
    paragraphs: list[str] = Field(default_factory=list)


class ConditionItem(BaseModel):
    finding_hash: str
    finding_title: str = ""
    severity: str = ""
    severity_label: str = ""
    location: str = ""
    deadline: str = ""


class Review(BaseModel):
    state: str = "automatic"
    reviewer: str = ""
    reviewed_at: str = ""
    proposed_verdict: str = "pending"
    proposed_verdict_label: str = "Pending"
    verdict: str = "pending"
    verdict_label: str = "Pending"
    overridden: bool = False
    override_reason: str = ""
    conditions: list[ConditionItem] = Field(default_factory=list)
    internal_notes: str = ""


class Snapshot(BaseModel):
    schema_version: int = SCHEMA_VERSION
    kind: str = "application"
    vendor_copy: bool = False
    header: Header = Field(default_factory=Header)
    vendor: VendorInfo | None = None
    vendor_scope: VendorScope | None = None
    summary: Summary = Field(default_factory=Summary)
    findings: list[FindingItem] = Field(default_factory=list)
    detail_limit: int = DEFAULT_DETAIL_LIMIT
    triaged: list[TriagedItem] = Field(default_factory=list)
    code_quality: CodeQuality = Field(default_factory=CodeQuality)
    components: Components = Field(default_factory=Components)
    coverage: Coverage = Field(default_factory=Coverage)
    methodology: Methodology = Field(default_factory=Methodology)
    known_limits: list[str] = Field(default_factory=lambda: list(KNOWN_LIMITS))
    review: Review = Field(default_factory=Review)


@dataclass
class PreviousReport:
    """What the delta needs from the report that came before: its open findings, by key."""

    ref: str = ""
    scan_date: str = ""
    version_label: str = ""
    findings: dict[str, BriefFinding] = field(default_factory=dict)


@dataclass
class ReviewInput:
    state: str = "automatic"
    reviewer: str = ""
    reviewed_at: datetime | None = None
    proposed_verdict: str = "pending"
    verdict: str = "pending"
    overridden: bool = False
    override_reason: str = ""
    conditions: Sequence[dict[str, Any]] = ()
    internal_notes: str = ""


# --------------------------------------------------------------------------- helpers


def enum_value(value: Any, default: str = "") -> str:
    """The string of an enum member or plain string (``None`` gives ``default``)."""
    if value is None:
        return default
    return str(getattr(value, "value", value))


def _g(obj: Any, name: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def iso(value: datetime | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def tool_key(name: str) -> str:
    return (name or "").strip().lower().replace("_", "-")


def tool_label(name: str) -> str:
    return TOOL_LABELS.get(tool_key(name), name)


def severity_key(value: Any) -> str:
    key = enum_value(value, "info").lower()
    return key if key in SEVERITIES else "info"


def clip(text: Any, limit: int = MAX_TEXT_CHARS) -> str:
    """Scrub token shapes and cap the length (evidence can be very long)."""
    if text is None:
        return ""
    value = scrub(str(text)).strip()
    if len(value) > limit:
        value = value[: limit - 3].rstrip() + "..."
    return value


def finding_location(file_path: str | None, line: int | None, url: str | None,
                     component: str | None, component_version: str | None) -> str:
    if file_path:
        return f"{file_path}:{line}" if line else str(file_path)
    if url:
        return str(url)
    if component:
        return f"{component} {component_version}".strip() if component_version else str(component)
    return ""


def finding_key(hash_code: str | None, tool: str, cwe: int | None, title: str,
                file_path: str | None, component: str | None, cve: str | None) -> str:
    """Identity of a finding across reports: DefectDojo's hash code, else a digest of its fields."""
    if hash_code:
        return str(hash_code)
    raw = "|".join(
        [tool_key(tool), str(cwe or ""), title or "", file_path or "", component or "", cve or ""]
    )
    return "x" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:40]


def review_label(state: str) -> str:
    return "Reviewed by an analyst" if state == "reviewed" else "Automatic, not yet reviewed"


def categorise(cwe: int | None, tool: str) -> tuple[str, str]:
    """OWASP Top 10 bucket (id, name) of a finding.

    Dependency scanners (Grype, Dependency-Check) report vulnerable components, so their findings
    count under A06 whatever CWE the CVE carries. Otherwise the CWE decides; a CWE outside the
    mapping or no CWE at all goes to a named catch-all bucket so the counts always add up.
    """
    if tool_key(tool) in COMPONENT_TOOLS:
        for category in mappings.owasp_categories():
            if category.id == COMPONENT_CATEGORY_ID:
                return category.id, category.name
    category_row = mappings.owasp_category_for_cwe(cwe)
    if category_row is not None:
        return category_row.id, category_row.name
    if cwe is None:
        return OWASP_NO_CWE_ID, OWASP_NO_CWE_NAME
    return OWASP_OTHER_ID, OWASP_OTHER_NAME


def canonical_json(snapshot: Snapshot) -> bytes:
    """Stable serialisation of a snapshot (sorted keys, no whitespace); its SHA-256 is the hash."""
    data = snapshot.model_dump(mode="json")
    text = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8")


def snapshot_sha256(snapshot: Snapshot) -> str:
    return hashlib.sha256(canonical_json(snapshot)).hexdigest()


def load_snapshot(data: bytes | str) -> Snapshot:
    return Snapshot.model_validate_json(data)


# --------------------------------------------------------------------------- findings


def _finding_text(row: Any, name: str, texts: Mapping[int, Mapping[str, Any]] | None = None) -> str:
    """Description or mitigation of a finding.

    The history table does not keep them, so the report job reads them from DefectDojo and passes
    them in ``texts`` (``{dd_finding_id: {"description": ..., "mitigation": ...}}``). A row (or its
    flags) that carries the text itself works too, which is how the unit tests supply it.
    """
    if texts:
        found = texts.get(int(_g(row, "dd_finding_id", 0) or 0))
        if found and found.get(name):
            return str(found[name])
    direct = _g(row, name)
    if direct:
        return str(direct)
    for flags_name in ("flags_now", "flags_at_scan"):
        flags = _g(row, flags_name)
        if isinstance(flags, dict) and flags.get(name):
            return str(flags[name])
    return ""


def _finding_item(
    row: Any,
    index: int,
    vs_previous: str,
    texts: Mapping[int, Mapping[str, Any]] | None = None,
) -> FindingItem:
    tool = str(_g(row, "tool", "") or "")
    title = clip(_g(row, "title", ""), 500) or "(no title)"
    cwe = mappings.parse_cwe(_g(row, "cwe"))
    owasp_id, owasp_name = categorise(cwe, tool)
    top25 = mappings.top25_entry_for_cwe(cwe)
    file_path = _g(row, "file_path")
    line = _g(row, "line")
    url = _g(row, "url")
    component = _g(row, "component")
    component_version = _g(row, "component_version")
    state = enum_value(_g(row, "state_now") or _g(row, "state_at_scan"), "open")
    secret_tool = tool_key(tool) in SECRET_TOOLS
    hash_code = _g(row, "hash_code")
    cvss = _g(row, "cvss")
    return FindingItem(
        key=finding_key(hash_code, tool, cwe, title, file_path, component, _g(row, "cve")),
        index=index,
        tool=tool,
        tool_label=tool_label(tool),
        severity=severity_key(_g(row, "severity")),
        severity_label=SEVERITY_LABELS[severity_key(_g(row, "severity"))],
        title=title,
        cwe=cwe,
        cwe_label=f"CWE-{cwe}" if cwe else "",
        owasp_id=owasp_id,
        owasp_name=owasp_name,
        top25_rank=top25.rank if top25 else None,
        cve=_g(row, "cve") or None,
        cvss=float(cvss) if cvss is not None else None,
        component=component or None,
        component_version=component_version or None,
        file_path=file_path or None,
        line=int(line) if line else None,
        url=url or None,
        location=finding_location(file_path, line, url, component, component_version),
        description="" if secret_tool else clip(_finding_text(row, "description", texts)),
        mitigation="" if secret_tool else clip(_finding_text(row, "mitigation", texts)),
        state=state,
        state_label=STATE_LABELS.get(state, state.replace("_", " ").capitalize()),
        hash_code=hash_code or None,
        vs_previous=vs_previous,
    )


def _severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES)


def _brief(item: FindingItem) -> BriefFinding:
    return BriefFinding(
        key=item.key,
        severity=item.severity,
        severity_label=item.severity_label,
        title=item.title,
        tool=item.tool_label,
        location=item.location,
    )


def previous_from_snapshot(snapshot: Snapshot) -> PreviousReport:
    """The part of an earlier snapshot the delta needs."""
    return PreviousReport(
        ref=snapshot.header.report_ref,
        scan_date=snapshot.header.scan_date,
        version_label=snapshot.header.version_label,
        findings={item.key: _brief(item) for item in snapshot.findings},
    )


def _delta(current: Sequence[FindingItem], previous: PreviousReport) -> Delta:
    current_keys = {item.key for item in current}
    previous_keys = set(previous.findings)
    fixed_keys = previous_keys - current_keys
    new_keys = current_keys - previous_keys
    fixed = sorted(
        (previous.findings[k] for k in fixed_keys),
        key=lambda b: (_severity_rank(b.severity), b.title),
    )
    new_items = sorted(
        (item for item in current if item.key in new_keys),
        key=lambda i: (_severity_rank(i.severity), i.title),
    )
    return Delta(
        previous_ref=previous.ref,
        previous_scan_date=previous.scan_date,
        previous_version_label=previous.version_label,
        fixed=len(fixed_keys),
        remaining=len(current_keys & previous_keys),
        new=len(new_keys),
        fixed_findings=fixed[:MAX_DELTA_ROWS],
        new_findings=[_brief(i) for i in new_items[:MAX_DELTA_ROWS]],
    )


# --------------------------------------------------------------------------- sections


def _job_status(job: Any) -> str:
    state = enum_value(_g(job, "state"))
    partial = bool(_g(job, "partial", False))
    if state == "completed_partial" or (state == "completed" and partial):
        return "partial"
    return {
        "completed": "ran",
        "failed": "failed",
        "timed_out": "timed out",
        "cancelled": "cancelled",
    }.get(state, "not finished")


def _coverage(scan: Any, jobs: Sequence[Any], requested: Sequence[str]) -> Coverage:
    entries: list[CoverageEntry] = []
    seen: set[str] = set()
    complete = True
    for job in jobs:
        tool = str(_g(job, "tool", ""))
        seen.add(tool_key(tool))
        status = _job_status(job)
        reasons: list[str] = []
        for text in (_g(job, "outcome_reason"), _g(job, "coverage_note")):
            if text and str(text) not in reasons:
                reasons.append(clip(text, 400))
        if enum_value(_g(job, "import_state")) == "failed":
            reasons.append("Results were not imported into DefectDojo.")
        if status != "ran":
            complete = False
        exclusions = [clip(e if isinstance(e, str) else json.dumps(e, sort_keys=True), 200)
                      for e in (_g(job, "applied_exclusions") or [])]
        entries.append(
            CoverageEntry(
                tool=tool,
                label=tool_label(tool),
                status=status,
                reason=" ".join(reasons),
                exclusions=exclusions,
            )
        )
    for tool in requested:
        if tool_key(str(tool)) not in seen:
            complete = False
            entries.append(
                CoverageEntry(
                    tool=str(tool),
                    label=tool_label(str(tool)),
                    status="skipped",
                    reason="The tool was requested but did not run.",
                )
            )
    notes: list[str] = []
    for item in _g(scan, "coverage_notes") or []:
        if isinstance(item, dict):
            text = item.get("note") or item.get("text") or item.get("reason") or ""
            tool = item.get("tool")
            text = f"{tool}: {text}" if tool and text else str(text)
        else:
            text = str(item)
        if text:
            notes.append(clip(text, 400))
    return Coverage(entries=entries, notes=notes, complete=complete and not notes)


def _plain(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:g}"
    return str(value)


def _code_quality(jobs: Sequence[Any]) -> CodeQuality:
    """SonarQube quality gate and measures, from the SonarQube job's ``options`` JSON.

    Accepted shapes (M8 fills them): ``options["quality_gate"]`` is a status string or
    ``{"status": "OK|ERROR|WARN", "conditions": [{"metric", "status", "actual", "threshold"}]}``;
    ``options["measures"]`` is ``{metric: value}`` or ``[{"metric": ..., "value": ...}]``. The same
    keys are also read below ``options["sonarqube"]`` or ``options["metrics"]``.
    """
    job = next((j for j in jobs if tool_key(str(_g(j, "tool", ""))) == "sonarqube"), None)
    if job is None:
        return CodeQuality(available=False, note="SonarQube did not run for this scan.")
    options = _g(job, "options") or {}
    if not isinstance(options, dict):
        options = {}
    for nested in ("sonarqube", "metrics"):
        inner = options.get(nested)
        if isinstance(inner, dict):
            options = {**inner, **options}
    gate = options.get("quality_gate")
    measures = options.get("measures")
    if gate is None and measures is None:
        return CodeQuality(
            available=False, note="SonarQube ran, but no quality gate or measures were recorded."
        )
    status = ""
    conditions: list[QualityCondition] = []
    if isinstance(gate, dict):
        status = str(gate.get("status") or gate.get("projectStatus") or "")
        for cond in gate.get("conditions") or []:
            if isinstance(cond, dict):
                conditions.append(
                    QualityCondition(
                        metric=str(cond.get("metric") or cond.get("metricKey") or ""),
                        status=str(cond.get("status") or ""),
                        actual=_plain(cond.get("actual") or cond.get("actualValue") or ""),
                        threshold=_plain(cond.get("threshold") or cond.get("errorThreshold") or ""),
                    )
                )
    elif gate is not None:
        status = str(gate)
    label = {"OK": "Passed", "ERROR": "Failed", "WARN": "Warning", "NONE": "Not computed"}.get(
        status.upper(), status or "Unknown"
    )
    rows: list[QualityMeasure] = []
    pairs: list[tuple[str, Any]] = []
    if isinstance(measures, dict):
        pairs = list(measures.items())
    elif isinstance(measures, list):
        for entry in measures:
            if isinstance(entry, dict) and (entry.get("metric") or entry.get("key")):
                pairs.append((str(entry.get("metric") or entry.get("key")), entry.get("value")))
    for key, value in pairs:
        if value is None:
            continue
        rows.append(
            QualityMeasure(
                key=str(key),
                label=SONAR_MEASURE_LABELS.get(str(key), str(key).replace("_", " ").capitalize()),
                value=_plain(value),
            )
        )
    return CodeQuality(
        available=True,
        quality_gate=status,
        quality_gate_label=label,
        conditions=conditions,
        measures=rows,
    )


def _components(
    sbom_artifacts: Sequence[Any], count: int | None, jobs: Sequence[Any]
) -> Components:
    files = [
        SbomFile(
            artifact_id=str(_g(a, "id", "")),
            filename=str(_g(a, "filename", "") or ""),
            sha256=str(_g(a, "sha256", "") or ""),
            size_bytes=int(_g(a, "size_bytes", 0) or 0),
        )
        for a in sbom_artifacts
    ]
    if count is None:
        for job in jobs:
            options = _g(job, "options") or {}
            if isinstance(options, dict) and isinstance(options.get("component_count"), int):
                count = int(options["component_count"])
                break
    if count is None and not files:
        return Components(available=False, note="No software bill of materials was produced.")
    return Components(available=True, count=count, sbom_files=files)


def _overall_risk(counts: SeverityCounts) -> str:
    if counts.critical:
        return "Critical"
    if counts.high:
        return "High"
    if counts.medium:
        return "Medium"
    if counts.low or counts.info:
        return "Low"
    return "None identified"


def _explanation(verdict: str, counts: SeverityCounts, detail: Any) -> str:
    if isinstance(detail, dict):
        text = detail.get("explanation") or detail.get("reason") or detail.get("summary")
        if isinstance(text, str) and text.strip():
            return clip(text, 600)
    if verdict == "pending":
        return "No verdict has been computed yet."
    plural = "findings" if counts.high != 1 else "finding"
    if verdict == "fail":
        return (
            f"The default policy found {counts.critical} open Critical and {counts.high} open "
            f"High {plural}."
        )
    if verdict == "conditional":
        return (
            f"The default policy found {counts.high} open High {plural}; each needs a remediation "
            "date agreed with the vendor."
        )
    return "The default policy found no open Critical or High findings."


def _methodology(header: Header, vendor: bool) -> Methodology:
    versions = header.mapping_versions
    parts = [
        "Each tool in the list above ran as a separate, isolated job. Raw tool reports were "
        "imported into DefectDojo, which is the only place findings are parsed and triaged; this "
        "report reads the findings back from DefectDojo and freezes them with a hash.",
        f"Findings are mapped to OWASP Top 10 ({versions.get('owasp_top10', '')}) and the CWE "
        f"Top 25 ({versions.get('cwe_top25', '')}) by their CWE. Findings from dependency "
        "scanners (Grype, Dependency-Check) are counted under A06, Vulnerable and Outdated "
        "Components. A finding without a CWE is listed under its own heading.",
        "Counts and the verdict include open findings only. Findings an analyst marked false "
        "positive, risk accepted, out of scope or duplicate in DefectDojo are listed separately.",
    ]
    if vendor:
        parts.append(
            "The verdict is proposed by the default verdict policy and then confirmed or "
            "overridden, with a recorded reason, by the reviewing analyst."
        )
    return Methodology(paragraphs=parts)


def _review_model(review: ReviewInput | None, verdict: str, vendor_copy: bool,
                  open_findings: Sequence[FindingItem]) -> Review:
    if review is None:
        label = VERDICT_LABELS.get(verdict, verdict)
        return Review(
            state="automatic",
            proposed_verdict=verdict,
            proposed_verdict_label=label,
            verdict=verdict,
            verdict_label=label,
        )
    by_key = {item.key: item for item in open_findings}
    conditions: list[ConditionItem] = []
    for cond in review.conditions:
        key = str(cond.get("finding_hash") or "")
        item = by_key.get(key)
        conditions.append(
            ConditionItem(
                finding_hash=key,
                finding_title=item.title if item else clip(cond.get("finding_title") or "", 300),
                severity=item.severity if item else "",
                severity_label=item.severity_label if item else "",
                location=item.location if item else "",
                deadline=str(cond.get("deadline") or ""),
            )
        )
    return Review(
        state=review.state,
        reviewer=review.reviewer,
        reviewed_at=iso(review.reviewed_at),
        proposed_verdict=review.proposed_verdict,
        proposed_verdict_label=VERDICT_LABELS.get(review.proposed_verdict, review.proposed_verdict),
        verdict=review.verdict,
        verdict_label=VERDICT_LABELS.get(review.verdict, review.verdict),
        overridden=review.overridden,
        override_reason=clip(review.override_reason, 1000),
        conditions=conditions,
        internal_notes="" if vendor_copy else clip(review.internal_notes, 2000),
    )


# --------------------------------------------------------------------------- the builder


def build_snapshot(
    *,
    kind: str,
    application: Any,
    version: Any,
    scan: Any,
    jobs: Sequence[Any],
    findings: Iterable[Any],
    vendor: Any = None,
    template_name: str = "",
    template_version: int = 0,
    report_ref: str = "",
    generated_at: datetime | None = None,
    previous: PreviousReport | None = None,
    sbom_artifacts: Sequence[Any] = (),
    sbom_component_count: int | None = None,
    review: ReviewInput | None = None,
    vendor_copy: bool = False,
    detail_limit: int = DEFAULT_DETAIL_LIMIT,
    finding_texts: Mapping[int, Mapping[str, Any]] | None = None,
) -> Snapshot:
    """Freeze the facts of one scan into a ``Snapshot``.

    ``findings`` are the finding-history rows of the scan (all states); the open ones are counted
    and detailed, the others are listed separately. ``verdict`` is ``scan.verdict`` (set by the
    policy when the scan finished) unless a ``review`` carries the reviewed verdict.
    """
    open_rows: list[Any] = []
    other_rows: list[Any] = []
    for row in findings:
        state = enum_value(_g(row, "state_now") or _g(row, "state_at_scan"), "open")
        (open_rows if state == "open" else other_rows).append(row)

    previous_keys = set(previous.findings) if previous else set()
    open_items: list[FindingItem] = []
    for row in open_rows:
        item = _finding_item(row, 0, "", finding_texts)
        if previous is not None:
            item.vs_previous = "remaining" if item.key in previous_keys else "new"
        open_items.append(item)
    open_items.sort(key=lambda i: (_severity_rank(i.severity), i.tool, i.title, i.location))
    for position, item in enumerate(open_items, start=1):
        item.index = position

    triaged_items: list[TriagedItem] = []
    for row in other_rows:
        item = _finding_item(row, 0, "")
        triaged_items.append(
            TriagedItem(
                key=item.key,
                tool_label=item.tool_label,
                severity=item.severity,
                severity_label=item.severity_label,
                title=item.title,
                state=item.state,
                state_label=item.state_label,
                location=item.location,
                cwe=item.cwe,
                hash_code=item.hash_code,
            )
        )
    triaged_items.sort(key=lambda t: (_severity_rank(t.severity), t.title))

    counter: Counter[str] = Counter(i.severity for i in open_items)
    counts = SeverityCounts.from_counter(counter)

    # per tool: every tool that ran appears, even with zero findings
    tool_order: list[str] = []
    for job in jobs:
        name = str(_g(job, "tool", ""))
        if name and name not in tool_order:
            tool_order.append(name)
    for item in open_items:
        if item.tool not in tool_order:
            tool_order.append(item.tool)
    by_tool = [
        ToolCount(
            tool=name,
            label=tool_label(name),
            counts=SeverityCounts.from_counter(
                Counter(i.severity for i in open_items if i.tool == name)
            ),
        )
        for name in tool_order
    ]

    # per OWASP category: all ten always, catch-all buckets only when used
    owasp_rows: list[CategoryCount] = []
    for category in mappings.owasp_categories():
        members = [i for i in open_items if i.owasp_id == category.id]
        owasp_rows.append(
            CategoryCount(
                id=category.id,
                name=category.name,
                count=len(members),
                critical=sum(1 for i in members if i.severity == "critical"),
                high=sum(1 for i in members if i.severity == "high"),
            )
        )
    for extra_id, extra_name in (
        (OWASP_OTHER_ID, OWASP_OTHER_NAME),
        (OWASP_NO_CWE_ID, OWASP_NO_CWE_NAME),
    ):
        members = [i for i in open_items if i.owasp_id == extra_id]
        if members:
            owasp_rows.append(
                CategoryCount(
                    id=extra_id,
                    name=extra_name,
                    count=len(members),
                    critical=sum(1 for i in members if i.severity == "critical"),
                    high=sum(1 for i in members if i.severity == "high"),
                )
            )

    top25_counter: Counter[int] = Counter(i.cwe for i in open_items if i.cwe and i.top25_rank)
    top25_rows = [
        Top25Count(rank=e.rank, cwe=e.cwe, name=e.name, count=int(top25_counter.get(e.cwe, 0)))
        for e in mappings.top25_entries()
    ]

    scan_verdict = enum_value(_g(scan, "verdict"), "pending")
    verdict = (review.verdict if review is not None else scan_verdict) or "pending"
    scan_date = _g(scan, "finished_at") or _g(scan, "started_at") or _g(scan, "created_at")
    generated = generated_at or datetime.now(timezone.utc)

    tools = [
        ToolInfo(
            name=str(_g(j, "tool", "")),
            label=tool_label(str(_g(j, "tool", ""))),
            version=_g(j, "tool_version"),
            image=_g(j, "image"),
            image_digest=_g(j, "image_digest"),
            state=enum_value(_g(j, "state")),
            partial=bool(_g(j, "partial", False)),
            content_versions={
                str(k): str(v) for k, v in (_g(j, "content_versions") or {}).items()
            },
        )
        for j in jobs
    ]

    app_name = str(_g(application, "name", ""))
    version_label = str(_g(version, "label", ""))
    review_state = review.state if review is not None else "automatic"
    header = Header(
        report_ref=report_ref,
        title=f"{app_name} {version_label}".strip()
        + (" - vendor assessment" if kind == "vendor" else " - security report"),
        kind=kind,
        application_name=app_name,
        application_type=enum_value(_g(application, "type")),
        criticality=_g(application, "criticality"),
        classification_label=str(_g(application, "data_classification", "") or "").upper(),
        version_label=version_label,
        version_kind=str(_g(version, "label_kind", "") or ""),
        commit_sha=_g(scan, "commit_sha") or _g(version, "commit_sha"),
        source_ref=_g(scan, "source_ref"),
        source_digest=_g(scan, "source_digest"),
        scan_id=str(_g(scan, "id", "")),
        scan_kind=enum_value(_g(scan, "kind")),
        scan_mode=_g(scan, "mode"),
        profile=f"{_g(scan, 'profile_name', '')} v{_g(scan, 'profile_version', '')}".strip(),
        scan_date=iso(scan_date),
        generated_at=iso(generated),
        tools=tools,
        template_name=template_name,
        template_version=template_version,
        mapping_versions=mappings.mapping_versions(),
        review_state=review_state,
        review_label=review_label(review_state),
    )

    vendor_info: VendorInfo | None = None
    if kind == "vendor" or vendor is not None:
        vendor_info = VendorInfo(
            name=str(_g(vendor, "name", "") or ""),
            product=_g(application, "vendor_product") or app_name,
            hosting=_g(application, "hosting"),
            contact_name=_g(vendor, "contact_name"),
            contact_email=_g(vendor, "contact_email"),
            risk_tier=_g(vendor, "risk_tier"),
        )

    top_risks = [
        f"{i.severity_label}: {i.title}" + (f" ({i.location})" if i.location else "")
        for i in open_items
        if i.severity in ("critical", "high")
    ][:5]

    summary = Summary(
        verdict=verdict,
        verdict_label=VERDICT_LABELS.get(verdict, verdict),
        verdict_explanation=_explanation(verdict, counts, _g(scan, "verdict_detail")),
        overall_risk=_overall_risk(counts),
        counts=counts,
        by_tool=by_tool,
        by_owasp=owasp_rows,
        owasp_max=max([r.count for r in owasp_rows] or [0]),
        cwe_top25=top25_rows,
        cwe_top25_present=sum(1 for r in top25_rows if r.count),
        triaged_out=len(other_rows),
        top_risks=top_risks,
        delta=_delta(open_items, previous) if previous is not None else None,
    )

    coverage = _coverage(scan, jobs, [str(t) for t in (_g(scan, "requested_tools") or [])])

    return Snapshot(
        kind=kind,
        vendor_copy=vendor_copy,
        header=header,
        vendor=vendor_info,
        summary=summary,
        findings=open_items,
        detail_limit=detail_limit,
        triaged=triaged_items[:MAX_TRIAGED_ROWS],
        code_quality=_code_quality(jobs),
        components=_components(sbom_artifacts, sbom_component_count, jobs),
        coverage=coverage,
        methodology=_methodology(header, kind == "vendor"),
        known_limits=list(KNOWN_LIMITS),
        review=_review_model(review, verdict, vendor_copy, open_items),
    )


def with_review(
    snapshot: Snapshot, review: ReviewInput, vendor_copy: bool | None = None
) -> Snapshot:
    """A copy of ``snapshot`` after a review: new verdict, conditions, review state and header."""
    data = snapshot.model_copy(deep=True)
    copy_flag = snapshot.vendor_copy if vendor_copy is None else vendor_copy
    data.vendor_copy = copy_flag
    data.review = _review_model(review, review.verdict, copy_flag, data.findings)
    data.summary.verdict = review.verdict
    data.summary.verdict_label = VERDICT_LABELS.get(review.verdict, review.verdict)
    data.header.review_state = review.state
    data.header.review_label = review_label(review.state)
    return data
