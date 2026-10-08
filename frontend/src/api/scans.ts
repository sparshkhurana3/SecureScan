/**
 * Scans, scan profiles, reports of a scan and the code-scan start sequence.
 *
 * Types mirror `backend/securescan/api/scans.py`, `profiles.py` and `reports.py` (the backend code wins
 * where it differs from the plan). The hooks of the history, summary and settings pages live in the other
 * `src/api/*.ts` files; the report view reuses `reports.ts` and adds the review form rules here.
 */
import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  fetchVersion,
  findOrCreateVersion,
  resolveApplication,
  validateApplicationChoice,
  type AppVersion,
  type Application,
  type ApplicationChoice,
  type LabelKind,
} from "./applications";
import { apiFetch, type CursorPage } from "./client";
import { createDeployKey, createVendorToken, type DeployKey, type GithubRepository } from "./github";
import type { Report, ReviewRequest } from "./reports";
import { createTarget, findOrCreateTarget, type Target } from "./targets";
import type { UploadResult } from "../lib/upload";

// --------------------------------------------------------------------------- types
export type ScanKind = "sast" | "dast";
export type ScanState = "queued" | "running" | "completed" | "completed_partial" | "failed" | "cancelled";
export type JobState =
  | "queued"
  | "preparing"
  | "running"
  | "completed"
  | "completed_partial"
  | "failed"
  | "cancelled"
  | "timed_out";
export type ImportState = "pending" | "imported" | "failed";
export type Verdict = "pass" | "conditional" | "fail" | "pending";

export type Scan = {
  id: string;
  application_id: string;
  version_id: string;
  target_id: string | null;
  profile_name: string;
  profile_version: number;
  kind: ScanKind;
  mode: string | null;
  trigger: string;
  trigger_detail: string | null;
  state: ScanState;
  verdict: Verdict;
  started_by_id: string | null;
  requested_tools: string[];
  commit_sha: string | null;
  source_ref: string | null;
  counts: Record<string, unknown>;
  coverage_notes: unknown[];
  error: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  cancel_requested_at: string | null;
};

export type ScanJob = {
  id: string;
  tool: string;
  state: JobState;
  import_state: ImportState;
  attempts: number;
  exit_code: number | null;
  outcome_reason: string | null;
  partial: boolean;
  counts: Record<string, unknown>;
  image: string | null;
  image_digest: string | null;
  tool_version: string | null;
  content_versions: Record<string, unknown>;
  applied_exclusions: unknown[];
  coverage_note: string | null;
  dd_test_id: number | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
};

export type ScanArtifact = {
  id: string;
  kind: string;
  job_id: string | null;
  filename: string | null;
  sha256: string;
  size_bytes: number;
  created_at: string;
};

export type ScanDetail = Scan & {
  jobs: ScanJob[];
  artifacts: ScanArtifact[];
  replayed: boolean;
  collapsed: boolean;
};

export type ScanProfile = {
  id: string;
  name: string;
  version: number;
  kind: ScanKind;
  mode: string | null;
  description: string | null;
  tools: string[];
  active: boolean;
  sha256: string;
  created_at: string;
};

// --------------------------------------------------------------------------- labels and small helpers
export const SCAN_STATE_LABELS: Record<ScanState, string> = {
  queued: "Queued",
  running: "Running",
  completed: "Completed",
  completed_partial: "Completed (partial)",
  failed: "Failed",
  cancelled: "Cancelled",
};

export const JOB_STATE_LABELS: Record<JobState, string> = {
  queued: "Queued",
  preparing: "Preparing",
  running: "Running",
  completed: "Completed",
  completed_partial: "Completed (partial)",
  failed: "Failed",
  cancelled: "Cancelled",
  timed_out: "Timed out",
};

export const IMPORT_STATE_LABELS: Record<ImportState, string> = {
  pending: "Import pending",
  imported: "Imported",
  failed: "Import failed",
};

export const VERDICT_LABELS: Record<Verdict, string> = {
  pass: "Pass",
  conditional: "Conditional pass",
  fail: "Fail",
  pending: "Pending",
};

export const TOOL_LABELS: Record<string, string> = {
  semgrep: "Semgrep",
  gitleaks: "Gitleaks",
  sonarqube: "SonarQube",
  syft: "Syft",
  grype: "Grype",
  "dependency-check": "Dependency-Check",
  spotbugs: "SpotBugs",
  zap: "OWASP ZAP",
  nuclei: "Nuclei",
};

export function toolLabel(tool: string): string {
  return TOOL_LABELS[tool] ?? tool;
}

export function isActiveScan(state: ScanState): boolean {
  return state === "queued" || state === "running";
}

export function isActiveJob(state: JobState): boolean {
  return state === "queued" || state === "preparing" || state === "running";
}

export type SeverityName = "critical" | "high" | "medium" | "low" | "info";
export const SEVERITIES: readonly SeverityName[] = ["critical", "high", "medium", "low", "info"];
export const SEVERITY_LABELS: Record<SeverityName, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

/** Counts by severity from the loosely typed `counts` object of a scan or job. */
export function severityCounts(counts: Record<string, unknown> | null | undefined): Record<SeverityName | "total", number> {
  const read = (key: string): number => {
    const value = counts?.[key];
    return typeof value === "number" && Number.isFinite(value) ? value : 0;
  };
  const result = {
    critical: read("critical"),
    high: read("high"),
    medium: read("medium"),
    low: read("low"),
    info: read("info"),
    total: 0,
  };
  const sum = result.critical + result.high + result.medium + result.low + result.info;
  const stated = counts?.total;
  result.total = typeof stated === "number" ? Math.max(stated, sum) : sum;
  return result;
}

// --------------------------------------------------------------------------- queries
export const scansKey = ["scans"] as const;

export function useScans(options: { kind?: ScanKind; limit?: number; refetchMs?: number | false } = {}) {
  const { kind, limit = 25, refetchMs = 5000 } = options;
  return useQuery({
    queryKey: [...scansKey, "list", kind ?? "all", limit],
    queryFn: ({ signal }) => apiFetch<CursorPage<Scan>>("/scans", { query: { kind, limit }, signal }),
    refetchInterval: refetchMs,
    select: (page) => page.items,
  });
}

/** One scan with its jobs. Refreshes every few seconds while it runs (the live stream also nudges it). */
export function useScan(scanId: string | undefined) {
  return useQuery({
    queryKey: [...scansKey, "detail", scanId],
    queryFn: ({ signal }) => apiFetch<ScanDetail>(`/scans/${scanId ?? ""}`, { signal }),
    enabled: Boolean(scanId),
    refetchInterval: (query) => {
      const data = query.state.data;
      if (!data) return 5000;
      const importing = data.jobs.some(
        (job) => job.import_state === "pending" && (job.state === "completed" || job.state === "completed_partial"),
      );
      return isActiveScan(data.state) || importing ? 5000 : false;
    },
  });
}

export function useCancelScan(scanId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => apiFetch<ScanDetail>(`/scans/${scanId}/cancel`, { method: "POST" }),
    onSuccess: (detail) => {
      queryClient.setQueryData([...scansKey, "detail", scanId], detail);
      void queryClient.invalidateQueries({ queryKey: scansKey });
    },
  });
}

/** Newest active version of every profile of a kind. */
export function useScanProfiles(kind: ScanKind) {
  return useQuery({
    queryKey: ["profiles", kind],
    queryFn: ({ signal }) => apiFetch<CursorPage<ScanProfile>>("/profiles", { query: { kind, limit: 200 }, signal }),
    staleTime: 60_000,
    select: (page) => newestProfiles(page.items),
  });
}

/** The highest version of each profile name, in name order. */
export function newestProfiles(profiles: ScanProfile[]): ScanProfile[] {
  const best = new Map<string, ScanProfile>();
  for (const profile of profiles) {
    if (!profile.active) continue;
    const current = best.get(profile.name);
    if (!current || profile.version > current.version) best.set(profile.name, profile);
  }
  return [...best.values()].sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * The profile of a DAST mode: by its `mode` field, else by the conventional name `dast-<mode>`
 * (`dast-baseline`, `dast-full`, `dast-api`, `dast-nuclei`).
 */
export function profileForMode(profiles: ScanProfile[], mode: string): ScanProfile | undefined {
  return profiles.find((profile) => profile.mode === mode) ?? profiles.find((profile) => profile.name === `dast-${mode}`);
}

/** The log of a job (the last 2 MB), loaded on request. */
export function useJobLog(scanId: string, jobId: string | null, enabled: boolean) {
  return useQuery({
    queryKey: [...scansKey, "log", scanId, jobId],
    queryFn: ({ signal }) => apiFetch<string>(`/scans/${scanId}/jobs/${jobId ?? ""}/log`, { signal }),
    enabled: enabled && Boolean(jobId),
    staleTime: Infinity,
  });
}

/** Labels of many versions at once (a scan list has ids only). Deduplicated and cached for five minutes. */
export function useVersionMap(versionIds: string[]): Map<string, AppVersion> {
  const unique = [...new Set(versionIds)];
  const results = useQueries({
    queries: unique.map((id) => ({
      queryKey: ["version", id],
      queryFn: ({ signal }: { signal: AbortSignal }) => fetchVersion(id, signal),
      staleTime: 5 * 60_000,
    })),
  });
  const map = new Map<string, AppVersion>();
  results.forEach((result, index) => {
    const id = unique[index];
    if (id && result.data) map.set(id, result.data);
  });
  return map;
}

// --------------------------------------------------------------------------- reports (the report view)
// The report hooks (`useReport`, `useReports`, `useCreateReport`, `useReviewReport`) are in `reports.ts`.
/** The newest ready report of each scan, by scan id (a scan list links to it). */
export function useRecentReports() {
  return useQuery({
    queryKey: ["reports", "recent"],
    queryFn: ({ signal }) => apiFetch<CursorPage<Report>>("/reports", { query: { limit: 200, status: "ready" }, signal }),
    staleTime: 15_000,
    select: (page) => {
      const byScan = new Map<string, Report>();
      for (const report of page.items) {
        if (report.scan_id && !byScan.has(report.scan_id)) byScan.set(report.scan_id, report);
      }
      return byScan;
    },
  });
}

export type ReportFinding = {
  key: string;
  tool_label: string;
  severity: string;
  severity_label: string;
  title: string;
  location: string;
};

/** The open findings a condition can refer to (from the frozen snapshot of the report). */
export function useReportFindings(reportId: string | undefined, enabled: boolean) {
  return useQuery({
    queryKey: ["reports", "snapshot", reportId],
    queryFn: ({ signal }) => apiFetch<{ findings?: ReportFinding[] }>(`/reports/${reportId ?? ""}/snapshot`, { signal }),
    enabled: enabled && Boolean(reportId),
    staleTime: 60_000,
    select: (snapshot) => snapshot.findings ?? [],
  });
}

export type ReviewValues = {
  decision: "confirm" | "override";
  verdict: "" | "pass" | "conditional" | "fail";
  reason: string;
  conditions: { findingKey: string; deadline: string }[];
  internalNotes: string;
  vendorCopy: boolean;
};

export function canConfirmProposal(proposed: string | null | undefined): boolean {
  return proposed === "pass" || proposed === "conditional" || proposed === "fail";
}

export function initialReview(report: Report): ReviewValues {
  return {
    decision: canConfirmProposal(report.proposed_verdict) ? "confirm" : "override",
    verdict: "",
    reason: "",
    conditions: report.conditions.map((condition) => ({
      findingKey: condition.finding_hash,
      deadline: condition.deadline.slice(0, 10),
    })),
    internalNotes: report.internal_notes ?? "",
    vendorCopy: report.vendor_copy,
  };
}

/** The verdict the review would record (null while it cannot be told). */
export function effectiveVerdict(values: ReviewValues, proposed: string | null | undefined): string | null {
  if (values.decision === "confirm") return canConfirmProposal(proposed) ? (proposed ?? null) : null;
  return values.verdict === "" ? null : values.verdict;
}

/** Field errors of a review, keyed `decision`, `verdict`, `reason`, `conditions`, `condition.<n>.finding|deadline`. */
export function validateReview(
  values: ReviewValues,
  proposed: string | null | undefined,
  today: string,
  openKeys?: ReadonlySet<string>,
): Record<string, string> {
  const errors: Record<string, string> = {};
  if (values.decision === "confirm") {
    if (!canConfirmProposal(proposed)) {
      errors.decision = "There is no proposed verdict to confirm. Choose a verdict and give a reason.";
    }
  } else {
    if (values.verdict === "") errors.verdict = "Choose pass, conditional pass or fail.";
    else if (values.verdict === proposed) {
      errors.verdict = "That is the proposed verdict. Confirm it instead of overriding it.";
    }
    if (values.reason.trim().length < 5) errors.reason = "Overriding the verdict needs a reason of at least 5 characters.";
  }
  if (values.reason.length > 2000) errors.reason = "The reason is limited to 2000 characters.";
  if (values.internalNotes.length > 4000) errors.internalNotes = "The notes are limited to 4000 characters.";
  if (values.conditions.length > 0 && effectiveVerdict(values, proposed) === "pass") {
    errors.conditions = "A passing verdict has no conditions.";
  }
  const seen = new Set<string>();
  values.conditions.forEach((condition, index) => {
    const prefix = `condition.${String(index)}`;
    if (!condition.findingKey) errors[`${prefix}.finding`] = "Choose the finding.";
    else if (openKeys && !openKeys.has(condition.findingKey)) {
      errors[`${prefix}.finding`] = "This is not an open finding of the report.";
    } else if (seen.has(condition.findingKey)) {
      errors[`${prefix}.finding`] = "This finding is listed twice.";
    }
    seen.add(condition.findingKey);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(condition.deadline)) {
      errors[`${prefix}.deadline`] = "Enter the remediation deadline.";
    } else if (condition.deadline < today) {
      errors[`${prefix}.deadline`] = "The deadline is in the past.";
    }
  });
  return errors;
}

export function buildReviewBody(values: ReviewValues, reportKind: "application" | "vendor"): ReviewRequest {
  const body: ReviewRequest = {
    decision: values.decision,
    conditions: values.conditions.map((condition) => ({
      finding_hash: condition.findingKey,
      deadline: condition.deadline,
    })),
    internal_notes: values.internalNotes,
  };
  if (values.decision === "override") {
    if (values.verdict !== "") body.verdict = values.verdict;
    body.reason = values.reason.trim();
  }
  if (reportKind === "vendor") body.vendor_copy = values.vendorCopy;
  return body;
}

// --------------------------------------------------------------------------- starting a code scan
export type VendorCredentialChoice =
  | { mode: "existing" }
  | { mode: "deploy_key" }
  | { mode: "token"; token: string; expiresOn: string };

export type SastSource =
  /** A repository found by the connected GitHub App; its application is `application`. */
  | { kind: "github"; fullName: string }
  /** Any repository address (an owner/name pair, an https or an ssh URL). */
  | { kind: "url"; url: string; credential: VendorCredentialChoice }
  | { kind: "zip"; artifactId: string | null; filename: string }
  | { kind: "image"; reference: string }
  | { kind: "image_tar"; artifactId: string | null; filename: string };

export type SastRequest = {
  source: SastSource;
  application: ApplicationChoice;
  versionLabel: string;
  /** Branch, tag or commit; empty for the default branch. */
  ref: string;
  profile: string;
  /** The ticked tools, in any order. */
  tools: string[];
  /** Every tool of the profile (a full selection is sent as "all", not as a list). */
  profileTools: string[];
};

/** What the source part of the code scan form holds (the request is built from it by `sourceToRequest`). */
export type SourceState = {
  kind: "github" | "url" | "zip" | "image";
  repo: GithubRepository | null;
  url: string;
  credentialMode: "existing" | "deploy_key" | "token";
  token: string;
  tokenExpires: string;
  zip: UploadResult | null;
  imageMode: "reference" | "tar";
  imageRef: string;
  imageTar: UploadResult | null;
};

export function emptySourceState(): SourceState {
  return {
    kind: "url",
    repo: null,
    url: "",
    credentialMode: "existing",
    token: "",
    tokenExpires: "",
    zip: null,
    imageMode: "reference",
    imageRef: "",
    imageTar: null,
  };
}

export function sourceToRequest(state: SourceState): SastSource {
  switch (state.kind) {
    case "github":
      return { kind: "github", fullName: state.repo?.full_name ?? "" };
    case "url": {
      const credential: VendorCredentialChoice =
        state.credentialMode === "token"
          ? { mode: "token", token: state.token, expiresOn: state.tokenExpires }
          : { mode: state.credentialMode };
      return { kind: "url", url: state.url, credential };
    }
    case "zip":
      return { kind: "zip", artifactId: state.zip?.artifactId ?? null, filename: state.zip?.filename ?? "" };
    case "image":
      return state.imageMode === "tar"
        ? { kind: "image_tar", artifactId: state.imageTar?.artifactId ?? null, filename: state.imageTar?.filename ?? "" }
        : { kind: "image", reference: state.imageRef };
  }
}

const REPO_SHORT = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const REPO_HTTP = /^https?:\/\/[^\s/@]+\/\S+$/;
const REPO_SSH = /^(ssh:\/\/\S+|[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+:\S+)$/;

export function isValidRepositoryAddress(text: string): boolean {
  const value = text.trim();
  if (!value || value.length > 2000 || /\s/.test(value)) return false;
  return REPO_SHORT.test(value) || REPO_HTTP.test(value) || REPO_SSH.test(value);
}

export function isValidImageReference(text: string): boolean {
  const value = text.trim();
  return value !== "" && value.length <= 2000 && !/\s/.test(value) && !/^[a-z]+:\/\//i.test(value);
}

/** Field errors of the code scan form (empty object: it can be sent). */
export function validateSastRequest(request: SastRequest, today: string): Record<string, string> {
  const errors: Record<string, string> = {};
  const { source } = request;
  switch (source.kind) {
    case "github":
      if (!source.fullName) errors.source = "Choose a repository.";
      break;
    case "url":
      if (!source.url.trim()) errors.source = "Enter the repository address.";
      else if (!isValidRepositoryAddress(source.url)) {
        errors.source =
          "Use owner/name, an https:// address or an ssh address, without spaces or a password in it.";
      }
      if (source.credential.mode === "token") {
        if (source.credential.token.trim().length < 20) {
          errors.token = "The vendor's token is at least 20 characters.";
        }
        if (!/^\d{4}-\d{2}-\d{2}$/.test(source.credential.expiresOn)) {
          errors.tokenExpires = "Enter the day the token expires.";
        } else if (source.credential.expiresOn <= today) {
          errors.tokenExpires = "The token's expiry date is in the past.";
        }
      }
      break;
    case "zip":
    case "image_tar":
      if (!source.artifactId) errors.source = "Upload the file first and wait until it is finished.";
      break;
    case "image":
      if (!source.reference.trim()) errors.source = "Enter the image reference, for example registry.example.com/app:1.4.2.";
      else if (!isValidImageReference(source.reference)) {
        errors.source = "An image reference has no spaces and no scheme, for example registry.example.com/app:1.4.2.";
      }
      break;
  }
  if (!request.versionLabel.trim()) errors.versionLabel = "Enter a version label, for example 1.4.2 or main.";
  else if (request.versionLabel.length > 255) errors.versionLabel = "The version label is limited to 255 characters.";
  if (request.ref.trim() && (/\s/.test(request.ref.trim()) || request.ref.length > 255)) {
    errors.ref = "A branch, tag or commit has no spaces.";
  }
  if (request.tools.length === 0) errors.tools = "Tick at least one tool.";
  if (!request.profile) errors.profile = "No scan profile is available.";
  for (const [key, message] of Object.entries(validateApplicationChoice(request.application))) {
    errors[`application.${key}`] = message;
  }
  return errors;
}

function labelKindFor(source: SastSource): LabelKind {
  switch (source.kind) {
    case "zip":
      return "upload";
    case "image":
      return source.reference.includes("@sha256:") ? "image_digest" : "tag";
    case "image_tar":
      return "image_digest";
    default:
      return "branch";
  }
}

export type PreparedSast = {
  application: Application;
  version: AppVersion;
  target: Target;
  /** A key the vendor has to add to the repository before the scan can read it. */
  deployKey: DeployKey | null;
};

/**
 * Creates what the scan needs: the application (unless chosen), the version, the target and, for a vendor
 * repository, the deploy key or token. Existing versions and targets with the same label or locator are
 * reused. Nothing is scanned yet; the caller shows a new deploy key and then calls `startPreparedScan`.
 */
export async function prepareSast(
  request: SastRequest,
  hooks: { onApplication?: (application: Application) => void } = {},
): Promise<PreparedSast> {
  const application = await resolveApplication(request.application);
  hooks.onApplication?.(application); // a retry after a later failure must reuse it, not create it again
  const version = await findOrCreateVersion(application.id, request.versionLabel, labelKindFor(request.source));
  const { source } = request;
  let target: Target;
  let deployKey: DeployKey | null = null;
  switch (source.kind) {
    case "github":
      target = await findOrCreateTarget(version.id, "github_repo", source.fullName);
      break;
    case "url": {
      const vendor = application.type === "vendor";
      target = await findOrCreateTarget(version.id, vendor ? "vendor_repo" : "github_repo", source.url);
      if (vendor) {
        const replace = target.credential_id !== null;
        if (source.credential.mode === "deploy_key") {
          deployKey = await createDeployKey(target.id, replace);
        } else if (source.credential.mode === "token") {
          await createVendorToken(target.id, source.credential.token, source.credential.expiresOn, replace);
        } else if (!target.credential_id) {
          throw new Error(
            "This vendor repository has no deploy key or token yet. Choose to generate a deploy key or enter the vendor's token.",
          );
        }
      }
      break;
    }
    case "zip":
      target = await createTarget(version.id, {
        kind: "zip",
        upload_artifact_id: source.artifactId,
        name: source.filename.slice(0, 200),
      });
      break;
    case "image":
      target = await findOrCreateTarget(version.id, "image", source.reference);
      break;
    case "image_tar":
      target = await createTarget(version.id, {
        kind: "image",
        locator: `upload:${source.artifactId ?? ""}`,
        upload_artifact_id: source.artifactId,
        name: source.filename.slice(0, 200),
      });
      break;
    default:
      throw new Error("Choose where the code comes from.");
  }
  return { application, version, target, deployKey };
}

/** `POST /scans`. The same `idempotencyKey` returns the first scan again instead of starting a second. */
export function startPreparedScan(
  prepared: PreparedSast,
  request: SastRequest,
  idempotencyKey: string,
): Promise<ScanDetail> {
  const allTools = request.profileTools.length > 0 && request.profileTools.every((tool) => request.tools.includes(tool));
  const repository = request.source.kind === "github" || request.source.kind === "url";
  const body: Record<string, unknown> = {
    version_id: prepared.version.id,
    target_id: prepared.target.id,
    profile: request.profile,
    ...(allTools ? {} : { tools: request.profileTools.filter((tool) => request.tools.includes(tool)) }),
    ...(repository && request.ref.trim() ? { ref: request.ref.trim() } : {}),
  };
  return apiFetch<ScanDetail>("/scans", { method: "POST", body, headers: { "Idempotency-Key": idempotencyKey } });
}

export function useStartScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (args: { prepared: PreparedSast; request: SastRequest; idempotencyKey: string }) =>
      startPreparedScan(args.prepared, args.request, args.idempotencyKey),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: scansKey }),
  });
}

/** DAST: start a scan of a registered target with the profile of the chosen mode. */
export function startDastScan(
  target: Pick<Target, "id" | "version_id">,
  profile: string,
  idempotencyKey: string,
): Promise<ScanDetail> {
  return apiFetch<ScanDetail>("/scans", {
    method: "POST",
    body: { version_id: target.version_id, target_id: target.id, profile },
    headers: { "Idempotency-Key": idempotencyKey },
  });
}

/** A fresh key for one start attempt (kept until the attempt succeeds, so a double click starts one scan). */
export function newIdempotencyKey(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") return crypto.randomUUID();
  return `${String(Date.now())}-${Math.random().toString(16).slice(2)}`;
}

export function todayIso(now: Date = new Date()): string {
  return now.toISOString().slice(0, 10);
}
