/**
 * Operations APIs used by Settings (scanner health, content feeds, the NVD key, scanner images) and by the
 * vendor assessment page.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch, apiUrl, useCursorList } from "./client";

// ---------------------------------------------------------------------------------- scanner health

export type ApprovedImage = { image: string; tag: string | null; digest: string; approved_at: string | null };

/** `ToolHealthOut` of `GET /api/v1/scanner-health`. */
export type ToolHealth = {
  tool: string;
  role: "scanner" | "support" | string;
  description: string;
  image: string | null;
  tag: string | null;
  digest: string | null;
  digest_source: string | null;
  last_job_digest: string | null;
  approved_image: ApprovedImage | null;
  max_parallel: number | null;
  last_success_at: string | null;
  last_failure_at: string | null;
  feed: string | null;
};

/** `FeedHealthOut`. */
export type FeedHealth = {
  feed: string;
  label: string;
  tool: string;
  version: string | null;
  path: string | null;
  source_commit: string | null;
  built_at: string | null;
  fetched_at: string | null;
  activated_at: string | null;
  age_seconds: number | null;
  limit_days: number;
  stale: boolean;
  regression_result: string | null;
  update_failed: boolean;
};

export type ScannerHealth = {
  /** `ok`, or `attention` when a feed is stale or an update failed */
  status: string;
  generated_at: string;
  tools: ToolHealth[];
  feeds: FeedHealth[];
  notes: string[];
};

export function useScannerHealth() {
  return useQuery({
    queryKey: ["scanner-health"],
    queryFn: ({ signal }) => apiFetch<ScannerHealth>("/scanner-health", { signal }),
    refetchInterval: 60_000,
  });
}

// ---------------------------------------------------------------------------------- content feeds

export type ContentFeed = "semgrep_rules" | "nuclei_templates" | "grype_db" | "nvd_data";

/** `ContentVersionOut`. */
export type ContentVersion = {
  id: string;
  feed: ContentFeed;
  version: string;
  path: string | null;
  source_commit: string | null;
  built_at: string | null;
  fetched_at: string;
  regression_result: string;
  regression_detail: Record<string, unknown>;
  active: boolean;
  activated_at: string | null;
  created_at: string;
};

export function useContentVersions(limit = 50) {
  return useCursorList<ContentVersion>(["content-versions"], "/content-versions", {}, { limit });
}

export type UpdateAccepted = { feed: ContentFeed; queued: boolean; message: string };

export function useStartContentUpdate() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (feed: ContentFeed) =>
      apiFetch<UpdateAccepted>("/content-versions/updates", { method: "POST", body: { feed } }),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["content-versions"] });
      return client.invalidateQueries({ queryKey: ["scanner-health"] });
    },
  });
}

export type NvdKeyStatus = {
  configured: boolean;
  /** `credential`, `environment` or `none` */
  source: string;
  mirror: boolean;
  stored_at?: string | null;
};

export function useNvdKeyStatus() {
  return useQuery({
    queryKey: ["content", "nvd-key"],
    queryFn: ({ signal }) => apiFetch<NvdKeyStatus>("/content/nvd-key", { signal }),
  });
}

/** Store the key (write-only: the key never comes back). */
export function useStoreNvdKey() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (key: string) => apiFetch<NvdKeyStatus>("/content/nvd-key", { method: "PUT", body: { key } }),
    onSuccess: (status) => client.setQueryData(["content", "nvd-key"], status),
  });
}

// ---------------------------------------------------------------------------------- scanner images

export type ImageState = "pending" | "active" | "retired" | "rejected";

/** `ImageVersionOut`. */
export type ImageVersion = {
  id: string;
  tool: string;
  image: string;
  tag: string | null;
  digest: string;
  source: string;
  state: ImageState;
  scope: string | null;
  reason: string | null;
  previous_tag: string | null;
  previous_digest: string | null;
  regression_result: string;
  regression_detail: Record<string, unknown>;
  active: boolean;
  proposed_at: string;
  approved_by_id: string | null;
  approved_at: string | null;
  notes: string | null;
  lock_line: string;
};

export function useImageVersions(state: ImageState | "") {
  return useCursorList<ImageVersion>(["image-versions"], "/image-versions", { state: state || undefined }, { limit: 50 });
}

function useImageAction<TBody>(action: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body?: TBody }) =>
      apiFetch<ImageVersion>(`/image-versions/${encodeURIComponent(id)}/${action}`, {
        method: "POST",
        body: body ?? {},
      }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["image-versions"] }),
  });
}

export function useApproveImage() {
  return useImageAction<{ acknowledge_skipped: boolean }>("approve");
}

export function useRejectImage() {
  return useImageAction<{ note?: string }>("reject");
}

export function useDeactivateImage() {
  return useImageAction<Record<string, never>>("deactivate");
}

export function useCheckImagesNow() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: () => apiFetch<{ queued: boolean; detail: string }>("/image-versions/check", { method: "POST" }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["image-versions"] }),
  });
}

// ---------------------------------------------------------------------------------- vendor assessments

export type Verdict = "pass" | "conditional" | "fail" | "pending";

/** `AssessmentOut` of `GET /api/v1/vendor-assessments`. */
export type Assessment = {
  id: string;
  application_id: string;
  version_id: string;
  scan_id: string | null;
  ref: string | null;
  title: string | null;
  status: string;
  review_state: "automatic" | "reviewed";
  proposed_verdict: string | null;
  verdict: string;
  vendor_copy: boolean;
  created_at: string;
  html_ready: boolean;
  pdf_ready: boolean;
  vendor_id: string | null;
  vendor_name: string | null;
  product: string | null;
  hosting: string | null;
  version_label: string | null;
};

export type FindingRef = { key: string; severity: string; severity_label: string; title: string; location: string };

export type ConditionRules = {
  severity: string;
  verdict: string;
  earliest_deadline: string;
  latest_deadline: string;
  text: string;
};

export type AssessmentDetail = Assessment & {
  conditions: { finding_hash: string; deadline: string }[];
  condition_rules: ConditionRules;
  condition_candidates: FindingRef[];
  missing_conditions: FindingRef[];
};

export type DeltaFinding = {
  key: string;
  severity: string;
  title: string;
  tool: string;
  location: string;
  state: string;
  previous_state: string;
  hash_code: string | null;
  occurrences: number;
};

export type Delta = {
  application_id: string;
  scan_id: string;
  previous_scan_id: string;
  version_id: string;
  previous_version_id: string;
  counts: Record<string, number>;
  fixed: DeltaFinding[];
  remaining: DeltaFinding[];
  new: DeltaFinding[];
  reopened: DeltaFinding[];
  triaged: DeltaFinding[];
  compared_tools: string[];
  skipped_tools: string[];
  notes: string[];
  truncated: boolean;
};

export type Hosting = {
  target_id: string;
  hosting: string;
  hosting_recorded: boolean;
  effective_environment: string | null;
  authorization_required: boolean;
  authorization: string;
  authorization_label: string;
  full_scans_allowed: boolean;
  rule: string;
};

export type IntakeInput = {
  vendor_name: string;
  product: string;
  version: string;
  hosting: "deployable" | "saas";
  contact_name?: string;
  contact_email?: string;
};

export type IntakeResult = {
  vendor: { id: string; name: string };
  application: { id: string; name: string };
  version: { id: string; label: string };
  vendor_created: boolean;
  application_created: boolean;
  version_created: boolean;
  next_steps: string[];
};

export function useAssessments() {
  return useCursorList<Assessment>(["assessments"], "/vendor-assessments", {}, { limit: 50 });
}

export function useAssessment(id: string | null) {
  return useQuery({
    queryKey: ["assessments", "detail", id],
    queryFn: ({ signal }) => apiFetch<AssessmentDetail>(`/vendor-assessments/${encodeURIComponent(String(id))}`, { signal }),
    enabled: id !== null,
  });
}

export function useAssessmentDelta(reportScanId: string | null, previousScanId: string | null) {
  return useQuery({
    queryKey: ["assessments", "delta", reportScanId, previousScanId],
    queryFn: ({ signal }) =>
      apiFetch<Delta>("/vendor-assessments/delta", {
        query: { scan_id: reportScanId ?? undefined, previous_scan_id: previousScanId ?? undefined },
        signal,
      }),
    enabled: reportScanId !== null,
  });
}

export function useVendorIntake() {
  return useMutation({
    mutationFn: (body: IntakeInput) => apiFetch<IntakeResult>("/vendor-assessments/intake", { method: "POST", body }),
  });
}

export function useCreateAssessment() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: { scan_id?: string; version_id?: string; vendor_copy?: boolean }) =>
      apiFetch<Assessment>("/vendor-assessments", { method: "POST", body }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["assessments"] }),
  });
}

export function useTargetHosting(targetId: string | null) {
  return useQuery({
    queryKey: ["assessments", "hosting", targetId],
    queryFn: ({ signal }) =>
      apiFetch<Hosting>(`/vendor-assessments/targets/${encodeURIComponent(String(targetId))}/hosting`, { signal }),
    enabled: targetId !== null,
  });
}

/** The reviewed report for the vendor (`?copy=vendor`; no internal notes). */
export function vendorCopyUrl(id: string, format: "html" | "pdf"): string {
  return apiUrl(`/vendor-assessments/${encodeURIComponent(id)}/${format}`, { copy: "vendor" });
}
