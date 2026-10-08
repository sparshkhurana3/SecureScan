import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch, apiUrl, type CursorPage, type QueryParams } from "./client";

export type ReportCondition = { finding_hash: string; deadline: string };

/** `ReportOut` of `GET /api/v1/reports/{id}`. */
export type Report = {
  id: string;
  application_id: string;
  version_id: string;
  scan_id: string | null;
  kind: "application" | "vendor";
  ref: string | null;
  title: string | null;
  template_id: string | null;
  template_version: number | null;
  snapshot_sha256: string | null;
  /** `pending`, `ready` or `failed` */
  status: string;
  error: string | null;
  review_state: "automatic" | "reviewed";
  proposed_verdict: string | null;
  verdict: string;
  verdict_overridden: boolean;
  override_reason: string | null;
  reviewer_id: string | null;
  reviewed_at: string | null;
  conditions: ReportCondition[];
  vendor_copy: boolean;
  internal_notes: string | null;
  mapping_versions: Record<string, unknown>;
  previous_report_id: string | null;
  generated_by_id: string | null;
  created_at: string;
  updated_at: string;
  html_ready: boolean;
  pdf_ready: boolean;
};

export type ReportFilters = {
  application_id?: string;
  version_id?: string;
  scan_id?: string;
  kind?: "application" | "vendor";
  status?: "pending" | "ready" | "failed";
};

export type ReviewRequest = {
  decision: "confirm" | "override";
  /** Required to override. */
  verdict?: "pass" | "conditional" | "fail";
  reason?: string;
  conditions?: ReportCondition[];
  internal_notes?: string;
  vendor_copy?: boolean;
};

export type CreateReportRequest = {
  scan_id?: string;
  version_id?: string;
  template_id?: string;
  kind?: "application" | "vendor";
  vendor_copy?: boolean;
};

/** The report page in a sandboxed frame (`<iframe sandbox="" src=...>`). */
export function reportHtmlUrl(id: string): string {
  return apiUrl(`/reports/${encodeURIComponent(id)}/html`);
}

/** The PDF download (stamped with the downloader at download time). */
export function reportPdfUrl(id: string): string {
  return apiUrl(`/reports/${encodeURIComponent(id)}/pdf`);
}

/** The finding list of one report as CSV. */
export function reportCsvUrl(id: string): string {
  return apiUrl(`/reports/${encodeURIComponent(id)}/findings.csv`);
}

/** A report; polls every 3 seconds while it is still being rendered. */
export function useReport(id: string | undefined) {
  return useQuery({
    queryKey: ["report", id],
    queryFn: ({ signal }) => apiFetch<Report>(`/reports/${String(id)}`, { signal }),
    enabled: Boolean(id),
    refetchInterval: (query) => (query.state.data?.status === "pending" ? 3000 : false),
  });
}

export function useReports(filters: ReportFilters = {}, limit = 50) {
  const query: QueryParams = { ...filters, limit };
  return useQuery({
    queryKey: ["reports", query],
    queryFn: ({ signal }) => apiFetch<CursorPage<Report>>("/reports", { query, signal }),
    placeholderData: keepPreviousData,
  });
}

/** Regenerate a report (202; render runs in the worker, `useReport` polls until ready). */
export function useCreateReport() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateReportRequest) => apiFetch<Report>("/reports", { method: "POST", body }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["reports"] }),
  });
}

/** Confirm or override the proposed verdict (Analyst or Admin). */
export function useReviewReport(id: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: ReviewRequest) =>
      apiFetch<Report>(`/reports/${encodeURIComponent(id)}/review`, { method: "POST", body }),
    onSuccess: (report) => {
      client.setQueryData(["report", id], report);
      return client.invalidateQueries({ queryKey: ["reports"] });
    },
  });
}
