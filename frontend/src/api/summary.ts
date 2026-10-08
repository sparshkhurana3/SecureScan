import { useQuery } from "@tanstack/react-query";

import { apiFetch } from "./client";

/** Counts by severity plus a total (`critical`, `high`, `medium`, `low`, `info`, `total`). */
export type SeverityCounts = Partial<Record<"critical" | "high" | "medium" | "low" | "info" | "total", number>>;

export type SummaryScan = {
  scan_id: string;
  application_id: string;
  application_name: string;
  version_label: string;
  kind: "sast" | "dast";
  state: string;
  verdict: string;
  counts: SeverityCounts;
  tools: string[];
  jobs_total: number;
  jobs_done: number;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
};

export type Summary = {
  running: SummaryScan[];
  queued: SummaryScan[];
  latest: SummaryScan[];
  open_counts: Record<string, number>;
  applications: number;
  applications_scanned: number;
  import_queue: { pending: number; dead_letters: number };
  defectdojo_url: string;
};

export function useSummary() {
  return useQuery({
    queryKey: ["summary"],
    queryFn: ({ signal }) => apiFetch<Summary>("/summary", { signal }),
    refetchInterval: 15_000,
  });
}
