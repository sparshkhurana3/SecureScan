import { keepPreviousData, useQuery } from "@tanstack/react-query";

import { apiFetch, type CursorPage, type QueryParams } from "./client";
import type { SeverityCounts } from "./summary";

export type HistoryTab = "scans" | "findings";

export type HistoryScan = {
  id: string;
  application_id: string;
  application_name: string;
  application_type: "internal" | "vendor" | null;
  vendor_id: string | null;
  vendor_name: string | null;
  version_id: string;
  version_label: string;
  kind: "sast" | "dast";
  mode: string | null;
  profile_name: string;
  trigger: string;
  state: string;
  verdict: string;
  counts: SeverityCounts;
  tools: string[];
  commit_sha: string | null;
  started_by_id: string | null;
  started_by_name: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
};

export type HistoryFinding = {
  id: string;
  scan_id: string;
  job_id: string;
  application_id: string;
  application_name: string;
  version_id: string;
  version_label: string;
  vendor_id: string | null;
  source_kind: string | null;
  tool: string;
  severity: string;
  title: string;
  cwe: number | null;
  cve: string | null;
  cvss: number | null;
  component: string | null;
  component_version: string | null;
  file_path: string | null;
  line: number | null;
  url: string | null;
  state_at_scan: string;
  state_now: string;
  state_now_updated_at: string | null;
  scanned_at: string;
  dd_finding_id: number;
  defectdojo_url: string;
};

/** Every filter of the Historical data page. Empty string or empty list means "not set". */
export type HistoryFilters = {
  application: string;
  vendor: string;
  type: "" | "internal" | "vendor";
  kind: "" | "sast" | "dast";
  source: string;
  tools: string[];
  severities: string[];
  cwe: string;
  cve: string;
  q: string;
  /** Triage state today (findings). */
  statesNow: string[];
  /** Triage state at scan time (findings). */
  statesThen: string[];
  /** Scan state (scans). */
  scanStates: string[];
  verdicts: string[];
  /** First day, `YYYY-MM-DD`. */
  from: string;
  /** Last day, `YYYY-MM-DD`. */
  to: string;
  startedBy: string;
};

export const EMPTY_FILTERS: HistoryFilters = {
  application: "",
  vendor: "",
  type: "",
  kind: "",
  source: "",
  tools: [],
  severities: [],
  cwe: "",
  cve: "",
  q: "",
  statesNow: [],
  statesThen: [],
  scanStates: [],
  verdicts: [],
  from: "",
  to: "",
  startedBy: "",
};

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export const TRIAGE_STATES = [
  "open",
  "false_positive",
  "risk_accepted",
  "out_of_scope",
  "duplicate",
  "mitigated",
  "closed",
  "deleted",
] as const;
export const SCAN_STATES = [
  "queued",
  "running",
  "completed",
  "completed_partial",
  "failed",
  "cancelled",
] as const;
export const VERDICTS = ["pass", "conditional", "fail", "pending"] as const;
export const SOURCE_KINDS = ["github_repo", "vendor_repo", "zip", "image", "url"] as const;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DAY = /^\d{4}-\d{2}-\d{2}$/;

/** The keys of the page URL, one per filter (`tool` and the other lists repeat the key). */
export const SEARCH_KEYS = {
  tab: "tab",
  application: "app",
  vendor: "vendor",
  type: "type",
  kind: "kind",
  source: "source",
  tools: "tool",
  severities: "severity",
  cwe: "cwe",
  cve: "cve",
  q: "q",
  statesNow: "state",
  statesThen: "then",
  scanStates: "scan_state",
  verdicts: "verdict",
  from: "from",
  to: "to",
  startedBy: "by",
} as const;

type RawSearch = Record<string, string | string[]>;

function one(raw: Record<string, unknown>, key: string): string {
  const value = raw[key];
  const text = Array.isArray(value) ? (value[0] as unknown) : value;
  return typeof text === "string" || typeof text === "number" ? String(text).trim() : "";
}

function many(raw: Record<string, unknown>, key: string, allowed?: readonly string[]): string[] {
  const value = raw[key];
  const list: unknown[] = Array.isArray(value) ? (value as unknown[]) : value === undefined ? [] : [value];
  const out: string[] = [];
  for (const item of list) {
    if (typeof item !== "string" && typeof item !== "number") continue;
    const text = String(item).trim();
    if (!text || out.includes(text)) continue;
    if (allowed && !allowed.includes(text)) continue;
    out.push(text);
  }
  return out;
}

/** The tab and filters held by a URL search object. Unknown or malformed values are dropped. */
export function parseHistorySearch(raw: unknown): { tab: HistoryTab; filters: HistoryFilters } {
  const search = (raw !== null && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  const uuid = (key: string) => {
    const text = one(search, key);
    return UUID.test(text) ? text.toLowerCase() : "";
  };
  const day = (key: string) => {
    const text = one(search, key);
    return DAY.test(text) ? text : "";
  };
  const type = one(search, SEARCH_KEYS.type);
  const kind = one(search, SEARCH_KEYS.kind);
  const cwe = one(search, SEARCH_KEYS.cwe).replace(/^CWE-/i, "");
  return {
    tab: one(search, SEARCH_KEYS.tab) === "findings" ? "findings" : "scans",
    filters: {
      application: uuid(SEARCH_KEYS.application),
      vendor: uuid(SEARCH_KEYS.vendor),
      type: type === "internal" || type === "vendor" ? type : "",
      kind: kind === "sast" || kind === "dast" ? kind : "",
      source: many(search, SEARCH_KEYS.source, SOURCE_KINDS)[0] ?? "",
      tools: many(search, SEARCH_KEYS.tools),
      severities: many(search, SEARCH_KEYS.severities, SEVERITIES),
      cwe: /^\d{1,6}$/.test(cwe) ? cwe : "",
      cve: one(search, SEARCH_KEYS.cve),
      q: one(search, SEARCH_KEYS.q),
      statesNow: many(search, SEARCH_KEYS.statesNow, TRIAGE_STATES),
      statesThen: many(search, SEARCH_KEYS.statesThen, TRIAGE_STATES),
      scanStates: many(search, SEARCH_KEYS.scanStates, SCAN_STATES),
      verdicts: many(search, SEARCH_KEYS.verdicts, VERDICTS),
      from: day(SEARCH_KEYS.from),
      to: day(SEARCH_KEYS.to),
      startedBy: uuid(SEARCH_KEYS.startedBy),
    },
  };
}

type TextField = "application" | "vendor" | "type" | "kind" | "source" | "cwe" | "cve" | "q" | "from" | "to" | "startedBy";
type ListField = "tools" | "severities" | "statesNow" | "statesThen" | "scanStates" | "verdicts";

const TEXT_FIELDS: TextField[] = [
  "application",
  "vendor",
  "type",
  "kind",
  "source",
  "cwe",
  "cve",
  "q",
  "from",
  "to",
  "startedBy",
];
const LIST_FIELDS: ListField[] = ["tools", "severities", "statesNow", "statesThen", "scanStates", "verdicts"];

/** The URL search object for a tab and filters: only what is set, so a default page has a clean URL. */
export function historySearchFromFilters(tab: HistoryTab, filters: HistoryFilters): RawSearch {
  const out: RawSearch = {};
  if (tab === "findings") out[SEARCH_KEYS.tab] = "findings";
  for (const field of TEXT_FIELDS) {
    const value = filters[field];
    if (value) out[SEARCH_KEYS[field]] = value;
  }
  for (const field of LIST_FIELDS) {
    const value = filters[field];
    if (value.length > 0) out[SEARCH_KEYS[field]] = [...value];
  }
  return out;
}

/** The number of filters that are set (for the "Clear filters" button). */
export function activeFilterCount(filters: HistoryFilters): number {
  return Object.keys(historySearchFromFilters("scans", filters)).length;
}

function dayStart(day: string): string | undefined {
  return day ? day + "T00:00:00Z" : undefined;
}

function dayEnd(day: string): string | undefined {
  return day ? day + "T23:59:59Z" : undefined;
}

/**
 * The backend query parameters for a tab: `GET /history/scans` or `GET /history/findings` (and
 * `findings.csv`, which takes the same filters as the findings list).
 */
export function filtersToQuery(tab: HistoryTab, f: HistoryFilters): QueryParams {
  const common: QueryParams = {
    application_id: f.application || undefined,
    vendor_id: f.vendor || undefined,
    type: f.type || undefined,
    tool: f.tools,
    started_by: f.startedBy || undefined,
    date_from: dayStart(f.from),
    date_to: dayEnd(f.to),
  };
  if (tab === "scans") {
    return { ...common, kind: f.kind || undefined, state: f.scanStates, verdict: f.verdicts };
  }
  return {
    ...common,
    source: f.source || undefined,
    severity: f.severities,
    cwe: f.cwe || undefined,
    cve: f.cve || undefined,
    q: f.q || undefined,
    state_now: f.statesNow,
    state_then: f.statesThen,
  };
}

export function useHistoryScans(filters: HistoryFilters, after: string | undefined, limit = 50) {
  const query = { ...filtersToQuery("scans", filters), after, limit };
  return useQuery({
    queryKey: ["history", "scans", query],
    queryFn: ({ signal }) => apiFetch<CursorPage<HistoryScan>>("/history/scans", { query, signal }),
    placeholderData: keepPreviousData,
  });
}

export function useHistoryFindings(filters: HistoryFilters, after: string | undefined, limit = 50) {
  const query = { ...filtersToQuery("findings", filters), after, limit };
  return useQuery({
    queryKey: ["history", "findings", query],
    queryFn: ({ signal }) =>
      apiFetch<CursorPage<HistoryFinding>>("/history/findings", { query, signal }),
    placeholderData: keepPreviousData,
  });
}

export type NamedOption = { id: string; name: string };

/** Applications for the filter drop-down (first 200 by name). */
export function useApplicationOptions() {
  return useQuery({
    queryKey: ["options", "applications"],
    queryFn: async ({ signal }) => {
      const page = await apiFetch<CursorPage<NamedOption>>("/applications", {
        query: { sort: "name", limit: 200 },
        signal,
      });
      return page.items.map((a) => ({ id: a.id, name: a.name }));
    },
    staleTime: 60_000,
  });
}

/** Vendors for the filter drop-down (first 200). */
export function useVendorOptions() {
  return useQuery({
    queryKey: ["options", "vendors"],
    queryFn: async ({ signal }) => {
      const page = await apiFetch<CursorPage<NamedOption>>("/vendors", {
        query: { limit: 200 },
        signal,
      });
      return page.items.map((v) => ({ id: v.id, name: v.name }));
    },
    staleTime: 60_000,
  });
}
