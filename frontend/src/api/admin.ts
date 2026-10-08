/**
 * Administration APIs used by the Settings pages: system health, scan profiles, the GitHub
 * connection, discovered repositories and schedules.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch, type CursorPage, type QueryParams, useCursorList } from "./client";

// ---------------------------------------------------------------------------------- system health

export type MetricSample = { labels: Record<string, string>; value: number };

/** `HealthOut` of `GET /api/v1/admin/health`. */
export type SystemHealth = {
  /** `ok` or `degraded` */
  status: string;
  version: string;
  database: string;
  values: Record<string, unknown>;
  metrics: Record<string, MetricSample[]>;
};

export function useSystemHealth() {
  return useQuery({
    queryKey: ["admin", "health"],
    queryFn: ({ signal }) => apiFetch<SystemHealth>("/admin/health", { signal }),
    refetchInterval: 30_000,
  });
}

// ---------------------------------------------------------------------------------- scan profiles

/** `ProfileOut` of `GET /api/v1/profiles`. */
export type ScanProfile = {
  id: string;
  name: string;
  version: number;
  kind: string;
  mode: string | null;
  description: string | null;
  tools: string[];
  active: boolean;
  sha256: string;
  created_at: string;
};

export type ScanProfileDetail = ScanProfile & { body_yaml: string; body: Record<string, unknown> };

export function useProfiles(includeInactive = true) {
  return useQuery({
    queryKey: ["profiles", includeInactive],
    queryFn: async ({ signal }) => {
      const page = await apiFetch<CursorPage<ScanProfile>>("/profiles", {
        query: { include_inactive: includeInactive, limit: 200 },
        signal,
      });
      return page.items;
    },
  });
}

export function useProfileDetail(id: string | null) {
  return useQuery({
    queryKey: ["profiles", "detail", id],
    queryFn: ({ signal }) =>
      apiFetch<ScanProfileDetail>(`/profiles/${encodeURIComponent(String(id))}`, { signal }),
    enabled: id !== null,
  });
}

export function useCreateProfileVersion() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (yaml: string) =>
      apiFetch<ScanProfileDetail>("/profiles", { method: "POST", body: { yaml } }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["profiles"] }),
  });
}

export function useSetProfileActive() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ id, active }: { id: string; active: boolean }) =>
      apiFetch<ScanProfile>(`/profiles/${encodeURIComponent(id)}`, {
        method: "PATCH",
        body: { active },
      }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["profiles"] }),
  });
}

// ---------------------------------------------------------------------------------- GitHub connection

export type KeySlot = {
  present: boolean;
  source: "uploaded" | "secret_file" | null;
  fingerprint: string | null;
  added_at: string | null;
};

/** `GitHubConnectionOut`. Private keys are write-only: only a fingerprint comes back. */
export type GitHubConnection = {
  id: string;
  name: string;
  org_login: string | null;
  app_id: string;
  client_id: string;
  installation_id: string;
  api_base_url: string;
  git_host: string;
  api_version: string;
  active_key: 1 | 2;
  enabled: boolean;
  key_1: KeySlot;
  key_2: KeySlot;
  last_test_at: string | null;
  last_test_ok: boolean | null;
  last_test_message: string | null;
  last_sync_at: string | null;
  last_poll_at: string | null;
  last_poll_ok: boolean | null;
  last_poll_message: string | null;
  rate_limit_remaining: number | null;
  rate_limit_reset_at: string | null;
  updated_at: string;
};

export type GitHubStatus = { configured: boolean; connection: GitHubConnection | null };

export type GitHubConnectionInput = {
  name: string;
  app_id: string;
  client_id: string;
  installation_id: string;
  api_base_url: string;
  git_host: string;
  api_version: string;
  /** Leave out to keep the stored key. */
  private_key_1?: string;
  private_key_2?: string;
  clear_key_2?: boolean;
  active_key: 1 | 2;
  enabled: boolean;
};

export type GitHubTestResult = {
  status: "ok" | "failed" | "running";
  message: string;
  problems: string[];
  repositories: number | null;
  tested_at: string | null;
};

export const githubQueryKey = ["admin", "github"] as const;

/** True while the worker is running a connection test (the backend clears the result and sets a message). */
export function isTestRunning(connection: GitHubConnection | null | undefined): boolean {
  return (
    connection !== null &&
    connection !== undefined &&
    connection.last_test_at === null &&
    connection.last_test_ok === null &&
    connection.last_test_message !== null
  );
}

/** The connection; asks again every 3 seconds while a test is running. */
export function useGitHubConnection() {
  return useQuery({
    queryKey: githubQueryKey,
    queryFn: ({ signal }) => apiFetch<GitHubStatus>("/integrations/github", { signal }),
    refetchInterval: (query) => (isTestRunning(query.state.data?.connection) ? 3000 : false),
  });
}

export function useSaveGitHubConnection() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: GitHubConnectionInput) =>
      apiFetch<GitHubStatus>("/integrations/github", { method: "PUT", body }),
    onSuccess: (status) => client.setQueryData(githubQueryKey, status),
  });
}

/** Test the connection. The worker runs it; an answer with status `running` means "ask again". */
export function useTestGitHubConnection() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiFetch<GitHubTestResult>("/integrations/github/test", { method: "POST", query: { wait: 45 } }),
    onSettled: () => client.invalidateQueries({ queryKey: githubQueryKey }),
  });
}

export function useSyncGitHub() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiFetch<{ queued: boolean; detail: string }>("/integrations/github/sync", { method: "POST" }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["admin", "repositories"] }),
  });
}

// ---------------------------------------------------------------------------------- repositories

/** `GitHubRepositoryOut` of `GET /api/v1/integrations/github/repositories`. */
export type GitHubRepository = {
  application_id: string;
  github_repo_id: number;
  full_name: string | null;
  default_branch: string | null;
  confirmed: boolean;
  automatic: boolean;
  removed: boolean;
  removed_at: string | null;
  archived: boolean;
  last_seen_sha: string | null;
  last_scanned_sha: string | null;
  last_seen_at: string | null;
  last_scanned_at: string | null;
  last_scan_id: string | null;
  last_poll_error: string | null;
};

export type RepositoryFilters = {
  q: string;
  confirmed: "" | "yes" | "no";
  automatic: "" | "yes" | "no";
  removed: "" | "yes" | "no";
};

function triState(value: "" | "yes" | "no"): boolean | undefined {
  return value === "" ? undefined : value === "yes";
}

export function repositoryQuery(f: RepositoryFilters): QueryParams {
  return {
    q: f.q.trim() || undefined,
    confirmed: triState(f.confirmed),
    automatic: triState(f.automatic),
    removed: triState(f.removed),
  };
}

export function useRepositories(filters: RepositoryFilters) {
  return useCursorList<GitHubRepository>(
    ["admin", "repositories"],
    "/integrations/github/repositories",
    repositoryQuery(filters),
    { limit: 100 },
  );
}

/** Confirm a discovered repository or switch its automatic scans on or off. */
export function useSetRepositoryFlags() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({
      applicationId,
      ...flags
    }: {
      applicationId: string;
      confirmed?: boolean;
      automatic?: boolean;
    }) =>
      apiFetch<unknown>(`/applications/${encodeURIComponent(applicationId)}`, {
        method: "PATCH",
        body: flags,
      }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["admin", "repositories"] }),
  });
}

// ---------------------------------------------------------------------------------- schedules

export type ScheduleKind = "weekly" | "dast" | "poll";

/** `ScheduleOut` of `GET /api/v1/schedules`. */
export type Schedule = {
  id: string;
  name: string;
  kind: ScheduleKind;
  enabled: boolean;
  cron: string | null;
  poll_interval_minutes: number | null;
  blackout_windows: Record<string, unknown>[];
  repository_set: { mode?: string; application_ids?: string[] };
  target_id: string | null;
  profile_name: string | null;
  last_run_at: string | null;
  next_run_at: string | null;
  last_status: string | null;
  created_at: string;
  updated_at: string;
};

export type ScheduleInput = {
  name: string;
  kind: ScheduleKind;
  enabled?: boolean;
  cron?: string;
  poll_interval_minutes?: number;
  profile_name?: string;
  repository_set?: { mode: "automatic" };
};

export function useSchedules() {
  return useQuery({
    queryKey: ["admin", "schedules"],
    queryFn: async ({ signal }) => {
      const page = await apiFetch<CursorPage<Schedule>>("/schedules", {
        query: { limit: 200 },
        signal,
      });
      return page.items;
    },
  });
}

export function useCreateSchedule() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: ScheduleInput) => apiFetch<Schedule>("/schedules", { method: "POST", body }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["admin", "schedules"] }),
  });
}

export function useUpdateSchedule() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      ...body
    }: {
      id: string;
      name?: string;
      enabled?: boolean;
      cron?: string;
      poll_interval_minutes?: number;
      profile_name?: string;
    }) => apiFetch<Schedule>(`/schedules/${encodeURIComponent(id)}`, { method: "PATCH", body }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["admin", "schedules"] }),
  });
}

export function useDeleteSchedule() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<void>(`/schedules/${encodeURIComponent(id)}`, { method: "DELETE" }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["admin", "schedules"] }),
  });
}
