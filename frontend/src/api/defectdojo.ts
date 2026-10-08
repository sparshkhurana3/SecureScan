import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch, useCursorList } from "./client";

/** `DefectDojoStatusOut` of `GET /api/v1/integrations/defectdojo`. */
export type DefectDojoStatus = {
  reachable: boolean;
  http_status: number | null;
  latency_ms: number | null;
  expected_version: string;
  public_url: string;
  tokens_ready: boolean;
  accounts_token_ready: boolean;
  last_import_at: string | null;
  queue_depth: number;
  oldest_pending_seconds: number | null;
  dead_letters: number;
};

export type OutboxState = "pending" | "processing" | "done" | "dead_letter";

export type OutboxItem = {
  id: string;
  job_id: string;
  scan_id: string | null;
  tool: string | null;
  application_name: string | null;
  state: OutboxState;
  attempts: number;
  next_attempt_at: string;
  last_error: string | null;
  created_at: string;
  completed_at: string | null;
};

/** A user's DefectDojo account as an Admin sees it (`DefectDojoAccountOut`). */
export type DefectDojoAccount = {
  user_id: string;
  name: string | null;
  email: string | null;
  role: "Admin" | "Analyst";
  has_account: boolean;
  dd_username: string | null;
  dd_user_id: number | null;
  disabled: boolean;
  disabled_at: string | null;
  password_waiting: boolean;
  last_login: string | null;
  expires_at: string | null;
};

/** The signed-in user's own DefectDojo account (`GET /me/defectdojo-account`). */
export type MyDefectDojoAccount = {
  /** `ready`, `unavailable` or `disabled` */
  status: string;
  username: string | null;
  login_url: string;
  /** Present once only; the backend marks it as shown. */
  initial_password: string | null;
  password_shown: boolean;
  must_change_password: boolean;
  disabled: boolean;
  detail: string | null;
};

export type PasswordReset = {
  username: string | null;
  login_url: string;
  password: string;
  must_change_password: boolean;
};

/** The address of DefectDojo's sign-in page on the public (gateway) host. */
export function defectDojoLoginUrl(publicUrl: string): string {
  return publicUrl.replace(/\/+$/, "") + "/login";
}

export function useDefectDojoStatus() {
  return useQuery({
    queryKey: ["defectdojo", "status"],
    queryFn: ({ signal }) => apiFetch<DefectDojoStatus>("/integrations/defectdojo", { signal }),
    refetchInterval: 30_000,
  });
}

export function useOutbox(state: OutboxState | "") {
  return useCursorList<OutboxItem>(["defectdojo", "outbox"], "/integrations/defectdojo/outbox", {
    state: state || undefined,
  });
}

export function useReplayImport() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<OutboxItem>(`/integrations/defectdojo/outbox/${encodeURIComponent(id)}/replay`, {
        method: "POST",
      }),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ["defectdojo"] });
      await client.invalidateQueries({ queryKey: ["summary"] });
    },
  });
}

export function useDefectDojoAccounts() {
  return useCursorList<DefectDojoAccount>(["defectdojo", "accounts"], "/admin/defectdojo-accounts");
}

export function useSetAccountActive() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ userId, active }: { userId: string; active: boolean }) =>
      apiFetch<DefectDojoAccount>(
        `/admin/defectdojo-accounts/${encodeURIComponent(userId)}/${active ? "enable" : "disable"}`,
        { method: "POST" },
      ),
    onSuccess: () => client.invalidateQueries({ queryKey: ["defectdojo", "accounts"] }),
  });
}

export const myAccountQueryKey = ["defectdojo", "my-account"] as const;

/**
 * Your own DefectDojo account. The initial password comes back on the first call only (the backend
 * marks it shown), so this query is read once and kept in memory: never refetched on focus or mount.
 */
export function useMyDefectDojoAccount() {
  return useQuery({
    queryKey: myAccountQueryKey,
    queryFn: ({ signal }) =>
      apiFetch<MyDefectDojoAccount>("/me/defectdojo-account", { signal }),
    staleTime: Infinity,
    gcTime: Infinity,
    refetchOnMount: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    retry: 1,
  });
}

/** Forget the one-time password in memory (the person has saved it). */
export function useForgetInitialPassword() {
  const client = useQueryClient();
  return () => {
    client.setQueryData<MyDefectDojoAccount>(myAccountQueryKey, (old) =>
      old ? { ...old, initial_password: null, password_shown: true } : old,
    );
  };
}

export function useResetMyDefectDojoPassword() {
  return useMutation({
    mutationFn: () =>
      apiFetch<PasswordReset>("/me/defectdojo-account/reset", { method: "POST" }),
  });
}
