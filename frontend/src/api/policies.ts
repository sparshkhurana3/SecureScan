import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch, type CursorPage } from "./client";

export type DataClassificationName = "public" | "internal" | "confidential" | "restricted";

/** Open findings of a severity at which a verdict level is reached (a missing severity is not used). */
export type Thresholds = {
  fail: Record<string, number>;
  conditional: Record<string, number>;
};

/** `PolicyOut` of `GET /api/v1/policies`. */
export type Policy = {
  id: string;
  name: string;
  data_classification: string | null;
  application_id: string | null;
  is_default: boolean;
  thresholds: Partial<Thresholds>;
  version: number;
  active: boolean;
  created_at: string;
  updated_at: string;
};

export type PolicyCreate = {
  name: string;
  /** Exactly one of `is_default`, `data_classification` and `application_id`. */
  is_default?: boolean;
  data_classification?: DataClassificationName;
  application_id?: string;
  thresholds: Thresholds;
  active?: boolean;
};

export type PolicyUpdate = { name?: string; thresholds?: Thresholds; active?: boolean };

export type BuiltinPolicy = { name: string; thresholds: Thresholds };

export function usePolicies() {
  return useQuery({
    queryKey: ["policies"],
    queryFn: async ({ signal }) => {
      const page = await apiFetch<CursorPage<Policy>>("/policies", {
        query: { limit: 200 },
        signal,
      });
      return page.items;
    },
  });
}

export function useBuiltinPolicy() {
  return useQuery({
    queryKey: ["policies", "builtin"],
    queryFn: ({ signal }) => apiFetch<BuiltinPolicy>("/policies/builtin", { signal }),
    staleTime: 5 * 60_000,
  });
}

export function useCreatePolicy() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: PolicyCreate) => apiFetch<Policy>("/policies", { method: "POST", body }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["policies"] }),
  });
}

export function useUpdatePolicy() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...body }: PolicyUpdate & { id: string }) =>
      apiFetch<Policy>(`/policies/${encodeURIComponent(id)}`, { method: "PATCH", body }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["policies"] }),
  });
}

/** Human description of a policy scope. */
export function policyScope(policy: Pick<Policy, "is_default" | "data_classification" | "application_id">): string {
  if (policy.is_default) return "Default for everything else";
  if (policy.data_classification) return "Data classification: " + policy.data_classification;
  if (policy.application_id) return "One application";
  return "Not set";
}
