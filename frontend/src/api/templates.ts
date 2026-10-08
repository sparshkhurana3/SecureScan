import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch, apiUrl, type CursorPage } from "./client";

export type ReportKindName = "application" | "vendor";

/** `TemplateOut` of `GET /api/v1/templates`. */
export type ReportTemplate = {
  id: string;
  name: string;
  version: number;
  builtin: boolean;
  default_for_application: boolean;
  default_for_vendor: boolean;
  entry_file: string;
  sha256: string | null;
  validated_at: string | null;
  validation_error: string | null;
  active: boolean;
  created_by_id: string | null;
  created_at: string;
};

/** The shipped SonaComstar template as a zip (a starting point for a new template). */
export function defaultTemplateDownloadUrl(): string {
  return apiUrl("/templates/default/download");
}

export function templateDownloadUrl(id: string): string {
  return apiUrl(`/templates/${encodeURIComponent(id)}/download`);
}

/** Templates, including switched-off versions (Admin settings page). */
export function useTemplates(includeInactive = true) {
  return useQuery({
    queryKey: ["templates", includeInactive],
    queryFn: async ({ signal }) => {
      const page = await apiFetch<CursorPage<ReportTemplate>>("/templates", {
        query: { include_inactive: includeInactive, limit: 200 },
        signal,
      });
      return page.items;
    },
  });
}

export function useUploadTemplate() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ name, file }: { name: string; file: File }) => {
      const formData = new FormData();
      formData.append("name", name);
      formData.append("file", file);
      return apiFetch<ReportTemplate>("/templates", { method: "POST", formData });
    },
    onSuccess: () => client.invalidateQueries({ queryKey: ["templates"] }),
  });
}

/** Render a template with the sample snapshot; resolves to the HTML text. */
export function usePreviewTemplate() {
  return useMutation({
    mutationFn: ({ id, kind }: { id: string; kind: ReportKindName }) =>
      apiFetch<string>(`/templates/${encodeURIComponent(id)}/preview`, {
        method: "POST",
        query: { kind },
      }),
  });
}

export function useSetDefaultTemplate() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ id, kind }: { id: string; kind: ReportKindName }) =>
      apiFetch<ReportTemplate>(`/templates/${encodeURIComponent(id)}/default`, {
        method: "POST",
        body: { kind },
      }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["templates"] }),
  });
}

export function useSetTemplateActive() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ id, active }: { id: string; active: boolean }) =>
      apiFetch<ReportTemplate>(`/templates/${encodeURIComponent(id)}`, {
        method: "PATCH",
        body: { active },
      }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["templates"] }),
  });
}
