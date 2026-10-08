import { useQuery } from "@tanstack/react-query";

import { ApiError, apiFetch, setCsrfFallback } from "./client";

export type Role = "Admin" | "Analyst";

/** `GET /api/v1/me` as the backend sends it (`MeOut`). */
export type ApiMe = {
  id: string;
  name: string | null;
  email: string | null;
  role: Role;
  roles: string[];
  csrf_token: string;
  last_login: string | null;
  defectdojo_url: string;
};

/** The signed-in user as the portal uses it. */
export type Me = {
  id: string;
  name: string;
  email: string;
  role: Role;
  /** Public address of DefectDojo (no trailing slash). */
  defectdojoUrl: string;
  lastLogin: string | null;
};

export function toMe(raw: ApiMe): Me {
  return {
    id: raw.id,
    name: raw.name ?? raw.email ?? "Signed-in user",
    email: raw.email ?? "",
    role: raw.role,
    defectdojoUrl: raw.defectdojo_url.replace(/\/+$/, ""),
    lastLogin: raw.last_login,
  };
}

export const meQueryKey = ["me"] as const;

/** The current user, or null when nobody is signed in (HTTP 401). Other failures are thrown. */
export async function fetchMe(signal?: AbortSignal): Promise<Me | null> {
  try {
    const raw = await apiFetch<ApiMe>("/me", { signal });
    setCsrfFallback(raw.csrf_token);
    return toMe(raw);
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      setCsrfFallback(null);
      return null;
    }
    throw error;
  }
}

export function useMeQuery() {
  return useQuery({
    queryKey: meQueryKey,
    queryFn: ({ signal }) => fetchMe(signal),
    retry: false,
    staleTime: 60_000,
    refetchOnWindowFocus: true,
  });
}

export async function signOut(): Promise<void> {
  await apiFetch<void>("/auth/logout", { method: "POST" });
  setCsrfFallback(null);
}
