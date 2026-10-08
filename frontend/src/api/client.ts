/**
 * The only place that calls `fetch`. Every API module goes through `apiFetch`.
 *
 * - Base path `/api/v1`, credentials `same-origin` (the session cookie is HttpOnly).
 * - Unsafe methods (anything but GET, HEAD, OPTIONS) send the CSRF token from the `securescan_csrf`
 *   cookie in the `X-CSRF-Token` header.
 * - Failures throw `ApiError` carrying the parsed RFC 9457 problem body.
 */
import { useInfiniteQuery } from "@tanstack/react-query";

export const API_BASE = "/api/v1";
export const CSRF_COOKIE = "securescan_csrf";
export const CSRF_HEADER = "X-CSRF-Token";
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export type QueryValue = string | number | boolean | undefined;
/** Query parameters. An array repeats the key (`?tool=a&tool=b`); undefined and empty values are left out. */
export type QueryParams = Record<string, QueryValue | readonly string[]>;

export type Problem = {
  title: string;
  detail?: string;
  /** Stable machine-readable code (for example `policy.duplicate_classification`). */
  code?: string;
  /** Field errors of a 422 validation problem. */
  errors?: { field: string; message: string; code?: string }[];
};

export class ApiError extends Error {
  status: number;
  problem: Problem;

  constructor(status: number, problem: Problem) {
    super(problem.detail ?? problem.title);
    this.name = "ApiError";
    this.status = status;
    this.problem = problem;
  }
}

/** The text to show a person for any thrown value. */
export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return error.problem.detail ?? error.problem.title;
  if (error instanceof Error) return error.message;
  return "Something went wrong.";
}

export type ApiInit = {
  method?: string;
  body?: unknown;
  query?: QueryParams;
  signal?: AbortSignal;
  formData?: FormData;
  headers?: Record<string, string>;
};

// Used when the CSRF cookie cannot be read (for example a cookie scoped to another host name).
let csrfFallback: string | null = null;

export function setCsrfFallback(token: string | null): void {
  csrfFallback = token;
}

export function readCookie(name: string, source?: string): string | null {
  const cookies = source ?? (typeof document === "undefined" ? "" : document.cookie);
  for (const part of cookies.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    if (part.slice(0, index).trim() === name) {
      const raw = part.slice(index + 1).trim();
      try {
        return decodeURIComponent(raw);
      } catch {
        return raw;
      }
    }
  }
  return null;
}

function withBase(path: string): string {
  if (path.startsWith(API_BASE + "/") || path === API_BASE) return path;
  return API_BASE + (path.startsWith("/") ? path : "/" + path);
}

export function buildQueryString(query?: QueryParams): string {
  if (!query) return "";
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined) continue;
    if (typeof value === "object") {
      for (const item of value) {
        if (item !== "") params.append(key, item);
      }
    } else if (value !== "") {
      params.append(key, String(value));
    }
  }
  const text = params.toString();
  return text ? "?" + text : "";
}

/** A URL under `/api/v1` for links, downloads and iframes (GET only; the cookie authenticates). */
export function apiUrl(path: string, query?: QueryParams): string {
  return withBase(path) + buildQueryString(query);
}

async function readProblem(response: Response): Promise<Problem> {
  const fallbackTitle = response.statusText || "HTTP " + String(response.status);
  const type = response.headers.get("content-type") ?? "";
  if (!type.includes("json")) return { title: fallbackTitle };
  try {
    const body = (await response.json()) as Record<string, unknown> | null;
    if (body === null || typeof body !== "object") return { title: fallbackTitle };
    const problem: Problem = {
      title: typeof body.title === "string" && body.title ? body.title : fallbackTitle,
    };
    if (typeof body.detail === "string") problem.detail = body.detail;
    if (typeof body.code === "string") problem.code = body.code;
    if (Array.isArray(body.errors)) {
      problem.errors = (body.errors as unknown[]).flatMap((item) => {
        if (item === null || typeof item !== "object") return [];
        const entry = item as Record<string, unknown>;
        if (typeof entry.message !== "string") return [];
        return [
          {
            field: typeof entry.field === "string" ? entry.field : "",
            message: entry.message,
            ...(typeof entry.code === "string" ? { code: entry.code } : {}),
          },
        ];
      });
    }
    return problem;
  } catch {
    return { title: fallbackTitle };
  }
}

export async function apiFetch<T>(path: string, init: ApiInit = {}): Promise<T> {
  const method = (init.method ?? (init.body !== undefined || init.formData ? "POST" : "GET")).toUpperCase();
  const headers: Record<string, string> = { Accept: "application/json, text/html;q=0.5, */*;q=0.1" };
  Object.assign(headers, init.headers);
  if (!SAFE_METHODS.has(method)) {
    const token = readCookie(CSRF_COOKIE) ?? csrfFallback;
    if (token) headers[CSRF_HEADER] = token;
  }
  let body: BodyInit | undefined;
  if (init.formData) {
    body = init.formData; // the browser sets the multipart boundary
  } else if (init.body !== undefined) {
    body = JSON.stringify(init.body);
    headers["Content-Type"] = "application/json";
  }
  const response = await fetch(apiUrl(path, init.query), {
    method,
    headers,
    body,
    credentials: "same-origin",
    signal: init.signal,
  });
  if (!response.ok) throw new ApiError(response.status, await readProblem(response));
  if (response.status === 204 || response.status === 205) return undefined as T;
  const type = response.headers.get("content-type") ?? "";
  if (type.includes("json")) return (await response.json()) as T;
  return (await response.text()) as T;
}

/** A page of a list endpoint. `next_cursor` is null on the last page. */
export type CursorPage<T> = { items: T[]; next_cursor: string | null };

/** "Load more" list over a cursor-paged endpoint (`?after=<cursor>&limit=`). */
export function useCursorList<T>(
  key: readonly unknown[],
  path: string,
  query: QueryParams = {},
  options: { limit?: number; enabled?: boolean; refetchInterval?: number } = {},
) {
  const limit = options.limit ?? 50;
  return useInfiniteQuery({
    queryKey: [...key, query, limit],
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam, signal }) =>
      apiFetch<CursorPage<T>>(path, { query: { ...query, after: pageParam, limit }, signal }),
    getNextPageParam: (last) => last.next_cursor ?? undefined,
    enabled: options.enabled,
    refetchInterval: options.refetchInterval,
  });
}
