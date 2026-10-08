import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

/** Join class names; later Tailwind classes win over earlier conflicting ones. */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

export type SearchValue = string | string[];
export type SearchObject = Record<string, SearchValue>;

/**
 * Parse a URL query string into `{ key: "value" }` or, for a repeated key, `{ key: ["a", "b"] }`.
 * Values stay strings (the router's default would turn `?cwe=79` into a number).
 */
export function parseSearchString(search: string): SearchObject {
  const params = new URLSearchParams(search.startsWith("?") ? search.slice(1) : search);
  const out: SearchObject = {};
  for (const key of new Set(params.keys())) {
    const values = params.getAll(key);
    if (values.length === 1) out[key] = values[0] ?? "";
    else if (values.length > 1) out[key] = values;
  }
  return out;
}

/** The inverse of `parseSearchString`: a leading `?`, or an empty string when nothing is set. */
export function stringifySearchObject(search: Record<string, unknown>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(search)) {
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value)) {
      for (const item of value as unknown[]) {
        if (typeof item === "string" || typeof item === "number" || typeof item === "boolean") {
          params.append(key, String(item));
        }
      }
    } else if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
      params.append(key, String(value));
    }
  }
  const text = params.toString();
  return text ? "?" + text : "";
}

/** Only same-origin relative paths may be used as a sign-in return address. */
export function safeNextPath(next: unknown): string {
  if (typeof next !== "string") return "/";
  if (!next.startsWith("/") || next.startsWith("//") || next.startsWith("/\\")) return "/";
  if (next.startsWith("/login")) return "/";
  return next;
}
