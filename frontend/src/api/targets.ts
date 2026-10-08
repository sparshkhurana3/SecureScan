/**
 * Scan targets: repositories, uploads and images (code scans) and registered web addresses (DAST).
 *
 * Types mirror `backend/securescan/api/versions_targets.py`. A target belongs to one application version.
 * The functions at the end are pure helpers of the DAST target form (which scan modes an environment
 * tag allows, validation, request bodies, blackout windows as text) and are unit tested.
 */
import { useQuery } from "@tanstack/react-query";

import { isVendorSaas, listAll, type Application, type ApplicationChoice } from "./applications";
import { apiFetch } from "./client";

export type TargetKind = "github_repo" | "vendor_repo" | "zip" | "image" | "url";
export type Environment = "production" | "uat";

export type BlackoutWindow = {
  starts_at?: string;
  ends_at?: string;
  days?: number[];
  start?: string;
  end?: string;
  reason?: string;
};

export type Target = {
  id: string;
  version_id: string;
  kind: TargetKind;
  name: string | null;
  locator: string;
  environment: Environment | null;
  environment_set_by_id: string | null;
  environment_set_at: string | null;
  credential_id: string | null;
  login_profile_id: string | null;
  upload_artifact_id: string | null;
  default_branch: string | null;
  scope_includes: string[];
  scope_excludes: string[];
  api_spec_type: string | null;
  api_spec_locator: string | null;
  api_spec_artifact_id: string | null;
  rate_limit_rps: number | null;
  blackout_windows: BlackoutWindow[];
  dast_cron: string | null;
  host_approved: boolean;
  vendor_authorization_artifact_id: string | null;
  vendor_authorized_from: string | null;
  vendor_authorized_until: string | null;
  vendor_contact: string | null;
  vendor_authorization_notes: string | null;
  archived_at: string | null;
  created_at: string;
  updated_at: string;
};

export const urlTargetsKey = ["targets", "url"] as const;

/** Every registered (not archived) web address. */
export function useUrlTargets() {
  return useQuery({
    queryKey: urlTargetsKey,
    queryFn: ({ signal }) => listAll<Target>("/targets", { kind: "url" }, 10, signal),
    refetchInterval: 30_000,
  });
}

export function listVersionTargets(versionId: string): Promise<Target[]> {
  return listAll<Target>(`/versions/${versionId}/targets`, {}, 5);
}

export type TargetBody = Record<string, unknown>;

export function createTarget(versionId: string, body: TargetBody): Promise<Target> {
  return apiFetch<Target>(`/versions/${versionId}/targets`, { method: "POST", body });
}

export function updateTarget(targetId: string, body: TargetBody): Promise<Target> {
  return apiFetch<Target>(`/targets/${targetId}`, { method: "PATCH", body });
}

export function archiveTarget(targetId: string): Promise<void> {
  return apiFetch<void>(`/targets/${targetId}`, { method: "DELETE" });
}

/** The version's target of this kind and locator (repositories and images are reused), or a new one. */
export async function findOrCreateTarget(
  versionId: string,
  kind: Exclude<TargetKind, "url" | "zip">,
  locator: string,
  extra: TargetBody = {},
): Promise<Target> {
  const wanted = locator.trim();
  const targets = await listVersionTargets(versionId);
  const existing = targets.find(
    (target) => target.kind === kind && target.locator === wanted && target.archived_at === null,
  );
  return existing ?? createTarget(versionId, { kind, locator: wanted, ...extra });
}

// --------------------------------------------------------------------------- scan modes per environment
export type DastMode = "baseline" | "full" | "api" | "nuclei";

export const DAST_MODES: readonly DastMode[] = ["baseline", "full", "api", "nuclei"];

export const MODE_LABELS: Record<DastMode, string> = {
  baseline: "Baseline (passive, unauthenticated)",
  full: "Full active scan",
  api: "API scan",
  nuclei: "Nuclei templates",
};

export const MODE_HINTS: Record<DastMode, string> = {
  baseline: "ZAP spider and passive checks only. Safe for production.",
  full: "ZAP active scan with Nuclei. UAT only.",
  api: "ZAP API scan from the API definition. UAT only.",
  nuclei: "Nuclei template checks. UAT only.",
};

/**
 * The scan modes an environment tag allows. Production: the unauthenticated baseline only. UAT: all four.
 * No tag: none (the target has to be tagged first). The API enforces the same rule; this only reflects it.
 */
export function modesForEnvironment(environment: Environment | null | undefined): DastMode[] {
  if (environment === "production") return ["baseline"];
  if (environment === "uat") return [...DAST_MODES];
  return [];
}

/** Login profiles are for UAT targets only. */
export function loginProfileAllowed(environment: Environment | "" | null | undefined): boolean {
  return environment === "uat";
}

// --------------------------------------------------------------------------- blackout windows as text
const DAY_NAMES = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"] as const;
const DAY_FULL = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"] as const;
const TIME = /^([01]\d|2[0-3]):[0-5]\d$/;

export type BlackoutParse = { ok: true; window: BlackoutWindow } | { ok: false; message: string };

/**
 * One window per line, times in UTC:
 *   `Mon,Tue 22:00-23:30 nightly batch`        weekly (days Mon..Sun, or 0..6 with 0 = Monday)
 *   `2026-10-10T22:00Z/2026-10-11T02:00Z freeze`   one-off interval
 * Text after the time or interval is the reason.
 */
export function parseBlackoutLine(line: string): BlackoutParse {
  const text = line.trim();
  const parts = text.split(/\s+/);
  const first = parts[0] ?? "";
  if (first.includes("/")) {
    const [from = "", to = ""] = first.split("/");
    const starts = new Date(from);
    const ends = new Date(to);
    if (Number.isNaN(starts.getTime()) || Number.isNaN(ends.getTime())) {
      return { ok: false, message: `"${first}" is not a pair of dates like 2026-10-10T22:00Z/2026-10-11T02:00Z.` };
    }
    if (ends <= starts) return { ok: false, message: "The end of a window must be after its start." };
    const reason = parts.slice(1).join(" ");
    return {
      ok: true,
      window: { starts_at: starts.toISOString(), ends_at: ends.toISOString(), ...(reason ? { reason } : {}) },
    };
  }
  const days: number[] = [];
  for (const raw of first.split(",")) {
    const token = raw.trim().toLowerCase();
    const index = DAY_NAMES.findIndex((name, position) => token === name || token === DAY_FULL[position]);
    const numeric = /^[0-6]$/.test(token) ? Number(token) : -1;
    const day = index >= 0 ? index : numeric;
    if (day < 0) return { ok: false, message: `"${raw}" is not a day. Use Mon, Tue, Wed, Thu, Fri, Sat or Sun.` };
    if (!days.includes(day)) days.push(day);
  }
  const range = (parts[1] ?? "").split("-");
  const start = range[0] ?? "";
  const end = range[1] ?? "";
  if (range.length !== 2 || !TIME.test(start) || !TIME.test(end)) {
    return { ok: false, message: "A weekly window needs times like 22:00-23:30 (UTC) after the days." };
  }
  const reason = parts.slice(2).join(" ");
  return { ok: true, window: { days: days.sort((a, b) => a - b), start, end, ...(reason ? { reason } : {}) } };
}

export function parseBlackoutText(text: string): { windows: BlackoutWindow[]; errors: string[] } {
  const windows: BlackoutWindow[] = [];
  const errors: string[] = [];
  splitLines(text).forEach((line, index) => {
    const parsed = parseBlackoutLine(line);
    if (parsed.ok) windows.push(parsed.window);
    else errors.push(`Line ${String(index + 1)}: ${parsed.message}`);
  });
  return { windows, errors };
}

export function formatBlackoutWindow(window: BlackoutWindow): string {
  const reason = window.reason ? ` ${window.reason}` : "";
  if (window.starts_at && window.ends_at) return `${window.starts_at}/${window.ends_at}${reason}`;
  const days = (window.days ?? []).map((day) => {
    const name = DAY_NAMES[day] ?? String(day);
    return name.charAt(0).toUpperCase() + name.slice(1);
  });
  return `${days.join(",")} ${window.start ?? ""}-${window.end ?? ""}${reason}`;
}

export function splitLines(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== "");
}

// --------------------------------------------------------------------------- the target form
export type TargetFormValues = {
  application: ApplicationChoice;
  versionLabel: string;
  name: string;
  url: string;
  environment: Environment | "";
  scopeIncludes: string;
  scopeExcludes: string;
  apiSpecType: "" | "openapi" | "graphql" | "soap";
  apiSpecLocator: string;
  rateLimit: string;
  blackouts: string;
  cron: string;
  loginProfileId: string;
  hostApproved: boolean;
  vendorAuthorizationArtifactId: string;
  vendorAuthorizationFilename: string;
  vendorAuthorizedFrom: string;
  vendorAuthorizedUntil: string;
  vendorContact: string;
  vendorNotes: string;
};

export function emptyTargetForm(application: ApplicationChoice): TargetFormValues {
  return {
    application,
    versionLabel: "",
    name: "",
    url: "",
    environment: "",
    scopeIncludes: "",
    scopeExcludes: "",
    apiSpecType: "",
    apiSpecLocator: "",
    rateLimit: "",
    blackouts: "",
    cron: "",
    loginProfileId: "",
    hostApproved: false,
    vendorAuthorizationArtifactId: "",
    vendorAuthorizationFilename: "",
    vendorAuthorizedFrom: "",
    vendorAuthorizedUntil: "",
    vendorContact: "",
    vendorNotes: "",
  };
}

/** Form values of an existing target (the application part is chosen by the caller). */
export function targetToForm(target: Target, application: ApplicationChoice, versionLabel: string): TargetFormValues {
  return {
    application,
    versionLabel,
    name: target.name ?? "",
    url: target.locator,
    environment: target.environment ?? "",
    scopeIncludes: target.scope_includes.join("\n"),
    scopeExcludes: target.scope_excludes.join("\n"),
    apiSpecType: (target.api_spec_type as TargetFormValues["apiSpecType"] | null) ?? "",
    apiSpecLocator: target.api_spec_locator ?? "",
    rateLimit: target.rate_limit_rps === null ? "" : String(target.rate_limit_rps),
    blackouts: target.blackout_windows.map(formatBlackoutWindow).join("\n"),
    cron: target.dast_cron ?? "",
    loginProfileId: target.login_profile_id ?? "",
    hostApproved: target.host_approved,
    vendorAuthorizationArtifactId: target.vendor_authorization_artifact_id ?? "",
    vendorAuthorizationFilename: target.vendor_authorization_artifact_id ? "Document on file" : "",
    vendorAuthorizedFrom: (target.vendor_authorized_from ?? "").slice(0, 10),
    vendorAuthorizedUntil: (target.vendor_authorized_until ?? "").slice(0, 10),
    vendorContact: target.vendor_contact ?? "",
    vendorNotes: target.vendor_authorization_notes ?? "",
  };
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CRON_FIELD = /^[0-9A-Za-z*/,\-?]+$/;

export function isValidUrl(text: string): boolean {
  try {
    const url = new URL(text.trim());
    return (url.protocol === "http:" || url.protocol === "https:") && url.hostname !== "" && !url.username && !url.password;
  } catch {
    return false;
  }
}

export type TargetFormContext = {
  mode: "create" | "edit";
  /** The application the target belongs to (new applications are described by the form's own choice). */
  application: Pick<Application, "type" | "hosting"> | null;
};

/** Field errors keyed by field name (an empty object means the form can be sent). */
export function validateTargetForm(values: TargetFormValues, context: TargetFormContext): Record<string, string> {
  const errors: Record<string, string> = {};
  if (!values.url.trim()) errors.url = "Enter the address to scan, for example https://app.example.com.";
  else if (!isValidUrl(values.url)) {
    errors.url = "Use an http:// or https:// address without a user name or password in it.";
  }
  if (!values.environment) errors.environment = "Tag the target as production or UAT.";
  if (values.name.length > 200) errors.name = "The name is limited to 200 characters.";
  if (context.mode === "create" && !values.versionLabel.trim()) {
    errors.versionLabel = "Enter a version label, for example the release or environment name.";
  }
  if (values.rateLimit.trim()) {
    const rate = Number(values.rateLimit);
    if (!Number.isInteger(rate) || rate < 1 || rate > 1000) {
      errors.rateLimit = "The request limit is a whole number from 1 to 1000 requests per second.";
    }
  }
  if (values.cron.trim()) {
    const fields = values.cron.trim().split(/\s+/);
    if (fields.length !== 5 || !fields.every((field) => CRON_FIELD.test(field))) {
      errors.cron = "A schedule has five fields: minute hour day-of-month month day-of-week (UTC).";
    }
  }
  const blackouts = parseBlackoutText(values.blackouts);
  if (blackouts.errors.length > 0) errors.blackouts = blackouts.errors.join(" ");
  if (values.apiSpecType && !values.apiSpecLocator.trim()) {
    errors.apiSpecLocator = "Give the address of the API definition, or clear the type.";
  }
  if (values.apiSpecLocator.trim() && !values.apiSpecType) {
    errors.apiSpecType = "Choose the type of the API definition.";
  }
  if (values.loginProfileId.trim()) {
    if (!loginProfileAllowed(values.environment)) {
      errors.loginProfileId = "A login profile is allowed on UAT targets only.";
    } else if (!UUID.test(values.loginProfileId.trim())) {
      errors.loginProfileId = "A login profile id looks like 3f2b8c1e-0000-4000-8000-000000000000.";
    }
  }
  if (isVendorSaas(context.application)) {
    if (!values.vendorAuthorizationArtifactId) {
      errors.vendorAuthorization = "Upload the vendor's written authorization before scanning a vendor SaaS product.";
    }
    if (!values.vendorAuthorizedFrom) errors.vendorAuthorizedFrom = "Enter the first day of the vendor's scan window.";
    if (!values.vendorAuthorizedUntil) errors.vendorAuthorizedUntil = "Enter the last day of the vendor's scan window.";
    if (
      values.vendorAuthorizedFrom &&
      values.vendorAuthorizedUntil &&
      values.vendorAuthorizedUntil < values.vendorAuthorizedFrom
    ) {
      errors.vendorAuthorizedUntil = "The window ends before it starts.";
    }
    if (!values.vendorContact.trim()) errors.vendorContact = "Enter the vendor's contact for scan problems.";
  }
  return errors;
}

function textOrNull(text: string): string | null {
  const clean = text.trim();
  return clean === "" ? null : clean;
}

/** Fields sent on create and on update. Cleared fields are sent as null or an empty list on update. */
function commonFields(values: TargetFormValues, application: Pick<Application, "type" | "hosting"> | null) {
  const login = loginProfileAllowed(values.environment) ? textOrNull(values.loginProfileId) : null;
  const saas = isVendorSaas(application);
  return {
    name: textOrNull(values.name),
    scope_includes: splitLines(values.scopeIncludes),
    scope_excludes: splitLines(values.scopeExcludes),
    api_spec_type: values.apiSpecType || null,
    api_spec_locator: values.apiSpecType ? textOrNull(values.apiSpecLocator) : null,
    rate_limit_rps: values.rateLimit.trim() ? Number(values.rateLimit) : null,
    blackout_windows: parseBlackoutText(values.blackouts).windows,
    dast_cron: textOrNull(values.cron),
    login_profile_id: login,
    ...(saas
      ? {
          vendor_authorization_artifact_id: textOrNull(values.vendorAuthorizationArtifactId),
          vendor_authorized_from: values.vendorAuthorizedFrom ? `${values.vendorAuthorizedFrom}T00:00:00Z` : null,
          vendor_authorized_until: values.vendorAuthorizedUntil ? `${values.vendorAuthorizedUntil}T23:59:59Z` : null,
          vendor_contact: textOrNull(values.vendorContact),
          vendor_authorization_notes: textOrNull(values.vendorNotes),
        }
      : {}),
  };
}

/** Body of `POST /versions/{id}/targets`. `host_approved` is sent only by an Admin who ticked it. */
export function buildTargetCreateBody(
  values: TargetFormValues,
  application: Pick<Application, "type" | "hosting"> | null,
  isAdmin: boolean,
): TargetBody {
  const fields = commonFields(values, application);
  const body: TargetBody = { kind: "url", locator: values.url.trim(), environment: values.environment || null };
  for (const [key, value] of Object.entries(fields)) {
    const empty = value === null || (Array.isArray(value) && value.length === 0);
    if (!empty) body[key] = value;
  }
  if (isAdmin && values.hostApproved) body.host_approved = true;
  return body;
}

/** Body of `PATCH /targets/{id}`: everything the form shows, so that clearing a field clears it. */
export function buildTargetUpdateBody(
  values: TargetFormValues,
  application: Pick<Application, "type" | "hosting"> | null,
  isAdmin: boolean,
  original: Pick<Target, "host_approved">,
): TargetBody {
  const body: TargetBody = {
    locator: values.url.trim(),
    environment: values.environment || null,
    ...commonFields(values, application),
  };
  if (isAdmin && values.hostApproved !== original.host_approved) body.host_approved = values.hostApproved;
  return body;
}

/** A short line for lists: the vendor authorization of a target, or why it is missing. */
export function authorizationSummary(target: Target, application: Pick<Application, "type" | "hosting"> | null): string {
  if (!isVendorSaas(application)) return "Not needed";
  if (!target.vendor_authorization_artifact_id) return "Missing";
  const until = target.vendor_authorized_until?.slice(0, 10);
  return until ? `On file until ${until}` : "On file";
}
