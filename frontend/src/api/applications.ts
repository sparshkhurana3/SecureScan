/**
 * Applications, versions and vendors: the inventory the scan forms pick from or add to.
 *
 * Types mirror `backend/securescan/api/applications.py`, `versions_targets.py` and `vendors.py`.
 * Hooks are TanStack Query hooks; the plain `async` functions are used by the scan forms, which
 * create what is missing (application, version) right before a scan starts.
 */
import { useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch, type CursorPage } from "./client";

export type AppType = "internal" | "vendor";
export type Hosting = "deployable" | "saas";
export type LabelKind = "branch" | "tag" | "upload" | "image_digest" | "release";
export type RiskTier = "low" | "medium" | "high" | "critical";

export type Application = {
  id: string;
  name: string;
  type: AppType;
  vendor_id: string | null;
  vendor_product: string | null;
  hosting: Hosting | null;
  description: string | null;
  criticality: string | null;
  data_classification: string | null;
  tags: string[];
  confirmed: boolean;
  automatic: boolean;
  github_repo_id: number | null;
  github_full_name: string | null;
  default_branch: string | null;
  dd_product_id: number | null;
  cached_counts: Record<string, unknown>;
  cached_counts_at: string | null;
  last_scan_at: string | null;
  last_scan_id: string | null;
  last_verdict: string | null;
  archived_at: string | null;
  created_at: string;
  updated_at: string;
};

export type Vendor = {
  id: string;
  name: string;
  contact_name: string | null;
  contact_email: string | null;
  risk_tier: RiskTier | null;
  notes: string | null;
  archived_at: string | null;
  created_at: string;
  updated_at: string;
};

export type AppVersion = {
  id: string;
  application_id: string;
  label: string;
  label_kind: string;
  description: string | null;
  commit_sha: string | null;
  dd_engagement_id: number | null;
  archived_at: string | null;
  created_at: string;
  updated_at: string;
};

/** Reads every page of a cursor list (at most `maxPages` pages of 200). */
export async function listAll<T>(
  path: string,
  query: Record<string, string | number | boolean | undefined> = {},
  maxPages = 10,
  signal?: AbortSignal,
): Promise<T[]> {
  const items: T[] = [];
  let after: string | undefined;
  for (let page = 0; page < maxPages; page += 1) {
    const result = await apiFetch<CursorPage<T>>(path, { query: { ...query, limit: 200, after }, signal });
    items.push(...result.items);
    if (!result.next_cursor) break;
    after = result.next_cursor;
  }
  return items;
}

// --------------------------------------------------------------------------- queries
export const applicationsKey = ["applications"] as const;
export const vendorsKey = ["vendors"] as const;

/** Every active application, by name. */
export function useApplications() {
  return useQuery({
    queryKey: applicationsKey,
    queryFn: ({ signal }) => listAll<Application>("/applications", { sort: "name" }, 10, signal),
    staleTime: 30_000,
  });
}

export function useVendors() {
  return useQuery({
    queryKey: vendorsKey,
    queryFn: ({ signal }) => listAll<Vendor>("/vendors", {}, 5, signal),
    staleTime: 30_000,
  });
}

/** The versions of one application (newest first). Disabled until an application is chosen. */
export function useVersions(applicationId: string | null | undefined) {
  return useQuery({
    queryKey: ["versions", applicationId],
    queryFn: ({ signal }) => listAll<AppVersion>(`/applications/${applicationId ?? ""}/versions`, {}, 5, signal),
    enabled: Boolean(applicationId),
    staleTime: 15_000,
  });
}

/** One version (used to turn the version id of a scan or target into a label and an application). */
export function fetchVersion(versionId: string, signal?: AbortSignal): Promise<AppVersion> {
  return apiFetch<AppVersion>(`/versions/${versionId}`, { signal });
}

export function useInvalidateInventory() {
  const queryClient = useQueryClient();
  return () => {
    void queryClient.invalidateQueries({ queryKey: applicationsKey });
    void queryClient.invalidateQueries({ queryKey: vendorsKey });
    void queryClient.invalidateQueries({ queryKey: ["versions"] });
  };
}

// --------------------------------------------------------------------------- writes
export type ApplicationCreate = {
  name: string;
  type: AppType;
  vendor_id?: string | null;
  vendor_product?: string | null;
  hosting?: Hosting | null;
};

export function createApplication(body: ApplicationCreate): Promise<Application> {
  return apiFetch<Application>("/applications", { method: "POST", body });
}

export function createVendor(name: string): Promise<Vendor> {
  return apiFetch<Vendor>("/vendors", { method: "POST", body: { name } });
}

export function createVersion(
  applicationId: string,
  label: string,
  labelKind: LabelKind,
): Promise<AppVersion> {
  return apiFetch<AppVersion>(`/applications/${applicationId}/versions`, {
    method: "POST",
    body: { label, label_kind: labelKind },
  });
}

/** The version with this label (case-sensitive, as the backend compares) or a new one. */
export async function findOrCreateVersion(
  applicationId: string,
  label: string,
  labelKind: LabelKind,
): Promise<AppVersion> {
  const clean = label.trim();
  const versions = await listAll<AppVersion>(`/applications/${applicationId}/versions`, {}, 5);
  const existing = versions.find((version) => version.label === clean);
  return existing ?? createVersion(applicationId, clean, labelKind);
}

// --------------------------------------------------------------------------- the application choice of the forms
/** What the person chose in the "Application" part of a form. */
export type ApplicationChoice =
  | { kind: "existing"; application: Application | null }
  | {
      kind: "new";
      name: string;
      type: AppType;
      /** An existing vendor id, or "new" to create one from `newVendorName`. */
      vendorId: string;
      newVendorName: string;
      vendorProduct: string;
      hosting: Hosting | "";
    };

export function emptyApplicationChoice(): ApplicationChoice {
  return {
    kind: "new",
    name: "",
    type: "internal",
    vendorId: "",
    newVendorName: "",
    vendorProduct: "",
    hosting: "",
  };
}

/** Field errors of an application choice, keyed by field name (empty object when valid). */
export function validateApplicationChoice(choice: ApplicationChoice): Record<string, string> {
  const errors: Record<string, string> = {};
  if (choice.kind === "existing") {
    if (!choice.application) errors.application = "Choose an application.";
    return errors;
  }
  const name = choice.name.trim();
  if (!name) errors.name = "Enter the application name.";
  else if (name.length > 200) errors.name = "The name is limited to 200 characters.";
  if (choice.type === "vendor") {
    if (!choice.vendorId) errors.vendor = "Choose the vendor or add a new one.";
    else if (choice.vendorId === "new" && !choice.newVendorName.trim()) {
      errors.vendor = "Enter the new vendor's name.";
    }
    if (!choice.hosting) errors.hosting = "Say whether the product is deployable or SaaS.";
    if (choice.vendorProduct.length > 200) errors.vendorProduct = "The product name is limited to 200 characters.";
  }
  return errors;
}

/** Returns the chosen application, creating it (and a new vendor) when the choice is a new one. */
export async function resolveApplication(choice: ApplicationChoice): Promise<Application> {
  if (choice.kind === "existing") {
    if (!choice.application) throw new Error("Choose an application.");
    return choice.application;
  }
  let vendorId: string | null = null;
  if (choice.type === "vendor") {
    vendorId = choice.vendorId;
    if (vendorId === "new") vendorId = (await createVendor(choice.newVendorName.trim())).id;
  }
  return createApplication({
    name: choice.name.trim(),
    type: choice.type,
    vendor_id: vendorId,
    vendor_product: choice.type === "vendor" ? choice.vendorProduct.trim() || null : null,
    hosting: choice.type === "vendor" && choice.hosting ? choice.hosting : null,
  });
}

/** True for a vendor application that is hosted by the vendor (DAST needs the vendor's authorization). */
export function isVendorSaas(application: Pick<Application, "type" | "hosting"> | null | undefined): boolean {
  return application?.type === "vendor" && application.hosting === "saas";
}
