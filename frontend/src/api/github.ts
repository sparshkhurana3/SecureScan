/**
 * GitHub repositories found by the connected GitHub App (for the repository picker) and the vendor
 * credentials of repository targets (deploy keys and vendor-issued tokens).
 *
 * Types mirror `backend/securescan/api/github.py` and `credentials.py`. Secrets are never returned by
 * the API; a token typed into the form is sent once and the form clears it.
 */
import { useQuery } from "@tanstack/react-query";

import { listAll } from "./applications";
import { apiFetch } from "./client";

export type GithubRepository = {
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

/** Repositories that can be scanned: still on GitHub and not archived. */
export function useGithubRepositories(search: string) {
  const q = search.trim();
  return useQuery({
    queryKey: ["github-repositories", q],
    queryFn: ({ signal }) =>
      listAll<GithubRepository>("/integrations/github/repositories", { q: q || undefined, removed: false }, 3, signal),
    staleTime: 30_000,
    select: (items) => items.filter((repo) => !repo.removed && !repo.archived && repo.full_name),
  });
}

export type CredentialKind = "deploy_key" | "vendor_token";

export type Credential = {
  id: string;
  kind: CredentialKind;
  name: string;
  target_id: string | null;
  application_id: string | null;
  version_id: string | null;
  public_key: string | null;
  fingerprint: string | null;
  expires_at: string | null;
  last_used_at: string | null;
  revoked_at: string | null;
  created_at: string;
};

export type DeployKey = Credential & { instructions: string };

export function useCredentials(versionId: string | null | undefined) {
  return useQuery({
    queryKey: ["credentials", versionId],
    queryFn: ({ signal }) => listAll<Credential>("/credentials", { version_id: versionId ?? undefined }, 2, signal),
    enabled: Boolean(versionId),
  });
}

export function createDeployKey(targetId: string, replace: boolean): Promise<DeployKey> {
  return apiFetch<DeployKey>("/credentials/deploy-key", {
    method: "POST",
    body: { target_id: targetId, replace },
  });
}

/** `expiresAt` is a date (`YYYY-MM-DD`); the token expires at the end of that day, UTC. */
export function createVendorToken(
  targetId: string,
  token: string,
  expiresAt: string,
  replace: boolean,
): Promise<Credential> {
  return apiFetch<Credential>("/credentials/vendor-token", {
    method: "POST",
    body: { target_id: targetId, token, expires_at: `${expiresAt}T23:59:59Z`, replace },
  });
}
