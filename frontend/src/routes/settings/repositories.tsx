import { Link } from "@tanstack/react-router";
import { type FormEvent, useState } from "react";

import {
  type GitHubRepository,
  type RepositoryFilters,
  useRepositories,
  useSetRepositoryFlags,
  useSyncGitHub,
} from "../../api/admin";
import { StatusBadge } from "../../components/StatusBadge";
import { Button } from "../../components/ui/button";
import { Checkbox } from "../../components/ui/checkbox";
import { Input } from "../../components/ui/input";
import {
  EmptyState,
  ErrorNotice,
  Field,
  LoadingText,
  LoadMore,
  PageHeader,
} from "../../components/ui/page";
import { Select } from "../../components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../../components/ui/table";
import { formatRelative, shortSha } from "../../lib/format";

const NO_FILTERS: RepositoryFilters = { q: "", confirmed: "", automatic: "", removed: "" };

function YesNoSelect({
  id,
  label,
  value,
  onChange,
}: {
  id: string;
  label: string;
  value: "" | "yes" | "no";
  onChange: (value: "" | "yes" | "no") => void;
}) {
  return (
    <Field id={id} label={label}>
      <Select id={id} value={value} onChange={(e) => onChange(e.target.value as "" | "yes" | "no")}>
        <option value="">Any</option>
        <option value="yes">Yes</option>
        <option value="no">No</option>
      </Select>
    </Field>
  );
}

function RepositoryRow({ repo }: { repo: GitHubRepository }) {
  const flags = useSetRepositoryFlags();
  const name = repo.full_name ?? String(repo.github_repo_id);
  return (
    <TableRow>
      <TableCell className="font-medium">
        {name}
        <span className="block text-xs font-normal text-muted-foreground">
          Branch {repo.default_branch ?? "-"}
        </span>
        {repo.removed ? (
          <StatusBadge status="failed" label="No longer on GitHub" className="mt-1" />
        ) : null}
        {repo.archived ? <StatusBadge status="disabled" label="Archived" className="mt-1" /> : null}
      </TableCell>
      <TableCell>
        <div className="flex items-center gap-2">
          <Checkbox
            id={`confirmed-${repo.application_id}`}
            aria-label={`Confirmed: ${name}`}
            checked={repo.confirmed}
            disabled={flags.isPending}
            onCheckedChange={(checked) =>
              flags.mutate({ applicationId: repo.application_id, confirmed: checked === true })
            }
          />
          <span className="text-xs text-muted-foreground">{repo.confirmed ? "Confirmed" : "Not confirmed"}</span>
        </div>
      </TableCell>
      <TableCell>
        <div className="flex items-center gap-2">
          <Checkbox
            id={`automatic-${repo.application_id}`}
            aria-label={`Scan automatically: ${name}`}
            checked={repo.automatic}
            disabled={flags.isPending || !repo.confirmed || repo.removed}
            onCheckedChange={(checked) =>
              flags.mutate({ applicationId: repo.application_id, automatic: checked === true })
            }
          />
          <span className="text-xs text-muted-foreground">
            {repo.automatic ? "On" : repo.confirmed ? "Off" : "Confirm first"}
          </span>
        </div>
        {flags.error ? <ErrorNotice error={flags.error} title="Not saved" className="mt-2" /> : null}
      </TableCell>
      <TableCell className="whitespace-nowrap">
        <span className="font-mono text-xs">{shortSha(repo.last_scanned_sha)}</span>
        <span className="block text-xs text-muted-foreground">{formatRelative(repo.last_scanned_at)}</span>
        {repo.last_scan_id ? (
          <Link to="/scans/$scanId" params={{ scanId: repo.last_scan_id }} className="text-xs underline">
            Last scan
          </Link>
        ) : null}
      </TableCell>
      <TableCell className="whitespace-nowrap">
        <span className="font-mono text-xs">{shortSha(repo.last_seen_sha)}</span>
        <span className="block text-xs text-muted-foreground">{formatRelative(repo.last_seen_at)}</span>
        {repo.last_poll_error ? <span className="block text-xs font-medium">{repo.last_poll_error}</span> : null}
      </TableCell>
    </TableRow>
  );
}

export function RepositoriesPage() {
  const [draft, setDraft] = useState<RepositoryFilters>(NO_FILTERS);
  const [applied, setApplied] = useState<RepositoryFilters>(NO_FILTERS);
  const repos = useRepositories(applied);
  const sync = useSyncGitHub();
  const items = repos.data?.pages.flatMap((page) => page.items) ?? [];

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setApplied(draft);
  };

  return (
    <>
      <PageHeader
        title="Repositories"
        description="Repositories found on GitHub. Confirm the ones SecureScan should know, then switch on automatic scans: a new commit on the default branch starts a scan within about 10 minutes."
        actions={
          <Button variant="outline" onClick={() => sync.mutate()} disabled={sync.isPending}>
            Find repositories now
          </Button>
        }
      />
      {sync.data ? (
        <p role="status" className="mb-3 text-sm font-medium">
          {sync.data.detail}
        </p>
      ) : null}
      {sync.error ? <ErrorNotice error={sync.error} title="Discovery could not be started" className="mb-3" /> : null}
      <form
        onSubmit={submit}
        aria-label="Repository filters"
        className="mb-4 grid gap-4 rounded-md border border-border p-4 sm:grid-cols-2 lg:grid-cols-5"
      >
        <Field id="repo-q" label="Name contains" className="lg:col-span-2">
          <Input id="repo-q" value={draft.q} onChange={(e) => setDraft({ ...draft, q: e.target.value })} />
        </Field>
        <YesNoSelect id="repo-confirmed" label="Confirmed" value={draft.confirmed} onChange={(v) => setDraft({ ...draft, confirmed: v })} />
        <YesNoSelect id="repo-automatic" label="Scanned automatically" value={draft.automatic} onChange={(v) => setDraft({ ...draft, automatic: v })} />
        <YesNoSelect id="repo-removed" label="Removed from GitHub" value={draft.removed} onChange={(v) => setDraft({ ...draft, removed: v })} />
        <div className="flex gap-2 sm:col-span-2 lg:col-span-5">
          <Button type="submit">Apply filters</Button>
          <Button
            type="button"
            variant="outline"
            onClick={() => {
              setDraft(NO_FILTERS);
              setApplied(NO_FILTERS);
            }}
          >
            Clear filters
          </Button>
        </div>
      </form>
      {repos.isPending ? <LoadingText>Loading repositories...</LoadingText> : null}
      {repos.isError ? (
        <ErrorNotice error={repos.error} title="Could not load repositories" onRetry={() => void repos.refetch()} />
      ) : null}
      {repos.data ? (
        items.length === 0 ? (
          <EmptyState>
            No repositories found. Check the GitHub connection and run discovery.
          </EmptyState>
        ) : (
          <Table aria-label="Repositories">
            <TableHeader>
              <TableRow>
                <TableHead>Repository</TableHead>
                <TableHead>Confirmed</TableHead>
                <TableHead>Automatic scans</TableHead>
                <TableHead>Last scanned commit</TableHead>
                <TableHead>Latest commit seen</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((repo) => (
                <RepositoryRow key={repo.application_id} repo={repo} />
              ))}
            </TableBody>
          </Table>
        )
      ) : null}
      <LoadMore
        hasMore={Boolean(repos.hasNextPage)}
        loading={repos.isFetchingNextPage}
        onClick={() => void repos.fetchNextPage()}
      />
    </>
  );
}
