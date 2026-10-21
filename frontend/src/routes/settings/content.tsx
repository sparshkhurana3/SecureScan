import { errorMessage } from "../../api/client";
import { type ContentFeed, useContentVersions, useStartContentUpdate } from "../../api/operations";
import { StatusBadge } from "../../components/StatusBadge";
import { Button } from "../../components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../../components/ui/card";
import { EmptyState, ErrorNotice, LoadMore, LoadingText, PageHeader } from "../../components/ui/page";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../../components/ui/table";
import { formatDateTime } from "../../lib/format";

export const FEED_LABELS: Record<ContentFeed, string> = {
  semgrep_rules: "Semgrep rules",
  nuclei_templates: "Nuclei templates",
  grype_db: "Grype vulnerability database",
};

export function ContentPage() {
  const versions = useContentVersions();
  const update = useStartContentUpdate();
  const rows = versions.data?.pages.flatMap((page) => page.items) ?? [];
  const feeds = Object.keys(FEED_LABELS) as ContentFeed[];

  return (
    <>
      <PageHeader
        title="Scanner content"
        description="Rules and vulnerability data are updated by the worker. A new version becomes active only after the regression suite passes."
      />
      <Card>
        <CardHeader>
          <CardTitle>Update now</CardTitle>
          <CardDescription>
            Starts the update of one feed. It runs in the background; reload this page to follow it.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ul className="m-0 flex list-none flex-wrap gap-2 p-0">
            {feeds.map((feed) => (
              <li key={feed}>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={update.isPending}
                  onClick={() => update.mutate(feed)}
                  aria-label={`Update ${FEED_LABELS[feed]}`}
                >
                  Update {FEED_LABELS[feed]}
                </Button>
              </li>
            ))}
          </ul>
          {update.isError ? (
            <p role="alert" className="mt-3 text-sm font-semibold text-foreground">
              {errorMessage(update.error)}
            </p>
          ) : null}
          {update.data ? (
            <p role="status" className="mt-3 text-sm">
              {update.data.message}
            </p>
          ) : null}
        </CardContent>
      </Card>

      <section aria-labelledby="versions-title" className="mt-8">
        <h2 id="versions-title" className="mb-3 text-lg font-semibold">
          Content versions
        </h2>
        {versions.isPending ? <LoadingText>Loading versions...</LoadingText> : null}
        {versions.isError ? (
          <ErrorNotice
            error={versions.error}
            title="Could not list the content versions"
            onRetry={() => void versions.refetch()}
          />
        ) : null}
        {versions.data && rows.length === 0 ? <EmptyState>No content has been fetched yet.</EmptyState> : null}
        {rows.length > 0 ? (
          <Table aria-label="Content versions">
            <TableHeader>
              <TableRow>
                <TableHead>Feed</TableHead>
                <TableHead>Version</TableHead>
                <TableHead>Fetched</TableHead>
                <TableHead>Regression</TableHead>
                <TableHead>State</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((row) => (
                <TableRow key={row.id}>
                  <TableCell>{FEED_LABELS[row.feed] ?? row.feed}</TableCell>
                  <TableCell className="font-mono text-xs">{row.version}</TableCell>
                  <TableCell>{formatDateTime(row.fetched_at)}</TableCell>
                  <TableCell>{row.regression_result}</TableCell>
                  <TableCell>
                    <StatusBadge status={row.active ? "active" : "skipped"} label={row.active ? "Active" : "Not active"} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : null}
        <LoadMore
          hasMore={Boolean(versions.hasNextPage)}
          loading={versions.isFetchingNextPage}
          onClick={() => void versions.fetchNextPage()}
        />
      </section>
    </>
  );
}
