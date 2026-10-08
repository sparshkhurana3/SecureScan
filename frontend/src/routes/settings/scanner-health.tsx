import { type FeedHealth, type ToolHealth, useScannerHealth } from "../../api/operations";
import { StatusBadge } from "../../components/StatusBadge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../../components/ui/card";
import { EmptyState, ErrorNotice, LoadingText, PageHeader } from "../../components/ui/page";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../../components/ui/table";
import { formatDateTime, formatDuration } from "../../lib/format";

function shortDigest(digest: string | null): string {
  if (!digest) return "-";
  const value = digest.replace(/^sha256:/, "");
  return `sha256:${value.slice(0, 12)}`;
}

/** The words for a feed row: a failed update beats stale data beats a good state. */
export function feedStatus(feed: FeedHealth): { status: string; label: string } {
  if (feed.update_failed) return { status: "failed", label: "Update failed" };
  if (feed.stale) return { status: "degraded", label: "Too old" };
  if (feed.version === null) return { status: "pending", label: "Not loaded yet" };
  return { status: "ok", label: "Current" };
}

/** True when the last job ran another digest than the one in use now: worth a look. */
export function digestDiffers(tool: ToolHealth): boolean {
  return Boolean(tool.last_job_digest && tool.digest && tool.last_job_digest !== tool.digest);
}

export function ScannerHealthPage() {
  const health = useScannerHealth();
  return (
    <>
      <PageHeader
        title="Scanner health"
        description="Which image each scanner runs, when it last worked, and how old its rules and vulnerability data are. This page refreshes every minute."
      />
      {health.isPending ? <LoadingText>Loading scanner health...</LoadingText> : null}
      {health.isError ? (
        <ErrorNotice
          error={health.error}
          title="Could not read the scanner health"
          onRetry={() => void health.refetch()}
        />
      ) : null}
      {health.data ? (
        <>
          <Card>
            <CardHeader>
              <CardTitle>Overall</CardTitle>
              <CardDescription>
                Generated {formatDateTime(health.data.generated_at)}. Needs attention means a data feed is too old or
                its last update failed.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <StatusBadge
                status={health.data.status === "ok" ? "ok" : "degraded"}
                label={health.data.status === "ok" ? "OK" : "Needs attention"}
              />
              {health.data.notes.length > 0 ? (
                <ul className="mt-3 list-disc pl-5 text-sm text-muted-foreground">
                  {health.data.notes.map((note) => (
                    <li key={note}>{note}</li>
                  ))}
                </ul>
              ) : null}
            </CardContent>
          </Card>

          <section aria-labelledby="feeds-title" className="mt-8">
            <h2 id="feeds-title" className="mb-3 text-lg font-semibold">
              Rules and vulnerability data
            </h2>
            {health.data.feeds.length === 0 ? (
              <EmptyState>No feeds are tracked.</EmptyState>
            ) : (
              <Table aria-label="Data feeds">
                <TableHeader>
                  <TableRow>
                    <TableHead>Feed</TableHead>
                    <TableHead>Version</TableHead>
                    <TableHead>Age</TableHead>
                    <TableHead>Limit</TableHead>
                    <TableHead>Regression</TableHead>
                    <TableHead>State</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {health.data.feeds.map((feed) => {
                    const state = feedStatus(feed);
                    return (
                      <TableRow key={feed.feed}>
                        <TableCell>{feed.label}</TableCell>
                        <TableCell className="font-mono text-xs">{feed.version ?? "-"}</TableCell>
                        <TableCell>{feed.age_seconds === null ? "-" : formatDuration(feed.age_seconds)}</TableCell>
                        <TableCell>{feed.limit_days} days</TableCell>
                        <TableCell>{feed.regression_result ?? "-"}</TableCell>
                        <TableCell>
                          <StatusBadge status={state.status} label={state.label} />
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            )}
          </section>

          <section aria-labelledby="tools-title" className="mt-8">
            <h2 id="tools-title" className="mb-3 text-lg font-semibold">
              Scanners
            </h2>
            <Table aria-label="Scanners">
              <TableHeader>
                <TableRow>
                  <TableHead>Tool</TableHead>
                  <TableHead>Image</TableHead>
                  <TableHead>Digest</TableHead>
                  <TableHead>Last success</TableHead>
                  <TableHead>Last failure</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {health.data.tools.map((tool) => (
                  <TableRow key={tool.tool}>
                    <TableCell>
                      <span className="font-medium">{tool.tool}</span>
                      <span className="block text-xs text-muted-foreground">{tool.description}</span>
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {tool.image ?? "-"}
                      {tool.tag ? `:${tool.tag}` : ""}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {shortDigest(tool.digest)}
                      {tool.digest_source ? (
                        <span className="block text-muted-foreground">from {tool.digest_source}</span>
                      ) : null}
                      {digestDiffers(tool) ? (
                        <span className="block text-muted-foreground">
                          last job ran {shortDigest(tool.last_job_digest)}
                        </span>
                      ) : null}
                    </TableCell>
                    <TableCell>{formatDateTime(tool.last_success_at)}</TableCell>
                    <TableCell>{formatDateTime(tool.last_failure_at)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </section>
        </>
      ) : null}
    </>
  );
}
