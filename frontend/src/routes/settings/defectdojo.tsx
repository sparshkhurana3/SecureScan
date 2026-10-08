import { Link } from "@tanstack/react-router";
import { type ReactNode, useState } from "react";

import {
  defectDojoLoginUrl,
  type OutboxItem,
  type OutboxState,
  useDefectDojoStatus,
  useOutbox,
  useReplayImport,
} from "../../api/defectdojo";
import { StatusBadge } from "../../components/StatusBadge";
import { Button } from "../../components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../../components/ui/card";
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
import { formatDateTime, formatDuration, formatRelative } from "../../lib/format";

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wide text-muted-foreground">{label}</dt>
      <dd className="m-0 mt-0.5 text-sm font-medium">{children}</dd>
    </div>
  );
}

function StatusCard() {
  const status = useDefectDojoStatus();
  return (
    <Card>
      <CardHeader>
        <CardTitle>DefectDojo status</CardTitle>
        <CardDescription>
          DefectDojo parses the scanner reports and holds the findings. Results wait in the import
          queue while it is unreachable.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {status.isPending ? <LoadingText /> : null}
        {status.isError ? (
          <ErrorNotice error={status.error} title="Could not read the DefectDojo status" onRetry={() => void status.refetch()} />
        ) : null}
        {status.data ? (
          <dl className="m-0 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <Fact label="Reachable">
              <StatusBadge
                status={status.data.reachable ? "ok" : "failed"}
                label={status.data.reachable ? "Yes" : "No"}
              />
              {status.data.latency_ms !== null ? (
                <span className="ml-2 text-xs font-normal text-muted-foreground">
                  {status.data.latency_ms} ms
                </span>
              ) : null}
            </Fact>
            <Fact label="Expected version">{status.data.expected_version}</Fact>
            <Fact label="Address">
              <a href={defectDojoLoginUrl(status.data.public_url)} target="_blank" rel="noopener noreferrer" className="underline">
                {status.data.public_url}
                <span className="sr-only"> (opens in a new tab)</span>
              </a>
            </Fact>
            <Fact label="Import account ready">
              <StatusBadge
                status={status.data.tokens_ready ? "ok" : "failed"}
                label={status.data.tokens_ready ? "Yes" : "Not yet"}
              />
            </Fact>
            <Fact label="Account management ready">
              <StatusBadge
                status={status.data.accounts_token_ready ? "ok" : "failed"}
                label={status.data.accounts_token_ready ? "Yes" : "Not yet"}
              />
            </Fact>
            <Fact label="Last import">{formatDateTime(status.data.last_import_at)}</Fact>
            <Fact label="Waiting imports">{status.data.queue_depth}</Fact>
            <Fact label="Oldest waiting import">
              {status.data.oldest_pending_seconds === null
                ? "-"
                : formatDuration(status.data.oldest_pending_seconds)}
            </Fact>
            <Fact label="Failed imports">
              {status.data.dead_letters > 0 ? (
                <StatusBadge status="failed" label={`${status.data.dead_letters} need a replay`} />
              ) : (
                "None"
              )}
            </Fact>
          </dl>
        ) : null}
      </CardContent>
    </Card>
  );
}

function canReplay(item: OutboxItem): boolean {
  return item.state === "dead_letter" || item.state === "pending";
}

const STATE_FILTERS: { value: OutboxState | ""; label: string }[] = [
  { value: "", label: "All" },
  { value: "dead_letter", label: "Failed (need a replay)" },
  { value: "pending", label: "Waiting" },
  { value: "processing", label: "Running now" },
  { value: "done", label: "Done" },
];

function QueueTable() {
  const [state, setState] = useState<OutboxState | "">("");
  const outbox = useOutbox(state);
  const replay = useReplayImport();
  const items = outbox.data?.pages.flatMap((page) => page.items) ?? [];

  return (
    <section aria-labelledby="queue-title" className="mt-8">
      <div className="mb-3 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 id="queue-title" className="text-lg font-semibold">
            Import queue
          </h2>
          <p className="text-sm text-muted-foreground">
            One row for each scanner report on its way into DefectDojo. Replay a failed one once the
            cause is fixed.
          </p>
        </div>
        <Field id="queue-state" label="Show">
          <Select
            id="queue-state"
            value={state}
            onChange={(e) => setState(e.target.value as OutboxState | "")}
          >
            {STATE_FILTERS.map((f) => (
              <option key={f.value} value={f.value}>
                {f.label}
              </option>
            ))}
          </Select>
        </Field>
      </div>
      {outbox.isPending ? <LoadingText>Loading the import queue...</LoadingText> : null}
      {outbox.isError ? (
        <ErrorNotice error={outbox.error} title="Could not load the import queue" onRetry={() => void outbox.refetch()} />
      ) : null}
      {replay.error ? <ErrorNotice error={replay.error} title="The import was not replayed" className="mb-3" /> : null}
      {replay.isSuccess ? (
        <p role="status" className="mb-3 text-sm font-medium">
          Replay queued. The import runs in a moment.
        </p>
      ) : null}
      {outbox.data ? (
        items.length === 0 ? (
          <EmptyState>Nothing in the import queue for this filter.</EmptyState>
        ) : (
          <Table aria-label="Import queue">
            <TableHeader>
              <TableRow>
                <TableHead>Application</TableHead>
                <TableHead>Tool</TableHead>
                <TableHead>State</TableHead>
                <TableHead>Attempts</TableHead>
                <TableHead>Next try</TableHead>
                <TableHead>Last error</TableHead>
                <TableHead>
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((item) => (
                <TableRow key={item.id}>
                  <TableCell>
                    {item.application_name ?? "-"}
                    {item.scan_id ? (
                      <Link
                        to="/scans/$scanId"
                        params={{ scanId: item.scan_id }}
                        className="block text-xs underline"
                      >
                        Scan details
                      </Link>
                    ) : null}
                  </TableCell>
                  <TableCell>{item.tool ?? "-"}</TableCell>
                  <TableCell>
                    <StatusBadge status={item.state} />
                  </TableCell>
                  <TableCell>{item.attempts}</TableCell>
                  <TableCell className="whitespace-nowrap">
                    {item.state === "pending" ? formatRelative(item.next_attempt_at) : "-"}
                  </TableCell>
                  <TableCell className="max-w-sm break-words text-xs">{item.last_error ?? "-"}</TableCell>
                  <TableCell>
                    {canReplay(item) ? (
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={replay.isPending}
                        onClick={() => replay.mutate(item.id)}
                      >
                        Replay<span className="sr-only"> import of {item.application_name ?? "scan"}</span>
                      </Button>
                    ) : null}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )
      ) : null}
      <LoadMore
        hasMore={Boolean(outbox.hasNextPage)}
        loading={outbox.isFetchingNextPage}
        onClick={() => void outbox.fetchNextPage()}
      />
    </section>
  );
}

export function DefectDojoSettingsPage() {
  return (
    <>
      <PageHeader title="DefectDojo and imports" />
      <StatusCard />
      <QueueTable />
    </>
  );
}
