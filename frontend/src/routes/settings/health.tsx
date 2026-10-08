import { useSystemHealth } from "../../api/admin";
import { StatusBadge } from "../../components/StatusBadge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../../components/ui/card";
import { ErrorNotice, LoadingText, PageHeader } from "../../components/ui/page";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../../components/ui/table";
import { formatDuration, formatNumber, formatPercent } from "../../lib/format";

type ValueKind = "count" | "seconds" | "ratio";

const KNOWN_VALUES: Record<string, { label: string; kind: ValueKind }> = {
  queue_depth: { label: "Jobs waiting, by queue", kind: "count" },
  oldest_queued_job_age_seconds: { label: "Oldest waiting job", kind: "seconds" },
  import_lag_seconds: { label: "Oldest result waiting for DefectDojo", kind: "seconds" },
  import_dead_letters: { label: "Failed imports (need a replay)", kind: "count" },
  credentials_expiring: { label: "Credentials that expire soon", kind: "count" },
  disk_used_ratio: { label: "Disk used, by volume", kind: "ratio" },
};

function formatValue(value: unknown, kind: ValueKind): string {
  if (typeof value !== "number") return String(value);
  if (kind === "seconds") return formatDuration(value);
  if (kind === "ratio") return formatPercent(value);
  return formatNumber(value);
}

export function healthRows(values: Record<string, unknown>): { label: string; value: string }[] {
  const rows: { label: string; value: string }[] = [];
  for (const [key, raw] of Object.entries(values)) {
    const known = KNOWN_VALUES[key] ?? { label: key.replace(/_/g, " "), kind: "count" as const };
    if (raw !== null && typeof raw === "object") {
      for (const [inner, innerValue] of Object.entries(raw as Record<string, unknown>)) {
        rows.push({ label: `${known.label}: ${inner}`, value: formatValue(innerValue, known.kind) });
      }
    } else {
      rows.push({ label: known.label, value: formatValue(raw, known.kind) });
    }
  }
  return rows;
}

export function HealthPage() {
  const health = useSystemHealth();
  return (
    <>
      <PageHeader
        title="System health"
        description="What the API sees right now. This page refreshes every 30 seconds. The same numbers go to Prometheus."
      />
      {health.isPending ? <LoadingText>Loading health...</LoadingText> : null}
      {health.isError ? (
        <ErrorNotice error={health.error} title="Could not read the system health" onRetry={() => void health.refetch()} />
      ) : null}
      {health.data ? (
        <>
          <Card>
            <CardHeader>
              <CardTitle>Overall</CardTitle>
              <CardDescription>The API, its database and the queues.</CardDescription>
            </CardHeader>
            <CardContent>
              <dl className="m-0 grid gap-4 sm:grid-cols-3">
                <div>
                  <dt className="text-xs uppercase tracking-wide text-muted-foreground">Status</dt>
                  <dd className="m-0 mt-1">
                    <StatusBadge status={health.data.status} label={health.data.status === "ok" ? "OK" : "Degraded"} />
                  </dd>
                </div>
                <div>
                  <dt className="text-xs uppercase tracking-wide text-muted-foreground">Database</dt>
                  <dd className="m-0 mt-1">
                    <StatusBadge
                      status={health.data.database === "ok" ? "ok" : "failed"}
                      label={health.data.database === "ok" ? "Reachable" : "Unavailable"}
                    />
                  </dd>
                </div>
                <div>
                  <dt className="text-xs uppercase tracking-wide text-muted-foreground">Version</dt>
                  <dd className="m-0 mt-1 text-sm font-medium">{health.data.version}</dd>
                </div>
              </dl>
            </CardContent>
          </Card>
          <section aria-labelledby="values-title" className="mt-8">
            <h2 id="values-title" className="mb-3 text-lg font-semibold">
              Current values
            </h2>
            {Object.keys(health.data.values).length === 0 ? (
              <p className="text-sm text-muted-foreground">No values yet.</p>
            ) : (
              <Table aria-label="Current values">
                <TableHeader>
                  <TableRow>
                    <TableHead>Measure</TableHead>
                    <TableHead>Value</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {healthRows(health.data.values).map((row) => (
                    <TableRow key={row.label}>
                      <TableCell>{row.label}</TableCell>
                      <TableCell className="tabular-nums">{row.value}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </section>
          <details className="mt-8">
            <summary className="cursor-pointer text-sm font-medium underline">
              All metrics of the API process
            </summary>
            <p className="my-2 text-xs text-muted-foreground">
              Worker-side metrics (job durations, scanner runs) are served by the worker on its own
              metrics port.
            </p>
            <Table aria-label="All metrics">
              <TableHeader>
                <TableRow>
                  <TableHead>Metric</TableHead>
                  <TableHead>Labels</TableHead>
                  <TableHead>Value</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {Object.entries(health.data.metrics).flatMap(([name, samples]) =>
                  samples.map((sample, index) => (
                    <TableRow key={`${name}-${index}`}>
                      <TableCell className="font-mono text-xs">{name}</TableCell>
                      <TableCell className="font-mono text-xs">
                        {Object.entries(sample.labels)
                          .map(([k, v]) => `${k}=${v}`)
                          .join(", ") || "-"}
                      </TableCell>
                      <TableCell className="tabular-nums">{sample.value}</TableCell>
                    </TableRow>
                  )),
                )}
              </TableBody>
            </Table>
          </details>
        </>
      ) : null}
    </>
  );
}
