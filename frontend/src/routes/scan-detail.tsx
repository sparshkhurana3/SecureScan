import { useQueryClient } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { useEffect, useId, useMemo, useState, type ReactNode } from "react";

import { useApplications } from "../api/applications";
import { ApiError } from "../api/client";
import { useMeQuery } from "../api/me";
import { useCreateReport, useReports } from "../api/reports";
import {
  IMPORT_STATE_LABELS,
  JOB_STATE_LABELS,
  SEVERITY_LABELS,
  SEVERITIES,
  isActiveScan,
  scansKey,
  severityCounts,
  toolLabel,
  useCancelScan,
  useScan,
  useVersionMap,
  type ScanDetail,
  type ScanJob,
} from "../api/scans";
import { AppLink, ProblemNotice } from "../components/FormBits";
import { LogViewer } from "../components/LogViewer";
import { reportPath, ScanStateBadge, VerdictBadge } from "../components/ScanTable";
import { SeverityBadge } from "../components/SeverityBadge";
import { StatusBadge } from "../components/StatusBadge";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { ErrorNotice, LoadingText, PageHeader } from "../components/ui/page";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";
import { formatBytes, formatDateTime, formatDuration, humanize, shortSha } from "../lib/format";
import { useScanEvents, type EventSourceFactory } from "../lib/sse";

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5">
      <dt className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">{label}</dt>
      <dd className="m-0 text-sm">{children}</dd>
    </div>
  );
}

function durationOf(scan: ScanDetail | ScanJob): string {
  if (!scan.started_at) return "-";
  const end = scan.finished_at ? new Date(scan.finished_at).getTime() : Date.now();
  return formatDuration((end - new Date(scan.started_at).getTime()) / 1000);
}

function contentVersionText(job: ScanJob): string {
  const entries = Object.entries(job.content_versions);
  if (entries.length === 0) return "-";
  return entries
    .map(([key, value]) => `${humanize(key)} ${typeof value === "string" ? value : JSON.stringify(value)}`)
    .join(", ");
}

function digestText(digest: string | null): string {
  return digest ? digest.replace(/^sha256:/, "").slice(0, 12) : "-";
}

/** What happened to a tool, in a few words: the reason the tool gave, its exit code or nothing. */
function outcomeText(job: ScanJob): string {
  const parts: string[] = [];
  if (job.outcome_reason) parts.push(job.outcome_reason);
  if (job.exit_code !== null && job.state !== "queued") parts.push(`exit code ${String(job.exit_code)}`);
  if (job.coverage_note) parts.push(job.coverage_note);
  if (job.partial) parts.push("partial results");
  return parts.length > 0 ? parts.join(". ") : "-";
}

/**
 * One scan: state, per-tool status, versions of tools and content, findings by severity, verdict, import
 * state, the report, the DefectDojo links, a cancel button and the live log. The page refreshes by itself
 * while the scan runs (live stream plus a short poll).
 */
export function ScanDetailView({ scanId, eventSourceFactory }: { scanId: string | undefined; eventSourceFactory?: EventSourceFactory }) {
  const headingId = useId();
  const queryClient = useQueryClient();
  const me = useMeQuery();
  const scanQuery = useScan(scanId);
  const scan = scanQuery.data;
  const stream = useScanEvents(scanId, { factory: eventSourceFactory });
  const applications = useApplications();
  const versions = useVersionMap(scan ? [scan.version_id] : []);
  const reports = useReports(scanId ? { scan_id: scanId } : {}, 20);
  const createReport = useCreateReport();
  const cancel = useCancelScan(scanId ?? "");
  const [confirmCancel, setConfirmCancel] = useState(false);

  // Every snapshot or state change of the stream refreshes the scan; the end also refreshes the reports.
  useEffect(() => {
    if (stream.changes > 0 && scanId) {
      void queryClient.invalidateQueries({ queryKey: [...scansKey, "detail", scanId] });
    }
  }, [stream.changes, scanId, queryClient]);
  useEffect(() => {
    if (stream.done) void queryClient.invalidateQueries({ queryKey: ["reports"] });
  }, [stream.done, queryClient]);

  const application = useMemo(
    () => (scan ? applications.data?.find((item) => item.id === scan.application_id) : undefined),
    [applications.data, scan],
  );
  const version = scan ? versions.get(scan.version_id) : undefined;
  const dojo = me.data?.defectdojoUrl;
  const reportList = reports.data?.items ?? [];
  const readyReport = reportList.find((report) => report.status === "ready");
  const pendingReport = reportList.find((report) => report.status === "pending");
  const failedReport = reportList.find((report) => report.status === "failed");

  if (!scanId) return <ErrorNotice error={new Error("No scan was chosen.")} title="Scan not found" />;
  if (scanQuery.isPending) return <LoadingText>Loading the scan...</LoadingText>;
  if (scanQuery.isError || !scan) {
    const notFound = scanQuery.error instanceof ApiError && scanQuery.error.status === 404;
    return (
      <ErrorNotice
        error={scanQuery.error}
        title={notFound ? "Scan not found" : "The scan could not be loaded"}
        onRetry={notFound ? undefined : () => void scanQuery.refetch()}
      />
    );
  }

  const counts = severityCounts(scan.counts);
  const active = isActiveScan(scan.state);
  const finished = !active;
  const jobsPendingImport = scan.jobs.filter(
    (job) => job.import_state === "pending" && (job.state === "completed" || job.state === "completed_partial"),
  );

  return (
    <div className="flex flex-col gap-8">
      <PageHeader
        title={application?.name ?? "Scan"}
        description={
          <>
            {version ? `Version ${version.label}. ` : ""}
            {scan.kind === "sast" ? "Code scan" : "Web scan"} with profile {scan.profile_name}
            {scan.mode ? ` (${scan.mode})` : ""}.
          </>
        }
        actions={
          <>
            {readyReport ? (
              <AppLink
                href={reportPath(readyReport.id)}
                className="inline-flex h-9 items-center rounded-md bg-accent px-4 text-sm font-medium text-accent-foreground no-underline hover:bg-neutral-700"
              >
                Open the report
              </AppLink>
            ) : null}
            {dojo && application?.dd_product_id ? (
              <a
                href={`${dojo}/product/${String(application.dd_product_id)}`}
                target="_blank"
                rel="noreferrer"
                className="inline-flex h-9 items-center rounded-md border border-input px-4 text-sm font-medium text-foreground no-underline hover:bg-muted"
              >
                Open in DefectDojo
              </a>
            ) : null}
            {active ? (
              confirmCancel ? (
                <>
                  <Button
                    onClick={() => cancel.mutate(undefined, { onSettled: () => setConfirmCancel(false) })}
                    disabled={cancel.isPending}
                  >
                    {cancel.isPending ? "Cancelling..." : "Yes, cancel the scan"}
                  </Button>
                  <Button variant="outline" onClick={() => setConfirmCancel(false)} disabled={cancel.isPending}>
                    Keep running
                  </Button>
                </>
              ) : (
                <Button variant="outline" onClick={() => setConfirmCancel(true)} disabled={Boolean(scan.cancel_requested_at)}>
                  {scan.cancel_requested_at ? "Cancel requested" : "Cancel scan"}
                </Button>
              )
            ) : null}
          </>
        }
      />

      {cancel.isError ? <ProblemNotice error={cancel.error} title="The scan could not be cancelled" /> : null}

      <Card aria-labelledby={headingId}>
        <CardHeader>
          <CardTitle>
            <span id={headingId}>Summary</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid gap-x-6 gap-y-4 sm:grid-cols-2 lg:grid-cols-4">
            <Fact label="State">
              <ScanStateBadge state={scan.state} />
            </Fact>
            <Fact label="Verdict">
              <VerdictBadge verdict={scan.verdict} state={scan.state} />
            </Fact>
            <Fact label="Started">{formatDateTime(scan.started_at ?? scan.created_at)}</Fact>
            <Fact label="Duration">{durationOf(scan)}</Fact>
            <Fact label="Finished">{formatDateTime(scan.finished_at)}</Fact>
            <Fact label="Started by">{humanize(scan.trigger)}{scan.trigger_detail ? ` (${scan.trigger_detail})` : ""}</Fact>
            <Fact label="Profile">
              {scan.profile_name} v{scan.profile_version}
            </Fact>
            <Fact label="Tools">{scan.requested_tools.map(toolLabel).join(", ") || "-"}</Fact>
            {scan.commit_sha || scan.source_ref ? (
              <Fact label="Source">
                {scan.source_ref ?? ""} {scan.commit_sha ? <span title={scan.commit_sha}>{shortSha(scan.commit_sha)}</span> : null}
              </Fact>
            ) : null}
            <Fact label="Import into DefectDojo">
              {jobsPendingImport.length > 0
                ? `Waiting for ${String(jobsPendingImport.length)} tool${jobsPendingImport.length === 1 ? "" : "s"}`
                : scan.jobs.some((job) => job.import_state === "failed")
                  ? "Some imports failed (they are retried)"
                  : scan.jobs.every((job) => job.import_state === "imported")
                    ? "Complete"
                    : "-"}
            </Fact>
          </dl>

          <div className="mt-5 flex flex-col gap-2">
            <h3 className="m-0 text-sm font-semibold">Open findings by severity</h3>
            {active ? (
              <p className="m-0 text-sm text-muted-foreground">Shown when the scan has finished and its results are imported.</p>
            ) : (
              <p className="m-0 flex flex-wrap items-center gap-2" data-testid="severity-counts">
                {SEVERITIES.map((severity) => (
                  <SeverityBadge key={severity} severity={severity} count={counts[severity]} className="" />
                ))}
                <span className="text-sm text-muted-foreground">Total {counts.total}</span>
              </p>
            )}
            <p className="sr-only">
              {SEVERITIES.map((severity) => `${SEVERITY_LABELS[severity]} ${String(counts[severity])}`).join(", ")}
            </p>
          </div>

          {scan.error ? (
            <p role="alert" className="mt-4 rounded-md border border-foreground p-3 text-sm">
              <span className="font-semibold">Error: </span>
              {scan.error}
            </p>
          ) : null}
          {scan.coverage_notes.length > 0 ? (
            <div className="mt-4">
              <h3 className="m-0 text-sm font-semibold">Coverage notes</h3>
              <ul className="mt-1 list-disc pl-5 text-sm">
                {scan.coverage_notes.map((note, index) => (
                  <li key={index}>{typeof note === "string" ? note : JSON.stringify(note)}</li>
                ))}
              </ul>
            </div>
          ) : null}
        </CardContent>
      </Card>

      <section aria-label="Tools" className="flex flex-col gap-3">
        <h2 className="m-0 text-lg font-semibold">Tools</h2>
        <Table aria-label="Status of each tool">
          <TableHeader>
            <TableRow>
              <TableHead>Tool</TableHead>
              <TableHead>State</TableHead>
              <TableHead>Import</TableHead>
              <TableHead>Version</TableHead>
              <TableHead>Content versions</TableHead>
              <TableHead>Findings</TableHead>
              <TableHead>Outcome</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {scan.jobs.map((job) => {
              const jobCounts = severityCounts(job.counts);
              return (
                <TableRow key={job.id} data-tool={job.tool}>
                  <TableCell className="font-medium">{toolLabel(job.tool)}</TableCell>
                  <TableCell>
                    <StatusBadge status={job.state} label={JOB_STATE_LABELS[job.state]} />
                    {job.attempts > 1 ? (
                      <span className="block text-xs text-muted-foreground">Attempt {job.attempts}</span>
                    ) : null}
                  </TableCell>
                  <TableCell>
                    <StatusBadge status={job.import_state} label={IMPORT_STATE_LABELS[job.import_state]} />
                    {dojo && job.dd_test_id ? (
                      <a
                        href={`${dojo}/test/${String(job.dd_test_id)}`}
                        target="_blank"
                        rel="noreferrer"
                        className="mt-1 block text-xs underline underline-offset-2 hover:no-underline"
                        aria-label={`${toolLabel(job.tool)} results in DefectDojo`}
                      >
                        DefectDojo
                      </a>
                    ) : null}
                  </TableCell>
                  <TableCell className="text-xs">
                    {job.tool_version ?? "-"}
                    <span className="block text-muted-foreground" title={job.image ?? undefined}>
                      image {digestText(job.image_digest)}
                    </span>
                  </TableCell>
                  <TableCell className="max-w-xs break-words text-xs">{contentVersionText(job)}</TableCell>
                  <TableCell>{finished || job.state !== "queued" ? jobCounts.total : "-"}</TableCell>
                  <TableCell className="max-w-xs break-words text-xs">{outcomeText(job)}</TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </section>

      <section aria-label="Report" className="flex flex-col gap-3">
        <h2 className="m-0 text-lg font-semibold">Report</h2>
        {readyReport ? (
          <p className="m-0 text-sm">
            <AppLink href={reportPath(readyReport.id)} className="font-medium underline underline-offset-2 hover:no-underline">
              {readyReport.title ?? readyReport.ref ?? "Open the report"}
            </AppLink>{" "}
            <span className="text-muted-foreground">
              made {formatDateTime(readyReport.created_at)}
              {readyReport.review_state === "reviewed" ? ", reviewed" : ", not reviewed yet"}
            </span>
          </p>
        ) : pendingReport ? (
          <p className="m-0 text-sm text-muted-foreground" role="status">
            The report is being made...
          </p>
        ) : active ? (
          <p className="m-0 text-sm text-muted-foreground">The report is made when the scan finishes and its results are imported.</p>
        ) : (
          <div className="flex flex-col gap-2">
            <p className="m-0 text-sm text-muted-foreground">
              {failedReport
                ? `The last report could not be made${failedReport.error ? `: ${failedReport.error}` : "."}`
                : jobsPendingImport.length > 0
                  ? "The report follows when the results are imported."
                  : "There is no report for this scan yet."}
            </p>
            <div>
              <Button
                variant="outline"
                size="sm"
                disabled={createReport.isPending}
                onClick={() => createReport.mutate({ scan_id: scan.id })}
              >
                {createReport.isPending ? "Requesting..." : "Make the report"}
              </Button>
            </div>
            {createReport.isError ? <ProblemNotice error={createReport.error} title="The report could not be requested" /> : null}
          </div>
        )}
      </section>

      {scan.artifacts.length > 0 ? (
        <section aria-label="Stored files" className="flex flex-col gap-3">
          <h2 className="m-0 text-lg font-semibold">Stored files</h2>
          <Table aria-label="Raw reports, SBOMs and logs kept for this scan">
            <TableHeader>
              <TableRow>
                <TableHead>File</TableHead>
                <TableHead>Kind</TableHead>
                <TableHead>Size</TableHead>
                <TableHead>SHA-256</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {scan.artifacts.map((artifact) => (
                <TableRow key={artifact.id}>
                  <TableCell>{artifact.filename ?? artifact.id}</TableCell>
                  <TableCell>{humanize(artifact.kind)}</TableCell>
                  <TableCell>{formatBytes(artifact.size_bytes)}</TableCell>
                  <TableCell className="font-mono text-xs" title={artifact.sha256}>
                    {artifact.sha256.slice(0, 16)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </section>
      ) : null}

      <section aria-label="Log" className="flex flex-col gap-3">
        <h2 className="m-0 text-lg font-semibold">Log</h2>
        <LogViewer
          scanId={scan.id}
          jobs={scan.jobs.map((job) => ({ id: job.id, tool: job.tool }))}
          lines={stream.lines}
          connection={stream.connection}
          serverError={stream.serverError}
        />
      </section>
    </div>
  );
}

/** The route component of `/scans/$scanId`. */
export function ScanDetailPage() {
  const params = useParams({ strict: false }) as { scanId?: string; id?: string };
  return <ScanDetailView scanId={params.scanId ?? params.id} />;
}
