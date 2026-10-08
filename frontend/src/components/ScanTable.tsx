import { useMemo } from "react";

import { useApplications } from "../api/applications";
import {
  SCAN_STATE_LABELS,
  VERDICT_LABELS,
  isActiveScan,
  severityCounts,
  useRecentReports,
  useVersionMap,
  type Scan,
  type ScanState,
  type Verdict,
} from "../api/scans";
import { formatDateTime } from "../lib/format";
import { AppLink } from "./FormBits";
import { SeverityCountBadges } from "./SeverityBadge";
import { StatusBadge } from "./StatusBadge";
import { EmptyState, ErrorNotice, LoadingText } from "./ui/page";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table";

export function scanPath(scanId: string): string {
  return `/scans/${encodeURIComponent(scanId)}`;
}

export function reportPath(reportId: string): string {
  return `/reports/${encodeURIComponent(reportId)}`;
}

/** The scan state as a labelled badge. */
export function ScanStateBadge({ state }: { state: ScanState }) {
  return <StatusBadge status={state} label={SCAN_STATE_LABELS[state]} />;
}

/** The verdict as a labelled badge; "-" while a scan has not finished. */
export function VerdictBadge({ verdict, state }: { verdict: Verdict; state?: ScanState }) {
  if (state && isActiveScan(state)) return <span className="text-muted-foreground">-</span>;
  return <StatusBadge status={verdict} label={VERDICT_LABELS[verdict]} />;
}

/**
 * Running and recent scans of one kind: application, version, state, findings by severity, verdict, start
 * time and links to the scan and its report. Application and version names are looked up (the list
 * carries ids only) and cached, so a long list costs a handful of requests.
 */
export function ScanTable({
  scans,
  loading,
  error,
  caption,
  emptyText = "No scans yet.",
  showMode = false,
}: {
  scans: Scan[] | undefined;
  loading?: boolean;
  error?: unknown;
  /** Names the table for screen readers. */
  caption: string;
  emptyText?: string;
  /** Show the scan mode (DAST) next to the profile. */
  showMode?: boolean;
}) {
  const applications = useApplications();
  const versions = useVersionMap((scans ?? []).map((scan) => scan.version_id));
  const reports = useRecentReports();
  const nameOf = useMemo(() => {
    const map = new Map<string, string>();
    for (const application of applications.data ?? []) map.set(application.id, application.name);
    return map;
  }, [applications.data]);

  if (error) return <ErrorNotice error={error} title="The scans could not be loaded" />;
  if (loading && !scans) return <LoadingText>Loading scans...</LoadingText>;
  if (!scans || scans.length === 0) return <EmptyState>{emptyText}</EmptyState>;

  return (
    <Table aria-label={caption}>
      <TableHeader>
        <TableRow>
          <TableHead>Application</TableHead>
          <TableHead>Version</TableHead>
          <TableHead>{showMode ? "Mode" : "Profile"}</TableHead>
          <TableHead>State</TableHead>
          <TableHead>Open findings</TableHead>
          <TableHead>Verdict</TableHead>
          <TableHead>Started</TableHead>
          <TableHead>
            <span className="sr-only">Links</span>
          </TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {scans.map((scan) => {
          const report = reports.data?.get(scan.id);
          const name = nameOf.get(scan.application_id) ?? "Application";
          const version = versions.get(scan.version_id)?.label ?? "";
          return (
            <TableRow key={scan.id} data-scan-id={scan.id}>
              <TableCell className="font-medium">{nameOf.get(scan.application_id) ?? "-"}</TableCell>
              <TableCell>{version || "-"}</TableCell>
              <TableCell>{showMode ? (scan.mode ?? scan.profile_name) : scan.profile_name}</TableCell>
              <TableCell>
                <ScanStateBadge state={scan.state} />
              </TableCell>
              <TableCell>
                {isActiveScan(scan.state) ? (
                  <span className="text-muted-foreground">-</span>
                ) : (
                  <SeverityCountBadges counts={severityCounts(scan.counts)} />
                )}
              </TableCell>
              <TableCell>
                <VerdictBadge verdict={scan.verdict} state={scan.state} />
              </TableCell>
              <TableCell className="whitespace-nowrap">{formatDateTime(scan.started_at ?? scan.created_at)}</TableCell>
              <TableCell className="whitespace-nowrap">
                <AppLink
                  href={scanPath(scan.id)}
                  className="underline underline-offset-2 hover:no-underline"
                  aria-label={`Details of the scan of ${name} ${version}`}
                >
                  Details
                </AppLink>
                {report ? (
                  <>
                    <span aria-hidden="true"> | </span>
                    <AppLink
                      href={reportPath(report.id)}
                      className="underline underline-offset-2 hover:no-underline"
                      aria-label={`Report of the scan of ${name} ${version}`}
                    >
                      Report
                    </AppLink>
                  </>
                ) : null}
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}
