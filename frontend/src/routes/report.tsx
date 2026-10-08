import { useParams } from "@tanstack/react-router";
import { useId, useMemo, useState, type FormEvent } from "react";

import { ApiError } from "../api/client";
import {
  reportCsvUrl,
  reportHtmlUrl,
  reportPdfUrl,
  useCreateReport,
  useReport,
  useReviewReport,
  type Report,
} from "../api/reports";
import {
  VERDICT_LABELS,
  buildReviewBody,
  canConfirmProposal,
  effectiveVerdict,
  initialReview,
  todayIso,
  useReportFindings,
  validateReview,
  type ReviewValues,
  type Verdict,
} from "../api/scans";
import { CheckField, describedBy, FieldGroup, fieldHelp, ProblemNotice, RadioField, AppLink } from "../components/FormBits";
import { scanPath } from "../components/ScanTable";
import { StatusBadge } from "../components/StatusBadge";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card";
import { Input } from "../components/ui/input";
import { ErrorNotice, Field, LoadingText, PageHeader } from "../components/ui/page";
import { Select } from "../components/ui/select";
import { Textarea } from "../components/ui/textarea";
import { formatDate, formatDateTime } from "../lib/format";

const VERDICT_CHOICES: Verdict[] = ["pass", "conditional", "fail"];

function verdictLabel(verdict: string | null | undefined): string {
  if (!verdict) return "None";
  return VERDICT_LABELS[verdict as Verdict] ?? verdict;
}

function VerdictPill({ verdict }: { verdict: string | null | undefined }) {
  if (!verdict) return <span>None</span>;
  return <StatusBadge status={verdict} label={verdictLabel(verdict)} />;
}

/** The review of a report by an analyst: confirm the proposed verdict or override it, with conditions. */
function ReviewPanel({ report }: { report: Report }) {
  const prefix = useId();
  const review = useReviewReport(report.id);
  const [values, setValues] = useState<ReviewValues>(() => initialReview(report));
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [saved, setSaved] = useState(false);
  const findings = useReportFindings(report.id, true);
  const today = todayIso();

  const openKeys = useMemo(
    () => (findings.data ? new Set(findings.data.map((finding) => finding.key)) : undefined),
    [findings.data],
  );
  const sortedFindings = useMemo(() => {
    const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return [...(findings.data ?? [])].sort(
      (a, b) => (rank[a.severity.toLowerCase()] ?? 5) - (rank[b.severity.toLowerCase()] ?? 5) || a.title.localeCompare(b.title),
    );
  }, [findings.data]);

  const proposed = report.proposed_verdict;
  const canConfirm = canConfirmProposal(proposed);
  const verdict = effectiveVerdict(values, proposed);
  const conditionsAllowed = verdict !== "pass";
  const set = (patch: Partial<ReviewValues>) => {
    setSaved(false);
    setValues((current) => ({ ...current, ...patch }));
  };
  const setCondition = (index: number, patch: Partial<ReviewValues["conditions"][number]>) =>
    set({ conditions: values.conditions.map((item, position) => (position === index ? { ...item, ...patch } : item)) });

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (review.isPending) return;
    const found = validateReview(values, proposed, today, openKeys);
    setErrors(found);
    setSaved(false);
    if (Object.keys(found).length > 0) return;
    review.mutate(buildReviewBody(values, report.kind), { onSuccess: () => setSaved(true) });
  };

  return (
    <Card aria-label="Review">
      <CardHeader>
        <CardTitle>Review</CardTitle>
        <CardDescription>
          The policy proposes <strong>{verdictLabel(proposed)}</strong>. Confirm it, or override it with a reason. The
          report is rendered again with your review.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} noValidate aria-label="Review the report" className="flex max-w-3xl flex-col gap-5">
          <FieldGroup legend="Your decision">
            <RadioField
              name={`${prefix}-decision`}
              value="confirm"
              checked={values.decision === "confirm"}
              onSelect={() => set({ decision: "confirm" })}
              label={canConfirm ? `Confirm the proposed verdict (${verdictLabel(proposed)})` : "Confirm the proposed verdict"}
              help={canConfirm ? undefined : "There is no proposed verdict to confirm yet."}
              disabled={!canConfirm || review.isPending}
            />
            <RadioField
              name={`${prefix}-decision`}
              value="override"
              checked={values.decision === "override"}
              onSelect={() => set({ decision: "override" })}
              label="Set a verdict myself"
              disabled={review.isPending}
            />
            {errors.decision ? (
              <p role="alert" className="m-0 text-xs font-semibold">
                {errors.decision}
              </p>
            ) : null}
          </FieldGroup>

          {values.decision === "override" ? (
            <>
              <Field id={`${prefix}-verdict`} label="Verdict" help={fieldHelp(errors.verdict, undefined)}>
                <Select
                  id={`${prefix}-verdict`}
                  value={values.verdict}
                  disabled={review.isPending}
                  onChange={(event) => set({ verdict: event.target.value as ReviewValues["verdict"] })}
                  {...describedBy(`${prefix}-verdict`, errors.verdict, false)}
                >
                  <option value="">Choose...</option>
                  {VERDICT_CHOICES.map((choice) => (
                    <option key={choice} value={choice}>
                      {VERDICT_LABELS[choice]}
                      {choice === proposed ? " (the proposed verdict)" : ""}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field
                id={`${prefix}-reason`}
                label="Reason for the override"
                help={fieldHelp(errors.reason, "Recorded in the report and the audit log. At least 5 characters.")}
              >
                <Textarea
                  id={`${prefix}-reason`}
                  value={values.reason}
                  maxLength={2000}
                  disabled={review.isPending}
                  onChange={(event) => set({ reason: event.target.value })}
                  {...describedBy(`${prefix}-reason`, errors.reason, true)}
                />
              </Field>
            </>
          ) : null}

          <fieldset className="flex flex-col gap-3 border-0 p-0">
            <legend className="mb-1 p-0 text-sm font-medium">Conditions (remediation deadlines)</legend>
            {!conditionsAllowed ? (
              <p className="m-0 text-sm text-muted-foreground">A passing verdict has no conditions.</p>
            ) : (
              <>
                {errors.conditions ? (
                  <p role="alert" className="m-0 text-xs font-semibold">
                    {errors.conditions}
                  </p>
                ) : null}
                {values.conditions.length === 0 ? (
                  <p className="m-0 text-sm text-muted-foreground">
                    No conditions. Add one for each finding the vendor has agreed to fix by a date.
                  </p>
                ) : null}
                {values.conditions.map((condition, index) => {
                  const findingId = `${prefix}-condition-${String(index)}-finding`;
                  const deadlineId = `${prefix}-condition-${String(index)}-deadline`;
                  const findingError = errors[`condition.${String(index)}.finding`];
                  const deadlineError = errors[`condition.${String(index)}.deadline`];
                  return (
                    <div key={index} className="grid items-end gap-3 sm:grid-cols-[1fr_11rem_auto]">
                      <Field id={findingId} label={`Finding of condition ${String(index + 1)}`} help={fieldHelp(findingError, undefined)}>
                        <Select
                          id={findingId}
                          value={condition.findingKey}
                          disabled={review.isPending}
                          onChange={(event) => setCondition(index, { findingKey: event.target.value })}
                          {...describedBy(findingId, findingError, false)}
                        >
                          <option value="">Choose a finding...</option>
                          {sortedFindings.map((finding) => (
                            <option key={finding.key} value={finding.key}>
                              [{finding.severity_label}] {finding.title}
                              {finding.location ? ` (${finding.location})` : ""}
                            </option>
                          ))}
                          {condition.findingKey && !sortedFindings.some((finding) => finding.key === condition.findingKey) ? (
                            <option value={condition.findingKey}>{condition.findingKey}</option>
                          ) : null}
                        </Select>
                      </Field>
                      <Field id={deadlineId} label="Deadline" help={fieldHelp(deadlineError, undefined)}>
                        <Input
                          id={deadlineId}
                          type="date"
                          min={today}
                          value={condition.deadline}
                          disabled={review.isPending}
                          onChange={(event) => setCondition(index, { deadline: event.target.value })}
                          {...describedBy(deadlineId, deadlineError, false)}
                        />
                      </Field>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => set({ conditions: values.conditions.filter((_, position) => position !== index) })}
                        disabled={review.isPending}
                        aria-label={`Remove condition ${String(index + 1)}`}
                      >
                        Remove
                      </Button>
                    </div>
                  );
                })}
                <div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => set({ conditions: [...values.conditions, { findingKey: "", deadline: "" }] })}
                    disabled={review.isPending || findings.isPending}
                  >
                    Add a condition
                  </Button>
                  {findings.isError ? (
                    <span role="alert" className="ml-3 text-xs font-semibold">
                      The findings of the report could not be loaded.
                    </span>
                  ) : null}
                </div>
              </>
            )}
          </fieldset>

          <Field
            id={`${prefix}-notes`}
            label="Internal notes (optional)"
            help={fieldHelp(errors.internalNotes, "Shown in the internal report only, never in a vendor copy.")}
          >
            <Textarea
              id={`${prefix}-notes`}
              value={values.internalNotes}
              maxLength={4000}
              disabled={review.isPending}
              onChange={(event) => set({ internalNotes: event.target.value })}
            />
          </Field>

          {report.kind === "vendor" ? (
            <CheckField
              id={`${prefix}-vendor-copy`}
              label="Make a copy for the vendor"
              checked={values.vendorCopy}
              onCheckedChange={(vendorCopy) => set({ vendorCopy })}
              disabled={review.isPending}
              help="The vendor copy leaves out the internal notes."
            />
          ) : null}

          {review.isError ? <ProblemNotice error={review.error} title="The review was refused" /> : null}
          {saved ? (
            <p role="status" className="m-0 text-sm font-medium">
              Review saved. The report below shows it.
            </p>
          ) : null}

          <div>
            <Button type="submit" disabled={review.isPending}>
              {review.isPending ? "Saving..." : report.review_state === "reviewed" ? "Save the review again" : "Save the review"}
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

/** A report: the verdict and review state, the report itself in a sandboxed frame, PDF and CSV downloads. */
export function ReportView({ reportId }: { reportId: string | undefined }) {
  const reportQuery = useReport(reportId);
  const regenerate = useCreateReport();
  const report = reportQuery.data;

  if (!reportId) return <ErrorNotice error={new Error("No report was chosen.")} title="Report not found" />;
  if (reportQuery.isPending) return <LoadingText>Loading the report...</LoadingText>;
  if (reportQuery.isError || !report) {
    const notFound = reportQuery.error instanceof ApiError && reportQuery.error.status === 404;
    return (
      <ErrorNotice
        error={reportQuery.error}
        title={notFound ? "Report not found" : "The report could not be loaded"}
        onRetry={notFound ? undefined : () => void reportQuery.refetch()}
      />
    );
  }

  const ready = report.status === "ready";

  return (
    <div className="flex flex-col gap-8">
      <PageHeader
        title={report.title ?? report.ref ?? "Report"}
        description={
          <>
            {report.kind === "vendor" ? "Vendor assessment" : "Application report"}
            {report.ref ? `, ${report.ref}` : ""}. Made {formatDateTime(report.created_at)}.
          </>
        }
        actions={
          <>
            {report.scan_id ? (
              <AppLink
                href={scanPath(report.scan_id)}
                className="inline-flex h-9 items-center rounded-md border border-input px-4 text-sm font-medium text-foreground no-underline hover:bg-muted"
              >
                Back to the scan
              </AppLink>
            ) : null}
            {ready && report.pdf_ready ? (
              <a
                href={reportPdfUrl(report.id)}
                download
                className="inline-flex h-9 items-center rounded-md bg-accent px-4 text-sm font-medium text-accent-foreground no-underline hover:bg-neutral-700"
              >
                Download PDF
              </a>
            ) : null}
            {ready ? (
              <a
                href={reportCsvUrl(report.id)}
                download
                className="inline-flex h-9 items-center rounded-md border border-input px-4 text-sm font-medium text-foreground no-underline hover:bg-muted"
              >
                Download findings (CSV)
              </a>
            ) : null}
          </>
        }
      />

      {report.status === "pending" ? (
        <p role="status" className="m-0 text-sm text-muted-foreground">
          The report is being made. This page updates when it is ready.
        </p>
      ) : null}
      {report.status === "failed" ? (
        <div role="alert" className="flex flex-col gap-3 rounded-md border border-foreground p-4 text-sm">
          <p className="m-0 font-semibold">The report could not be made.</p>
          {report.error ? <p className="m-0">{report.error}</p> : null}
          {report.scan_id ? (
            <div>
              <Button
                variant="outline"
                size="sm"
                disabled={regenerate.isPending}
                onClick={() => report.scan_id && regenerate.mutate({ scan_id: report.scan_id })}
              >
                {regenerate.isPending ? "Requesting..." : "Try to make it again"}
              </Button>
            </div>
          ) : null}
          {regenerate.isError ? <ProblemNotice error={regenerate.error} title="The report could not be requested" /> : null}
        </div>
      ) : null}

      <Card aria-label="Verdict and review state">
        <CardContent className="pt-5">
          <dl className="grid gap-x-6 gap-y-4 sm:grid-cols-2 lg:grid-cols-4">
            <div>
              <dt className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Verdict</dt>
              <dd className="m-0 mt-1" data-testid="report-verdict">
                <VerdictPill verdict={report.verdict} />
              </dd>
            </div>
            <div>
              <dt className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Proposed by policy</dt>
              <dd className="m-0 mt-1">
                <VerdictPill verdict={report.proposed_verdict} />
              </dd>
            </div>
            <div>
              <dt className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Review</dt>
              <dd className="m-0 mt-1 text-sm">
                {report.review_state === "reviewed"
                  ? `Reviewed ${formatDateTime(report.reviewed_at)}${report.verdict_overridden ? ", verdict overridden" : ""}`
                  : "Not reviewed yet"}
              </dd>
            </div>
            <div>
              <dt className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Conditions</dt>
              <dd className="m-0 mt-1 text-sm">
                {report.conditions.length === 0
                  ? "None"
                  : `${String(report.conditions.length)} with deadlines from ${formatDate(
                      [...report.conditions].map((condition) => condition.deadline).sort()[0],
                    )}`}
              </dd>
            </div>
          </dl>
          {report.override_reason ? (
            <p className="mb-0 mt-4 text-sm">
              <span className="font-semibold">Reason for the override: </span>
              {report.override_reason}
            </p>
          ) : null}
        </CardContent>
      </Card>

      {ready ? <ReviewPanel key={report.id} report={report} /> : null}

      {ready && report.html_ready ? (
        <section aria-label="The report" className="flex flex-col gap-2">
          <h2 className="m-0 text-lg font-semibold">The report</h2>
          <iframe
            title="Report"
            sandbox=""
            src={reportHtmlUrl(report.id)}
            key={report.updated_at}
            className="h-[85vh] w-full rounded-md border border-border bg-white"
          />
        </section>
      ) : null}
    </div>
  );
}

/** The route component of `/reports/$reportId`. */
export function ReportPage() {
  const params = useParams({ strict: false }) as { reportId?: string; id?: string };
  return <ReportView reportId={params.reportId ?? params.id} />;
}
