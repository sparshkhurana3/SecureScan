import { type FormEvent, useState } from "react";

import { errorMessage } from "../api/client";
import {
  type Assessment,
  type Delta,
  type DeltaFinding,
  type IntakeInput,
  useAssessmentDelta,
  useAssessments,
  useCreateAssessment,
  useVendorIntake,
  vendorCopyUrl,
} from "../api/operations";
import { AppLink } from "../components/FormBits";
import { reportPath } from "../components/ScanTable";
import { StatusBadge } from "../components/StatusBadge";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card";
import { Input } from "../components/ui/input";
import { EmptyState, ErrorNotice, Field, LoadMore, LoadingText, PageHeader, TextLink } from "../components/ui/page";
import { Select } from "../components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../components/ui/table";
import { formatDateTime } from "../lib/format";

/** The vendor copy is offered once the report was reviewed and is ready to send. */
export function vendorCopyAvailable(assessment: Assessment): boolean {
  return assessment.status === "ready" && assessment.review_state === "reviewed";
}

function IntakeCard() {
  const intake = useVendorIntake();
  const [form, setForm] = useState<IntakeInput>({ vendor_name: "", product: "", version: "", hosting: "deployable" });

  const submit = (event: FormEvent) => {
    event.preventDefault();
    intake.mutate({
      ...form,
      vendor_name: form.vendor_name.trim(),
      product: form.product.trim(),
      version: form.version.trim(),
    });
  };
  const set = (key: keyof IntakeInput) => (value: string) => setForm((previous) => ({ ...previous, [key]: value }));

  return (
    <Card>
      <CardHeader>
        <CardTitle>Register a vendor product</CardTitle>
        <CardDescription>
          Names the vendor, product and version of a scan. Hosting decides the DAST rules (a SaaS product needs the
          vendor's written authorization before any active scan) and cannot be changed afterwards.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} aria-label="Register a vendor product" className="grid gap-4 sm:grid-cols-2">
          <Field id="intake-vendor" label="Vendor">
            <Input
              id="intake-vendor"
              value={form.vendor_name}
              onChange={(e) => set("vendor_name")(e.target.value)}
              maxLength={200}
              required
            />
          </Field>
          <Field id="intake-product" label="Product">
            <Input
              id="intake-product"
              value={form.product}
              onChange={(e) => set("product")(e.target.value)}
              maxLength={200}
              required
            />
          </Field>
          <Field id="intake-version" label="Version">
            <Input
              id="intake-version"
              value={form.version}
              onChange={(e) => set("version")(e.target.value)}
              maxLength={100}
              required
            />
          </Field>
          <Field id="intake-hosting" label="Hosting">
            <Select
              id="intake-hosting"
              value={form.hosting}
              onChange={(e) => set("hosting")(e.target.value === "saas" ? "saas" : "deployable")}
            >
              <option value="deployable">Deployable (we run it in UAT)</option>
              <option value="saas">SaaS (the vendor runs it)</option>
            </Select>
          </Field>
          <div className="sm:col-span-2">
            <Button type="submit" disabled={intake.isPending}>
              {intake.isPending ? "Saving..." : "Register"}
            </Button>
          </div>
        </form>
        {intake.isError ? (
          <p role="alert" className="mt-3 text-sm font-semibold">
            {errorMessage(intake.error)}
          </p>
        ) : null}
        {intake.data ? (
          <div role="status" className="mt-3 text-sm">
            <p className="m-0">
              {intake.data.vendor.name} / {intake.data.application.name} / {intake.data.version.label} is ready.
            </p>
            <ul className="mt-1 list-disc pl-5">
              {intake.data.next_steps.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ul>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}

function CreateCard() {
  const create = useCreateAssessment();
  const [scanId, setScanId] = useState("");
  const submit = (event: FormEvent) => {
    event.preventDefault();
    create.mutate({ scan_id: scanId.trim() }, { onSuccess: () => setScanId("") });
  };
  return (
    <Card className="mt-6">
      <CardHeader>
        <CardTitle>Create an assessment</CardTitle>
        <CardDescription>
          Freezes the current findings of a finished vendor scan into a report. Review it, set the conditions and
          deadlines, then send the vendor copy.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} aria-label="Create an assessment" className="flex flex-wrap items-end gap-4">
          <Field id="assessment-scan" label="Scan id" help="Copy it from the address of the scan page." className="min-w-64">
            <Input id="assessment-scan" value={scanId} onChange={(e) => setScanId(e.target.value)} required />
          </Field>
          <Button type="submit" disabled={create.isPending || scanId.trim() === ""}>
            {create.isPending ? "Creating..." : "Create assessment"}
          </Button>
        </form>
        {create.isError ? (
          <p role="alert" className="mt-3 text-sm font-semibold">
            {errorMessage(create.error)}
          </p>
        ) : null}
        {create.data ? (
          <p role="status" className="mt-3 text-sm">
            The report is being prepared. It appears in the list below when it is ready.
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}

function DeltaRows({ title, rows }: { title: string; rows: DeltaFinding[] }) {
  if (rows.length === 0) return null;
  return (
    <section aria-label={title} className="mt-4">
      <h3 className="mb-2 text-sm font-semibold">
        {title} ({rows.length})
      </h3>
      <Table aria-label={title}>
        <TableHeader>
          <TableRow>
            <TableHead>Severity</TableHead>
            <TableHead>Finding</TableHead>
            <TableHead>Tool</TableHead>
            <TableHead>Where</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((row) => (
            <TableRow key={`${title}-${row.key}`}>
              <TableCell>{row.severity}</TableCell>
              <TableCell>{row.title}</TableCell>
              <TableCell>{row.tool}</TableCell>
              <TableCell className="font-mono text-xs">{row.location}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </section>
  );
}

export function DeltaView({ delta }: { delta: Delta }) {
  return (
    <div>
      <p className="m-0 text-sm">
        Fixed {delta.counts.fixed ?? delta.fixed.length}, remaining {delta.counts.remaining ?? delta.remaining.length},
        new {delta.counts.new ?? delta.new.length}, reopened {delta.counts.reopened ?? delta.reopened.length}.
      </p>
      {delta.skipped_tools.length > 0 ? (
        <p className="mt-1 text-xs text-muted-foreground">
          Not compared (not run in both scans): {delta.skipped_tools.join(", ")}.
        </p>
      ) : null}
      {delta.notes.map((note) => (
        <p key={note} className="mt-1 text-xs text-muted-foreground">
          {note}
        </p>
      ))}
      <DeltaRows title="Fixed in the new version" rows={delta.fixed} />
      <DeltaRows title="Still present" rows={delta.remaining} />
      <DeltaRows title="New in this version" rows={delta.new} />
      <DeltaRows title="Reopened" rows={delta.reopened} />
      {delta.truncated ? <p className="mt-2 text-xs text-muted-foreground">Only the first rows are shown.</p> : null}
    </div>
  );
}

function DeltaCard() {
  const [scanId, setScanId] = useState("");
  const [previousId, setPreviousId] = useState("");
  const [asked, setAsked] = useState<{ scan: string; previous: string } | null>(null);
  const delta = useAssessmentDelta(asked?.scan ?? null, asked?.previous || null);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setAsked({ scan: scanId.trim(), previous: previousId.trim() });
  };

  return (
    <Card className="mt-6">
      <CardHeader>
        <CardTitle>Compare with an earlier version</CardTitle>
        <CardDescription>
          Shows which findings the vendor fixed and which remain, matched by DefectDojo&apos;s hash code. Leave the
          earlier scan empty to compare with the last scan of an earlier version.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} aria-label="Compare with an earlier version" className="flex flex-wrap items-end gap-4">
          <Field id="delta-scan" label="New scan id" className="min-w-64">
            <Input id="delta-scan" value={scanId} onChange={(e) => setScanId(e.target.value)} required />
          </Field>
          <Field id="delta-previous" label="Earlier scan id (optional)" className="min-w-64">
            <Input id="delta-previous" value={previousId} onChange={(e) => setPreviousId(e.target.value)} />
          </Field>
          <Button type="submit" disabled={scanId.trim() === ""}>
            Compare
          </Button>
        </form>
        {asked && delta.isPending ? <LoadingText>Comparing...</LoadingText> : null}
        {asked && delta.isError ? (
          <ErrorNotice error={delta.error} title="Could not compare the scans" />
        ) : null}
        {delta.data ? (
          <div className="mt-4">
            <DeltaView delta={delta.data} />
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}

export function VendorAssessmentsPage() {
  const assessments = useAssessments();
  const rows = assessments.data?.pages.flatMap((page) => page.items) ?? [];

  return (
    <>
      <PageHeader
        title="Vendor assessments"
        description="Register a vendor product, scan it, review the findings and send the vendor a report with conditions and deadlines."
      />
      <IntakeCard />
      <CreateCard />
      <DeltaCard />

      <section aria-labelledby="assessments-title" className="mt-8">
        <h2 id="assessments-title" className="mb-3 text-lg font-semibold">
          Assessments
        </h2>
        {assessments.isPending ? <LoadingText>Loading assessments...</LoadingText> : null}
        {assessments.isError ? (
          <ErrorNotice
            error={assessments.error}
            title="Could not list the assessments"
            onRetry={() => void assessments.refetch()}
          />
        ) : null}
        {assessments.data && rows.length === 0 ? <EmptyState>No assessments yet.</EmptyState> : null}
        {rows.length > 0 ? (
          <Table aria-label="Assessments">
            <TableHeader>
              <TableRow>
                <TableHead>Vendor and product</TableHead>
                <TableHead>Version</TableHead>
                <TableHead>Verdict</TableHead>
                <TableHead>Review</TableHead>
                <TableHead>Created</TableHead>
                <TableHead>Open</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((row) => (
                <TableRow key={row.id}>
                  <TableCell>
                    <span className="font-medium">{row.vendor_name ?? "-"}</span>
                    <span className="block text-xs text-muted-foreground">
                      {row.product ?? ""}
                      {row.hosting ? ` (${row.hosting})` : ""}
                    </span>
                  </TableCell>
                  <TableCell>{row.version_label ?? "-"}</TableCell>
                  <TableCell>
                    <StatusBadge status={row.status === "ready" ? row.verdict : row.status} />
                  </TableCell>
                  <TableCell>{row.review_state === "reviewed" ? "Reviewed" : "Awaiting review"}</TableCell>
                  <TableCell>{formatDateTime(row.created_at)}</TableCell>
                  <TableCell>
                    <div className="flex flex-col gap-1 text-sm">
                      <AppLink href={reportPath(row.id)} className="underline">
                        Review
                      </AppLink>
                      {vendorCopyAvailable(row) && row.html_ready ? (
                        <TextLink href={vendorCopyUrl(row.id, "html")} aria-label={`Vendor copy of ${row.product ?? row.id} as HTML`}>
                          Vendor copy (HTML)
                        </TextLink>
                      ) : null}
                      {vendorCopyAvailable(row) && row.pdf_ready ? (
                        <TextLink href={vendorCopyUrl(row.id, "pdf")} aria-label={`Vendor copy of ${row.product ?? row.id} as PDF`}>
                          Vendor copy (PDF)
                        </TextLink>
                      ) : null}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : null}
        <LoadMore
          hasMore={Boolean(assessments.hasNextPage)}
          loading={assessments.isFetchingNextPage}
          onClick={() => void assessments.fetchNextPage()}
        />
      </section>
    </>
  );
}
