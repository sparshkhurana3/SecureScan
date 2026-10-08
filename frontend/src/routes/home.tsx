import { Link } from "@tanstack/react-router";
import { type ReactNode, useState } from "react";

import {
  defectDojoLoginUrl,
  type MyDefectDojoAccount,
  type PasswordReset,
  useForgetInitialPassword,
  useMyDefectDojoAccount,
  useResetMyDefectDojoPassword,
} from "../api/defectdojo";
import type { Summary, SummaryScan } from "../api/summary";
import { useSummary } from "../api/summary";
import { SeverityBadge, SeverityCountBadges } from "../components/SeverityBadge";
import { StatusBadge } from "../components/StatusBadge";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "../components/ui/dialog";
import { Input } from "../components/ui/input";
import { Label } from "../components/ui/label";
import { ErrorNotice, LoadingText, PageHeader } from "../components/ui/page";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../components/ui/table";
import { useMe } from "../lib/auth";
import { formatDateTime, formatNumber } from "../lib/format";

// ------------------------------------------------------------------------------------------ tiles

function Tile({ title, value, children }: { title: string; value: string; children?: ReactNode }) {
  return (
    <Card>
      <CardHeader className="pb-1">
        <CardDescription>{title}</CardDescription>
        <p className="text-3xl font-semibold tabular-nums">{value}</p>
      </CardHeader>
      {children ? <CardContent className="text-sm text-muted-foreground">{children}</CardContent> : null}
    </Card>
  );
}

function SummaryTiles({ summary, isAdmin }: { summary: Summary; isAdmin: boolean }) {
  const open = summary.open_counts;
  return (
    <section aria-label="Summary" className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <Tile title="Applications scanned" value={`${formatNumber(summary.applications_scanned)} of ${formatNumber(summary.applications)}`}>
        Applications with at least one finished scan.
      </Tile>
      <Tile title="Running scans" value={formatNumber(summary.running.length)}>
        {summary.queued.length > 0 ? `${formatNumber(summary.queued.length)} waiting in the queue.` : "Nothing waiting."}
      </Tile>
      <Tile title="Open findings" value={formatNumber(open.total ?? 0)}>
        <span className="inline-flex flex-wrap gap-1">
          {(["critical", "high", "medium", "low"] as const).map((name) => (
            <SeverityBadge key={name} severity={name} count={open[name] ?? 0} />
          ))}
        </span>
      </Tile>
      <Tile title="Results waiting for DefectDojo" value={formatNumber(summary.import_queue.pending)}>
        {summary.import_queue.dead_letters > 0 ? (
          <>
            <strong className="text-foreground">
              {formatNumber(summary.import_queue.dead_letters)} failed
            </strong>
            {isAdmin ? (
              <>
                {" "}
                -{" "}
                <Link to="/settings/defectdojo" className="underline">
                  replay them in Settings
                </Link>
              </>
            ) : (
              " - ask an Admin to replay them."
            )}
          </>
        ) : (
          "Imports are up to date."
        )}
      </Tile>
    </section>
  );
}

// ------------------------------------------------------------------------------------------ scan tables

function ScanTable({ caption, scans }: { caption: string; scans: SummaryScan[] }) {
  return (
    <Table aria-label={caption}>
      <TableHeader>
        <TableRow>
          <TableHead>Application</TableHead>
          <TableHead>Version</TableHead>
          <TableHead>Kind</TableHead>
          <TableHead>State</TableHead>
          <TableHead>Tools done</TableHead>
          <TableHead>Open findings</TableHead>
          <TableHead>Verdict</TableHead>
          <TableHead>When</TableHead>
          <TableHead>
            <span className="sr-only">Actions</span>
          </TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {scans.map((scan) => (
          <TableRow key={scan.scan_id}>
            <TableCell className="font-medium">{scan.application_name}</TableCell>
            <TableCell>{scan.version_label}</TableCell>
            <TableCell>{scan.kind.toUpperCase()}</TableCell>
            <TableCell>
              <StatusBadge status={scan.state} />
            </TableCell>
            <TableCell className="tabular-nums">
              {scan.jobs_done} / {scan.jobs_total}
            </TableCell>
            <TableCell>
              <SeverityCountBadges counts={scan.counts} />
            </TableCell>
            <TableCell>
              <StatusBadge status={scan.verdict} />
            </TableCell>
            <TableCell className="whitespace-nowrap">
              {formatDateTime(scan.finished_at ?? scan.started_at ?? scan.created_at)}
            </TableCell>
            <TableCell>
              <Link to="/scans/$scanId" params={{ scanId: scan.scan_id }} className="underline">
                Details<span className="sr-only"> of {scan.application_name}</span>
              </Link>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function ScanSection({ title, scans, empty }: { title: string; scans: SummaryScan[]; empty: string }) {
  const headingId = "section-" + title.toLowerCase().replace(/[^a-z0-9]+/g, "-");
  return (
    <section aria-labelledby={headingId} className="mt-8">
      <h2 id={headingId} className="mb-3 text-lg font-semibold">
        {title}
      </h2>
      {scans.length === 0 ? (
        <p className="rounded-md border border-dashed border-border p-4 text-sm text-muted-foreground">{empty}</p>
      ) : (
        <ScanTable caption={title} scans={scans} />
      )}
    </section>
  );
}

// ------------------------------------------------------------------------------------------ DefectDojo account

/** A password that is shown masked until asked for, with copy. It is never written anywhere. */
function SecretReveal({ label, value, onDone }: { label: string; value: string; onDone: () => void }) {
  const [visible, setVisible] = useState(false);
  const [copied, setCopied] = useState<"yes" | "failed" | null>(null);
  const copy = () => {
    navigator.clipboard.writeText(value).then(
      () => setCopied("yes"),
      () => setCopied("failed"),
    );
  };
  return (
    <div className="rounded-md border border-foreground p-4">
      <p className="text-sm font-semibold">This is shown only once. Save it now.</p>
      <p className="mt-1 text-sm text-muted-foreground">
        DefectDojo asks you to choose your own password the first time you sign in.
      </p>
      <div className="mt-3 flex flex-wrap items-end gap-2">
        <div className="flex min-w-60 flex-1 flex-col gap-1.5">
          <Label htmlFor="dd-secret">{label}</Label>
          <Input
            id="dd-secret"
            readOnly
            type={visible ? "text" : "password"}
            value={value}
            autoComplete="off"
            spellCheck={false}
            className="font-mono"
          />
        </div>
        <Button variant="outline" onClick={() => setVisible((v) => !v)} aria-pressed={visible}>
          {visible ? "Hide password" : "Show password"}
        </Button>
        <Button variant="outline" onClick={copy}>
          Copy password
        </Button>
        <Button onClick={onDone}>I have saved it</Button>
      </div>
      <p role="status" className="mt-2 min-h-5 text-sm">
        {copied === "yes" ? "Copied to the clipboard." : null}
        {copied === "failed" ? "Could not copy. Use Show password and copy it by hand." : null}
      </p>
    </div>
  );
}

function ResetDialog({
  open,
  onOpenChange,
  onReset,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onReset: (result: PasswordReset) => void;
}) {
  const reset = useResetMyDefectDojoPassword();
  const confirm = () =>
    reset.mutate(undefined, {
      onSuccess: (result) => {
        onReset(result);
        onOpenChange(false);
      },
    });
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Reset your DefectDojo password?</DialogTitle>
          <DialogDescription>
            A new random password is set and shown once. Your old password stops working. You will be
            asked to choose your own password when you next sign in to DefectDojo.
          </DialogDescription>
        </DialogHeader>
        {reset.error ? <ErrorNotice error={reset.error} title="The password was not reset" /> : null}
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <Button onClick={confirm} disabled={reset.isPending}>
            {reset.isPending ? "Resetting..." : "Reset password"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function accountNote(account: MyDefectDojoAccount): string | null {
  if (account.status === "disabled" || account.disabled) {
    return "Your DefectDojo account is disabled. Ask an Admin to enable it.";
  }
  if (account.status === "unavailable") {
    return account.detail ?? "Your DefectDojo account is not ready yet. Reload this page in a moment.";
  }
  return account.detail;
}

export function DefectDojoAccountPanel() {
  const account = useMyDefectDojoAccount();
  const forget = useForgetInitialPassword();
  const [resetOpen, setResetOpen] = useState(false);
  const [fresh, setFresh] = useState<PasswordReset | null>(null);

  let body: ReactNode;
  if (account.isPending) {
    body = <LoadingText>Loading your DefectDojo account...</LoadingText>;
  } else if (account.isError) {
    body = <ErrorNotice error={account.error} title="Could not load your DefectDojo account" />;
  } else {
    const data = account.data;
    const note = accountNote(data);
    const ready = data.status === "ready" && !data.disabled;
    body = (
      <div className="flex flex-col gap-4">
        {note ? <p className="text-sm">{note}</p> : null}
        {data.username ? (
          <p className="text-sm">
            User name: <strong className="font-mono">{data.username}</strong>
          </p>
        ) : null}
        {data.initial_password ? (
          <SecretReveal label="Your first password" value={data.initial_password} onDone={forget} />
        ) : null}
        {fresh ? (
          <SecretReveal label="Your new password" value={fresh.password} onDone={() => setFresh(null)} />
        ) : null}
        {ready && !data.initial_password && !fresh ? (
          <p className="text-sm text-muted-foreground">
            Your first password was shown once and is not stored where anyone can read it. If you
            lost it, set a new one.
          </p>
        ) : null}
        {ready ? (
          <div>
            <Button variant="outline" onClick={() => setResetOpen(true)}>
              Reset DefectDojo password
            </Button>
          </div>
        ) : null}
      </div>
    );
  }

  return (
    <Card className="mt-8" aria-labelledby="dd-account-title">
      <CardHeader>
        <CardTitle id="dd-account-title">Your DefectDojo account</CardTitle>
        <CardDescription>
          DefectDojo holds the findings and their triage. You sign in there with the account made
          for you here.
        </CardDescription>
      </CardHeader>
      <CardContent>{body}</CardContent>
      <ResetDialog open={resetOpen} onOpenChange={setResetOpen} onReset={setFresh} />
    </Card>
  );
}

// ------------------------------------------------------------------------------------------ page

export function HomePage() {
  const { user } = useMe();
  const summary = useSummary();
  const dojoBase = summary.data?.defectdojo_url ?? user?.defectdojoUrl;

  return (
    <>
      <PageHeader
        title="Home"
        description="What is running, what finished lately, and how many findings are open."
        actions={
          dojoBase ? (
            <Button asChild>
              <a href={defectDojoLoginUrl(dojoBase)} target="_blank" rel="noopener noreferrer">
                Open DefectDojo<span className="sr-only"> (opens in a new tab)</span>
              </a>
            </Button>
          ) : null
        }
      />
      {summary.isPending ? <LoadingText>Loading the summary...</LoadingText> : null}
      {summary.isError ? (
        <ErrorNotice error={summary.error} title="Could not load the summary" onRetry={() => void summary.refetch()} />
      ) : null}
      {summary.data ? (
        <>
          <SummaryTiles summary={summary.data} isAdmin={user?.role === "Admin"} />
          <ScanSection title="Running scans" scans={summary.data.running} empty="No scan is running." />
          <ScanSection title="Waiting in the queue" scans={summary.data.queued} empty="No scan is waiting." />
          <ScanSection
            title="Latest results"
            scans={summary.data.latest}
            empty="No scan has finished yet. Start one from the SAST scan page."
          />
        </>
      ) : null}
      <DefectDojoAccountPanel />
      <p className="mt-6 text-xs text-muted-foreground">This page updates every 15 seconds.</p>
    </>
  );
}
