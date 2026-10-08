import { type FormEvent, useState } from "react";

import {
  type Schedule,
  type ScheduleInput,
  type ScheduleKind,
  useCreateSchedule,
  useDeleteSchedule,
  useSchedules,
  useUpdateSchedule,
} from "../../api/admin";
import { StatusBadge } from "../../components/StatusBadge";
import { Button } from "../../components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../../components/ui/card";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "../../components/ui/dialog";
import { Input } from "../../components/ui/input";
import { EmptyState, ErrorNotice, Field, LoadingText, PageHeader } from "../../components/ui/page";
import { Select } from "../../components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../../components/ui/table";
import { formatDateTime, humanize } from "../../lib/format";

const KIND_LABELS: Record<ScheduleKind, string> = {
  weekly: "Weekly scan of repositories",
  dast: "DAST scan of a target",
  poll: "Change polling",
};

function whatItDoes(schedule: Schedule): string {
  if (schedule.kind === "poll") {
    return `Look for new commits at least every ${schedule.poll_interval_minutes ?? "?"} minutes`;
  }
  if (schedule.kind === "weekly") {
    const set = schedule.repository_set;
    const repos = set.application_ids
      ? `${set.application_ids.length} chosen repositories`
      : "all repositories with automatic scans";
    return `Scan ${repos} with ${schedule.profile_name ?? "the standard profile"}`;
  }
  return `Scan one URL target with ${schedule.profile_name ?? "a DAST profile"}`;
}

function NewScheduleForm() {
  const create = useCreateSchedule();
  const [kind, setKind] = useState<"weekly" | "poll">("weekly");
  const [name, setName] = useState("");
  const [cron, setCron] = useState("0 2 * * 0");
  const [pollMinutes, setPollMinutes] = useState("10");
  const [profile, setProfile] = useState("code-standard");
  const [done, setDone] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setDone(null);
    setProblem(null);
    const body: ScheduleInput = { name: name.trim(), kind };
    if (kind === "weekly") {
      body.cron = cron.trim();
      body.profile_name = profile.trim();
      body.repository_set = { mode: "automatic" };
    } else {
      const minutes = Number(pollMinutes);
      if (!Number.isInteger(minutes) || minutes < 1 || minutes > 1440) {
        setProblem("The interval must be a whole number of minutes from 1 to 1440.");
        return;
      }
      body.poll_interval_minutes = minutes;
    }
    create.mutate(body, {
      onSuccess: (created) => {
        setDone(`Created "${created.name}".`);
        setName("");
      },
    });
  };

  return (
    <Card className="mt-8">
      <CardHeader>
        <CardTitle>New schedule</CardTitle>
        <CardDescription>
          Times are UTC. A weekly scan covers the repositories that have automatic scans switched on.
          DAST schedules are added when a URL target is ready for them.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} aria-label="New schedule" className="flex flex-col gap-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <Field id="schedule-kind" label="Kind">
              <Select
                id="schedule-kind"
                value={kind}
                onChange={(e) => setKind(e.target.value === "poll" ? "poll" : "weekly")}
              >
                <option value="weekly">{KIND_LABELS.weekly}</option>
                <option value="poll">{KIND_LABELS.poll}</option>
              </Select>
            </Field>
            <Field id="schedule-name" label="Name">
              <Input
                id="schedule-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                maxLength={200}
                required
              />
            </Field>
            {kind === "weekly" ? (
              <>
                <Field
                  id="schedule-cron"
                  label="When (cron, UTC)"
                  help="Minute, hour, day of month, month, day of week. The default is Sunday at 02:00."
                >
                  <Input
                    id="schedule-cron"
                    value={cron}
                    onChange={(e) => setCron(e.target.value)}
                    className="font-mono"
                    required
                  />
                </Field>
                <Field id="schedule-profile" label="Scan profile">
                  <Input
                    id="schedule-profile"
                    value={profile}
                    onChange={(e) => setProfile(e.target.value)}
                    required
                  />
                </Field>
              </>
            ) : (
              <Field id="schedule-interval" label="Poll at least every (minutes)">
                <Input
                  id="schedule-interval"
                  inputMode="numeric"
                  value={pollMinutes}
                  onChange={(e) => setPollMinutes(e.target.value)}
                  required
                />
              </Field>
            )}
          </div>
          {problem ? (
            <p role="alert" className="text-sm font-medium">
              {problem}
            </p>
          ) : null}
          {create.error ? <ErrorNotice error={create.error} title="The schedule was not created" /> : null}
          {done ? (
            <p role="status" className="text-sm font-medium">
              {done}
            </p>
          ) : null}
          <div>
            <Button type="submit" disabled={create.isPending || !name.trim()}>
              {create.isPending ? "Creating..." : "Create schedule"}
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

export function SchedulesPage() {
  const schedules = useSchedules();
  const update = useUpdateSchedule();
  const remove = useDeleteSchedule();
  const [deleting, setDeleting] = useState<Schedule | null>(null);

  return (
    <>
      <PageHeader
        title="Schedules"
        description="Scans that start by themselves, and how often SecureScan looks for new commits."
      />
      {schedules.isPending ? <LoadingText>Loading schedules...</LoadingText> : null}
      {schedules.isError ? (
        <ErrorNotice error={schedules.error} title="Could not load schedules" onRetry={() => void schedules.refetch()} />
      ) : null}
      {update.error ? <ErrorNotice error={update.error} title="The change was not saved" className="mb-4" /> : null}
      {schedules.data ? (
        schedules.data.length === 0 ? (
          <EmptyState>No schedules yet. Create a weekly scan below.</EmptyState>
        ) : (
          <Table aria-label="Schedules">
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>What it does</TableHead>
                <TableHead>When (UTC)</TableHead>
                <TableHead>Next run</TableHead>
                <TableHead>Last run</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {schedules.data.map((schedule) => (
                <TableRow key={schedule.id}>
                  <TableCell className="font-medium">
                    {schedule.name}
                    <span className="block text-xs font-normal text-muted-foreground">
                      {KIND_LABELS[schedule.kind]}
                    </span>
                  </TableCell>
                  <TableCell className="max-w-xs">{whatItDoes(schedule)}</TableCell>
                  <TableCell className="font-mono text-xs">
                    {schedule.cron ?? (schedule.poll_interval_minutes ? `every ${schedule.poll_interval_minutes} min` : "-")}
                    {schedule.blackout_windows.length > 0 ? (
                      <span className="block font-sans text-muted-foreground">
                        {schedule.blackout_windows.length} blackout window(s)
                      </span>
                    ) : null}
                  </TableCell>
                  <TableCell className="whitespace-nowrap">{formatDateTime(schedule.next_run_at)}</TableCell>
                  <TableCell className="whitespace-nowrap">
                    {formatDateTime(schedule.last_run_at)}
                    {schedule.last_status ? (
                      <span className="block text-xs text-muted-foreground">{humanize(schedule.last_status)}</span>
                    ) : null}
                  </TableCell>
                  <TableCell>
                    <StatusBadge
                      status={schedule.enabled ? "active" : "disabled"}
                      label={schedule.enabled ? "On" : "Off"}
                    />
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={update.isPending}
                        onClick={() => update.mutate({ id: schedule.id, enabled: !schedule.enabled })}
                      >
                        {schedule.enabled ? "Switch off" : "Switch on"}
                        <span className="sr-only"> {schedule.name}</span>
                      </Button>
                      <Button size="sm" variant="ghost" onClick={() => setDeleting(schedule)}>
                        Delete<span className="sr-only"> {schedule.name}</span>
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )
      ) : null}
      <NewScheduleForm />
      <Dialog
        open={deleting !== null}
        onOpenChange={(open) => {
          if (!open) {
            setDeleting(null);
            remove.reset();
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete {deleting?.name}?</DialogTitle>
            <DialogDescription>
              The schedule stops for good. Scans it already started are not affected. The deletion is
              recorded in the audit log.
            </DialogDescription>
          </DialogHeader>
          {remove.error ? <ErrorNotice error={remove.error} title="The schedule was not deleted" /> : null}
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="outline">Cancel</Button>
            </DialogClose>
            <Button
              onClick={() => deleting && remove.mutate(deleting.id, { onSuccess: () => setDeleting(null) })}
              disabled={remove.isPending}
            >
              {remove.isPending ? "Deleting..." : "Delete schedule"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
