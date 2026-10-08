import { type FormEvent, useState } from "react";

import {
  type AuditEvent,
  type AuditFilters,
  EMPTY_AUDIT_FILTERS,
  useAuditEvents,
} from "../../api/audit";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { EmptyState, ErrorNotice, Field, LoadingText, LoadMore, PageHeader } from "../../components/ui/page";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../../components/ui/table";
import { formatDateTime } from "../../lib/format";

function DetailCell({ event }: { event: AuditEvent }) {
  const keys = Object.keys(event.detail);
  if (keys.length === 0) return <span className="text-muted-foreground">-</span>;
  return (
    <details>
      <summary className="cursor-pointer text-xs underline">
        Details<span className="sr-only"> of {event.action}</span>
      </summary>
      <pre className="mt-1 max-w-md overflow-auto whitespace-pre-wrap break-words rounded bg-muted p-2 font-mono text-xs">
        {JSON.stringify(event.detail, null, 2)}
      </pre>
    </details>
  );
}

export function AuditPage() {
  const [draft, setDraft] = useState<AuditFilters>(EMPTY_AUDIT_FILTERS);
  const [applied, setApplied] = useState<AuditFilters>(EMPTY_AUDIT_FILTERS);
  const events = useAuditEvents(applied);
  const items = events.data?.pages.flatMap((page) => page.items) ?? [];
  const set = (key: keyof AuditFilters, value: string) => setDraft((d) => ({ ...d, [key]: value }));

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setApplied(draft);
  };
  const clear = () => {
    setDraft(EMPTY_AUDIT_FILTERS);
    setApplied(EMPTY_AUDIT_FILTERS);
  };

  return (
    <>
      <PageHeader
        title="Audit log"
        description="Who did what: sign-ins, scans, downloads, exports and every change in Settings. Entries cannot be changed or deleted. Newest first."
      />
      <form
        onSubmit={submit}
        aria-label="Audit filters"
        className="mb-4 grid gap-4 rounded-md border border-border p-4 sm:grid-cols-2 lg:grid-cols-3"
      >
        <Field id="audit-actor" label="Person contains">
          <Input id="audit-actor" value={draft.actor} onChange={(e) => set("actor", e.target.value)} />
        </Field>
        <Field id="audit-action" label="Action starts with" help="For example scan, report, export or auth.">
          <Input
            id="audit-action"
            value={draft.action_prefix}
            onChange={(e) => set("action_prefix", e.target.value)}
          />
        </Field>
        <Field id="audit-object-type" label="Object type">
          <Input
            id="audit-object-type"
            value={draft.object_type}
            onChange={(e) => set("object_type", e.target.value)}
            placeholder="report"
          />
        </Field>
        <Field id="audit-object-id" label="Object ID">
          <Input
            id="audit-object-id"
            value={draft.object_id}
            onChange={(e) => set("object_id", e.target.value)}
          />
        </Field>
        <Field id="audit-from" label="From date">
          <Input id="audit-from" type="date" value={draft.from} onChange={(e) => set("from", e.target.value)} />
        </Field>
        <Field id="audit-to" label="To date">
          <Input id="audit-to" type="date" value={draft.to} onChange={(e) => set("to", e.target.value)} />
        </Field>
        <div className="flex gap-2 sm:col-span-2 lg:col-span-3">
          <Button type="submit">Apply filters</Button>
          <Button type="button" variant="outline" onClick={clear}>
            Clear filters
          </Button>
        </div>
      </form>
      {events.isPending ? <LoadingText>Loading the audit log...</LoadingText> : null}
      {events.isError ? (
        <ErrorNotice error={events.error} title="Could not load the audit log" onRetry={() => void events.refetch()} />
      ) : null}
      {events.data ? (
        items.length === 0 ? (
          <EmptyState>No entries match these filters.</EmptyState>
        ) : (
          <Table aria-label="Audit log">
            <TableHeader>
              <TableRow>
                <TableHead>When</TableHead>
                <TableHead>Person</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Object</TableHead>
                <TableHead>From address</TableHead>
                <TableHead>Details</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((event) => (
                <TableRow key={event.id}>
                  <TableCell className="whitespace-nowrap">{formatDateTime(event.created_at)}</TableCell>
                  <TableCell>{event.actor_label}</TableCell>
                  <TableCell className="font-mono text-xs">{event.action}</TableCell>
                  <TableCell className="break-all text-xs">
                    {event.object_type ?? "-"}
                    {event.object_id ? <span className="block text-muted-foreground">{event.object_id}</span> : null}
                  </TableCell>
                  <TableCell className="font-mono text-xs">{event.source_ip ?? "-"}</TableCell>
                  <TableCell>
                    <DetailCell event={event} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )
      ) : null}
      <LoadMore
        hasMore={Boolean(events.hasNextPage)}
        loading={events.isFetchingNextPage}
        onClick={() => void events.fetchNextPage()}
      />
    </>
  );
}
