import { humanize } from "../lib/format";
import { Badge, type BadgeTone } from "./ui/badge";

type StatusStyle = { tone: BadgeTone; label?: string };

/** Scan, job, import, report and verdict states, and the words the portal shows for them. */
const STATUSES: Record<string, StatusStyle> = {
  queued: { tone: "neutral" },
  pending: { tone: "neutral" },
  preparing: { tone: "active" },
  running: { tone: "active" },
  processing: { tone: "active" },
  completed: { tone: "ok" },
  completed_partial: { tone: "warn", label: "Completed (partial)" },
  imported: { tone: "ok" },
  ready: { tone: "ok" },
  done: { tone: "ok" },
  ok: { tone: "ok", label: "OK" },
  pass: { tone: "ok", label: "Pass" },
  active: { tone: "ok" },
  conditional: { tone: "warn" },
  skipped: { tone: "neutral" },
  not_applicable: { tone: "neutral", label: "Not applicable" },
  cancelled: { tone: "neutral" },
  disabled: { tone: "neutral" },
  failed: { tone: "bad" },
  fail: { tone: "bad", label: "Fail" },
  timed_out: { tone: "bad", label: "Timed out" },
  dead_letter: { tone: "bad", label: "Failed (needs replay)" },
  error: { tone: "bad" },
  degraded: { tone: "warn" },
};

export function statusTone(status: string): BadgeTone {
  return STATUSES[status.trim().toLowerCase()]?.tone ?? "neutral";
}

export function statusLabel(status: string): string {
  return STATUSES[status.trim().toLowerCase()]?.label ?? humanize(status);
}

/** A scan, job, import, report or verdict state as a labelled pill. */
export function StatusBadge({
  status,
  label,
  className,
}: {
  status: string;
  /** Replace the default wording. */
  label?: string;
  className?: string;
}) {
  return (
    <Badge tone={statusTone(status)} className={className} data-status={status.toLowerCase()}>
      {label ?? statusLabel(status)}
    </Badge>
  );
}
