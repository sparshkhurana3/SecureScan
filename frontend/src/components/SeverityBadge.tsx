import type { SeverityCounts } from "../api/summary";
import { humanize } from "../lib/format";
import { Badge, type BadgeTone } from "./ui/badge";

const SEVERITY_TONES: Record<string, BadgeTone> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
  informational: "info",
};

export function severityTone(severity: string): BadgeTone {
  return SEVERITY_TONES[severity.trim().toLowerCase()] ?? "info";
}

/** A severity as coloured text on a pill. The word is always shown, so colour is never the only signal. */
export function SeverityBadge({
  severity,
  count,
  className,
}: {
  severity: string;
  /** Shown after the word, for example "Critical 3". */
  count?: number;
  className?: string;
}) {
  return (
    <Badge tone={severityTone(severity)} className={className} data-severity={severity.toLowerCase()}>
      {humanize(severity)}
      {count !== undefined ? <span className="ml-1.5 tabular-nums">{count}</span> : null}
    </Badge>
  );
}

const ORDER = ["critical", "high", "medium", "low", "info"] as const;

/** Every severity that has findings, as badges with counts; "None" when there are none. */
export function SeverityCountBadges({
  counts,
  showZero = false,
}: {
  counts: SeverityCounts | null | undefined;
  showZero?: boolean;
}) {
  const shown = ORDER.filter((name) => showZero || (counts?.[name] ?? 0) > 0);
  if (shown.length === 0) return <span className="text-muted-foreground">None</span>;
  return (
    <span className="inline-flex flex-wrap gap-1">
      {shown.map((name) => (
        <SeverityBadge key={name} severity={name} count={counts?.[name] ?? 0} />
      ))}
    </span>
  );
}
