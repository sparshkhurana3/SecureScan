/** Display helpers. Dates are shown in the viewer's time zone, 24-hour clock. */

const dateTime = new Intl.DateTimeFormat("en-GB", {
  year: "numeric",
  month: "short",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
});

const dateOnly = new Intl.DateTimeFormat("en-GB", {
  year: "numeric",
  month: "short",
  day: "2-digit",
});

function parse(value: string | null | undefined): Date | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function formatDateTime(value: string | null | undefined): string {
  const date = parse(value);
  return date ? dateTime.format(date) : "-";
}

export function formatDate(value: string | null | undefined): string {
  const date = parse(value);
  return date ? dateOnly.format(date) : "-";
}

/** "5 minutes ago", "in 2 hours", "just now". */
export function formatRelative(value: string | null | undefined, now: Date = new Date()): string {
  const date = parse(value);
  if (!date) return "-";
  const seconds = Math.round((date.getTime() - now.getTime()) / 1000);
  const abs = Math.abs(seconds);
  if (abs < 45) return "just now";
  const units: [number, string][] = [
    [86_400, "day"],
    [3_600, "hour"],
    [60, "minute"],
  ];
  for (const [size, name] of units) {
    if (abs >= size) {
      const count = Math.round(abs / size);
      const label = count + " " + name + (count === 1 ? "" : "s");
      return seconds < 0 ? label + " ago" : "in " + label;
    }
  }
  return "just now";
}

/** "2 h 05 min", "45 s". */
export function formatDuration(totalSeconds: number | null | undefined): string {
  if (totalSeconds === null || totalSeconds === undefined || !Number.isFinite(totalSeconds)) {
    return "-";
  }
  const seconds = Math.max(0, Math.round(totalSeconds));
  if (seconds < 60) return String(seconds) + " s";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return String(minutes) + " min " + String(seconds % 60).padStart(2, "0") + " s";
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return String(hours) + " h " + String(minutes % 60).padStart(2, "0") + " min";
  return String(Math.round(hours / 24)) + " days";
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes)) return "-";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return (unit === 0 ? String(value) : value.toFixed(1)) + " " + (units[unit] ?? "B");
}

export function formatNumber(value: number | null | undefined): string {
  return value === null || value === undefined ? "-" : value.toLocaleString("en-GB");
}

export function formatPercent(ratio: number | null | undefined): string {
  return ratio === null || ratio === undefined ? "-" : Math.round(ratio * 100).toString() + " %";
}

/** First 8 characters of a commit hash. */
export function shortSha(sha: string | null | undefined): string {
  return sha ? sha.slice(0, 8) : "-";
}

/** "completed_partial" -> "Completed partial". */
export function humanize(value: string | null | undefined): string {
  if (!value) return "-";
  const text = value.replace(/[_-]+/g, " ").trim();
  return text.charAt(0).toUpperCase() + text.slice(1);
}

export function pluralize(count: number, singular: string, plural?: string): string {
  return String(count) + " " + (count === 1 ? singular : (plural ?? singular + "s"));
}
