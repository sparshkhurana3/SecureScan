import { useEffect, useId, useMemo, useRef, useState } from "react";

import { toolLabel, useJobLog } from "../api/scans";
import { MAX_LOG_LINES, type ConnectionState, type LogLine } from "../lib/sse";
import { CheckField } from "./FormBits";
import { Button } from "./ui/button";
import { Label } from "./ui/label";
import { Select } from "./ui/select";

const CONNECTION_TEXT: Record<ConnectionState, string> = {
  idle: "Not connected",
  connecting: "Connecting to the live log...",
  open: "Live",
  reconnecting: "Connection lost, reconnecting...",
  closed: "Stream ended",
};

/**
 * The log of a scan: lines from the live stream (the last few thousand), one tool or all of them, with
 * "follow the end" and, for one tool, the full stored log on request. The text is plain: it is never
 * interpreted as markup.
 */
export function LogViewer({
  scanId,
  jobs,
  lines,
  connection,
  serverError,
}: {
  scanId: string;
  jobs: { id: string; tool: string }[];
  lines: LogLine[];
  connection: ConnectionState;
  serverError?: string | null;
}) {
  const selectId = useId();
  const followId = useId();
  const [jobId, setJobId] = useState<string>("");
  const [follow, setFollow] = useState(true);
  const [loadFull, setLoadFull] = useState(false);
  const boxRef = useRef<HTMLPreElement>(null);

  const shown = useMemo(() => (jobId ? lines.filter((line) => line.jobId === jobId) : lines), [lines, jobId]);
  const full = useJobLog(scanId, jobId || null, loadFull && Boolean(jobId));
  const showingFull = loadFull && Boolean(jobId) && full.data !== undefined;
  const text = showingFull
    ? (full.data ?? "")
    : shown.map((line) => (jobId ? line.text : `[${line.tool}] ${line.text}`)).join("\n");

  useEffect(() => {
    const box = boxRef.current;
    if (follow && box) box.scrollTop = box.scrollHeight;
  }, [text, follow]);

  const changeJob = (value: string) => {
    setJobId(value);
    setLoadFull(false);
  };

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-end gap-4">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor={selectId}>Show the log of</Label>
          <Select id={selectId} value={jobId} onChange={(event) => changeJob(event.target.value)} className="w-56">
            <option value="">All tools</option>
            {jobs.map((job) => (
              <option key={job.id} value={job.id}>
                {toolLabel(job.tool)}
              </option>
            ))}
          </Select>
        </div>
        <CheckField id={followId} label="Follow the end" checked={follow} onCheckedChange={setFollow} className="pb-2" />
        {jobId ? (
          <Button
            variant="outline"
            size="sm"
            onClick={() => setLoadFull((value) => !value)}
            disabled={full.isFetching}
            className="mb-0.5"
          >
            {loadFull ? "Show the live tail" : full.isFetching ? "Loading..." : "Load the full log"}
          </Button>
        ) : null}
        <p className="m-0 pb-2 text-sm text-muted-foreground" role="status" data-testid="log-connection">
          {CONNECTION_TEXT[connection]}
        </p>
      </div>
      {serverError ? (
        <p role="alert" className="m-0 text-sm font-medium">
          {serverError}
        </p>
      ) : null}
      {full.isError && loadFull ? (
        <p role="alert" className="m-0 text-sm font-medium">
          The full log could not be loaded.
        </p>
      ) : null}
      <pre
        ref={boxRef}
        role="log"
        aria-label="Scan log"
        aria-live="off"
        tabIndex={0}
        data-testid="scan-log"
        className="m-0 h-96 overflow-auto whitespace-pre-wrap break-words rounded-md border border-border bg-muted p-3 font-mono text-xs leading-relaxed"
      >
        {text || (connection === "open" ? "Waiting for output..." : "No log lines yet.")}
      </pre>
      {!showingFull && lines.length >= MAX_LOG_LINES ? (
        <p className="m-0 text-xs text-muted-foreground">
          Only the last {MAX_LOG_LINES} lines are kept here. Choose one tool and load its full log to see all of it.
        </p>
      ) : null}
    </div>
  );
}
