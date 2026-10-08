/**
 * Live progress of one scan: `GET /api/v1/scans/{id}/events` (server-sent events).
 *
 * The server sends, in this order: `snapshot` (the scan with its jobs), `log` (the last lines of each job,
 * marked `backlog`), then `state` and `log` events as things happen, and finally `done`. A stream that
 * ends without `done` is picked up again: the browser reconnects by itself while the connection is only
 * interrupted; when the browser gives up (readyState CLOSED) the hook opens a new one after a growing
 * delay. Every reconnect starts with a snapshot and the backlog again, so the backlog of a job replaces
 * the lines we hold for that job instead of being appended.
 *
 * `streamReducer` is a pure function (unit tested); `useScanEvents` is the React hook around it. The
 * scan page also polls `GET /scans/{id}`, so a missing EventSource only costs the live log.
 */
import { useEffect, useReducer, useRef } from "react";

import { apiUrl } from "../api/client";
import type { ScanDetail } from "../api/scans";

export const MAX_LOG_LINES = 5000;

export type LogLine = { id: number; jobId: string; tool: string; text: string };

export type ConnectionState = "idle" | "connecting" | "open" | "reconnecting" | "closed";

export type StreamState = {
  connection: ConnectionState;
  snapshot: ScanDetail | null;
  lines: LogLine[];
  nextId: number;
  done: boolean;
  doneState: string | null;
  /** A message the server sent in an `error` event (for example "Scan not found"). */
  serverError: string | null;
  /** Counts snapshots, state changes and the end: the page refreshes its data when it changes. */
  changes: number;
  /** How many times the connection had to be re-established. */
  reconnects: number;
};

export type LogPayload = { job_id?: string | null; tool?: string | null; lines?: unknown; backlog?: boolean };

export type StreamAction =
  | { type: "connecting" }
  | { type: "open" }
  | { type: "snapshot"; data: ScanDetail }
  | { type: "log"; data: LogPayload }
  | { type: "state" }
  | { type: "done"; state: string | null }
  | { type: "server_error"; message: string }
  | { type: "interrupted"; closed: boolean }
  | { type: "reset" };

export function initialStreamState(): StreamState {
  return {
    connection: "idle",
    snapshot: null,
    lines: [],
    nextId: 1,
    done: false,
    doneState: null,
    serverError: null,
    changes: 0,
    reconnects: 0,
  };
}

function toLines(payload: LogPayload): string[] {
  if (!Array.isArray(payload.lines)) return [];
  return payload.lines.filter((line): line is string => typeof line === "string");
}

export function streamReducer(state: StreamState, action: StreamAction): StreamState {
  switch (action.type) {
    case "reset":
      return initialStreamState();
    case "connecting":
      return { ...state, connection: state.reconnects > 0 ? "reconnecting" : "connecting" };
    case "open":
      return { ...state, connection: "open", serverError: null };
    case "snapshot":
      return { ...state, snapshot: action.data, changes: state.changes + 1 };
    case "state":
      return { ...state, changes: state.changes + 1 };
    case "log": {
      const texts = toLines(action.data);
      const jobId = action.data.job_id ?? "";
      const tool = action.data.tool ?? "";
      // A backlog replaces what we hold for the job (it is sent again after every reconnect).
      let kept = action.data.backlog ? state.lines.filter((line) => line.jobId !== jobId) : state.lines;
      if (texts.length === 0 && kept === state.lines) return state;
      let nextId = state.nextId;
      const added: LogLine[] = texts.map((text) => ({ id: nextId++, jobId, tool, text }));
      kept = kept.concat(added);
      if (kept.length > MAX_LOG_LINES) kept = kept.slice(kept.length - MAX_LOG_LINES);
      return { ...state, lines: kept, nextId };
    }
    case "done":
      return { ...state, done: true, doneState: action.state, connection: "closed", changes: state.changes + 1 };
    case "server_error":
      return { ...state, serverError: action.message, connection: "closed" };
    case "interrupted":
      return {
        ...state,
        connection: action.closed ? "closed" : "reconnecting",
        reconnects: state.reconnects + 1,
      };
  }
}

/** The part of the browser's EventSource that the hook uses (a fake implements the same). */
export type EventSourceLike = {
  readyState: number;
  close(): void;
  addEventListener(type: string, listener: (event: Event) => void): void;
};

export type EventSourceFactory = (url: string) => EventSourceLike;

const CLOSED = 2;

function defaultFactory(): EventSourceFactory | null {
  if (typeof EventSource === "undefined") return null;
  return (url) => new EventSource(url) as unknown as EventSourceLike;
}

export type ScanEventsOptions = {
  /** Replaces `new EventSource(url)`; used by tests. */
  factory?: EventSourceFactory;
  /** Turn the stream off (for example for a scan that finished long ago). Default true. */
  enabled?: boolean;
  /** Wait before reopening a stream the browser gave up on: 1 s, doubling up to this many ms (default 15000). */
  maxBackoffMs?: number;
  baseBackoffMs?: number;
};

function readJson(event: Event): unknown {
  const data = (event as MessageEvent<unknown>).data;
  if (typeof data !== "string") return undefined;
  try {
    return JSON.parse(data) as unknown;
  } catch {
    return undefined;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Opens the stream of a scan and keeps it open until the server says `done`. */
export function useScanEvents(scanId: string | undefined, options: ScanEventsOptions = {}): StreamState {
  const [state, dispatch] = useReducer(streamReducer, undefined, initialStreamState);
  const { factory, enabled = true, maxBackoffMs = 15_000, baseBackoffMs = 1000 } = options;
  const factoryRef = useRef(factory);
  factoryRef.current = factory;

  useEffect(() => {
    dispatch({ type: "reset" });
    if (!scanId || !enabled) return undefined;
    const create = factoryRef.current ?? defaultFactory();
    if (!create) return undefined;

    let stopped = false;
    let finished = false;
    let source: EventSourceLike | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let failures = 0;

    const open = () => {
      if (stopped) return;
      dispatch({ type: "connecting" });
      const current = create(apiUrl(`/scans/${scanId}/events`));
      source = current;
      current.addEventListener("open", () => {
        failures = 0;
        dispatch({ type: "open" });
      });
      current.addEventListener("snapshot", (event) => {
        const data = readJson(event);
        if (isRecord(data) && Array.isArray(data.jobs)) dispatch({ type: "snapshot", data: data as unknown as ScanDetail });
      });
      current.addEventListener("log", (event) => {
        const data = readJson(event);
        if (isRecord(data)) dispatch({ type: "log", data: data as LogPayload });
      });
      current.addEventListener("state", () => dispatch({ type: "state" }));
      current.addEventListener("done", (event) => {
        const data = readJson(event);
        finished = true;
        current.close();
        dispatch({ type: "done", state: isRecord(data) && typeof data.state === "string" ? data.state : null });
      });
      // "error" is both the browser's connection error (a plain Event) and a server event with data.
      current.addEventListener("error", (event) => {
        if (stopped || finished) return;
        const data = readJson(event);
        if (isRecord(data)) {
          const message = typeof data.detail === "string" ? data.detail : "The live stream reported an error.";
          finished = true;
          current.close();
          dispatch({ type: "server_error", message });
          return;
        }
        if (current.readyState === CLOSED) {
          failures += 1;
          dispatch({ type: "interrupted", closed: false });
          const delay = Math.min(maxBackoffMs, baseBackoffMs * 2 ** Math.max(0, failures - 1));
          timer = setTimeout(open, delay);
        } else {
          dispatch({ type: "interrupted", closed: false }); // the browser is reconnecting by itself
        }
      });
    };
    open();

    return () => {
      stopped = true;
      if (timer !== undefined) clearTimeout(timer);
      source?.close();
    };
  }, [scanId, enabled, maxBackoffMs, baseBackoffMs]);

  return state;
}
