import { act, renderHook } from "@testing-library/react";

import type { ScanDetail } from "../api/scans";
import {
  initialStreamState,
  MAX_LOG_LINES,
  streamReducer,
  useScanEvents,
  type EventSourceLike,
  type StreamAction,
  type StreamState,
} from "./sse";

class FakeSource implements EventSourceLike {
  static instances: FakeSource[] = [];
  readyState = 0;
  closed = false;
  private listeners = new Map<string, ((event: Event) => void)[]>();

  constructor(readonly url: string) {
    FakeSource.instances.push(this);
  }

  addEventListener(type: string, listener: (event: Event) => void): void {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]);
  }

  close(): void {
    this.readyState = 2;
    this.closed = true;
  }

  emit(type: string, data?: unknown): void {
    const event = new Event(type);
    if (data !== undefined) Object.assign(event, { data: JSON.stringify(data) });
    for (const listener of this.listeners.get(type) ?? []) listener(event);
  }

  /** The browser's own connection error: a plain event without data. */
  fail(readyState: number): void {
    this.readyState = readyState;
    this.emit("error");
  }

  static last(): FakeSource {
    const source = FakeSource.instances.at(-1);
    if (!source) throw new Error("no event source was opened");
    return source;
  }
}

const factory = (url: string) => new FakeSource(url);

const SCAN = "11111111-1111-4111-8111-111111111111";
const JOB_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const JOB_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

function snapshot(state = "running"): ScanDetail {
  return { id: SCAN, state, jobs: [], artifacts: [] } as unknown as ScanDetail;
}

function run(actions: StreamAction[], from: StreamState = initialStreamState()): StreamState {
  return actions.reduce(streamReducer, from);
}

beforeEach(() => {
  FakeSource.instances = [];
});

afterEach(() => {
  vi.useRealTimers();
});

describe("streamReducer", () => {
  it("keeps the snapshot and counts changes", () => {
    const state = run([{ type: "snapshot", data: snapshot() }, { type: "state" }]);
    expect(state.snapshot?.state).toBe("running");
    expect(state.changes).toBe(2);
  });

  it("appends log lines with their tool and numbers them", () => {
    const state = run([
      { type: "log", data: { job_id: JOB_A, tool: "semgrep", lines: ["one", "two"] } },
      { type: "log", data: { job_id: JOB_B, tool: "gitleaks", lines: ["three"] } },
    ]);
    expect(state.lines.map((line) => [line.tool, line.text])).toEqual([
      ["semgrep", "one"],
      ["semgrep", "two"],
      ["gitleaks", "three"],
    ]);
    expect(new Set(state.lines.map((line) => line.id)).size).toBe(3);
  });

  it("replaces a job's lines with its backlog (sent again after a reconnect)", () => {
    const state = run([
      { type: "log", data: { job_id: JOB_A, tool: "semgrep", lines: ["a1", "a2"], backlog: true } },
      { type: "log", data: { job_id: JOB_B, tool: "gitleaks", lines: ["b1"], backlog: true } },
      { type: "log", data: { job_id: JOB_A, tool: "semgrep", lines: ["a1", "a2", "a3"], backlog: true } },
    ]);
    expect(state.lines.filter((line) => line.jobId === JOB_A).map((line) => line.text)).toEqual(["a1", "a2", "a3"]);
    expect(state.lines.filter((line) => line.jobId === JOB_B)).toHaveLength(1);
  });

  it("ignores log events without lines and non-text lines", () => {
    const empty = run([{ type: "log", data: { job_id: JOB_A, tool: "x", lines: [] } }]);
    expect(empty.lines).toEqual([]);
    const mixed = run([{ type: "log", data: { job_id: JOB_A, tool: "x", lines: ["ok", 5, null] } }]);
    expect(mixed.lines.map((line) => line.text)).toEqual(["ok"]);
  });

  it("keeps only the newest lines", () => {
    const lines = Array.from({ length: MAX_LOG_LINES + 10 }, (_, index) => `line ${String(index)}`);
    const state = run([{ type: "log", data: { job_id: JOB_A, tool: "x", lines } }]);
    expect(state.lines).toHaveLength(MAX_LOG_LINES);
    expect(state.lines[0]?.text).toBe("line 10");
    expect(state.lines.at(-1)?.text).toBe(`line ${String(MAX_LOG_LINES + 9)}`);
  });

  it("tracks the connection", () => {
    expect(run([{ type: "connecting" }]).connection).toBe("connecting");
    expect(run([{ type: "connecting" }, { type: "open" }]).connection).toBe("open");
    const interrupted = run([{ type: "open" }, { type: "interrupted", closed: false }, { type: "connecting" }]);
    expect(interrupted.connection).toBe("reconnecting");
    expect(interrupted.reconnects).toBe(1);
    expect(run([{ type: "done", state: "completed" }]).connection).toBe("closed");
  });
});

describe("useScanEvents", () => {
  it("opens the event stream of the scan and shows it as open", () => {
    const { result } = renderHook(() => useScanEvents(SCAN, { factory }));
    expect(FakeSource.instances).toHaveLength(1);
    expect(FakeSource.last().url).toBe(`/api/v1/scans/${SCAN}/events`);
    expect(result.current.connection).toBe("connecting");
    act(() => FakeSource.last().emit("open"));
    expect(result.current.connection).toBe("open");
  });

  it("collects the snapshot and log lines", () => {
    const { result } = renderHook(() => useScanEvents(SCAN, { factory }));
    act(() => {
      const source = FakeSource.last();
      source.emit("snapshot", snapshot());
      source.emit("log", { scan_id: SCAN, job_id: JOB_A, tool: "semgrep", lines: ["scanning"], backlog: true });
      source.emit("log", { scan_id: SCAN, job_id: JOB_A, tool: "semgrep", lines: ["found 3"] });
      source.emit("state", { event: "state", state: "completed" });
    });
    expect(result.current.snapshot?.id).toBe(SCAN);
    expect(result.current.lines.map((line) => line.text)).toEqual(["scanning", "found 3"]);
    expect(result.current.changes).toBe(2);
  });

  it("closes the stream when the server says done", () => {
    const { result } = renderHook(() => useScanEvents(SCAN, { factory }));
    act(() => FakeSource.last().emit("done", { scan_id: SCAN, state: "completed" }));
    expect(result.current.done).toBe(true);
    expect(result.current.doneState).toBe("completed");
    expect(result.current.connection).toBe("closed");
    expect(FakeSource.last().closed).toBe(true);
  });

  it("lets the browser reconnect while the connection is only interrupted", () => {
    vi.useFakeTimers();
    const { result } = renderHook(() => useScanEvents(SCAN, { factory, baseBackoffMs: 1000 }));
    act(() => FakeSource.last().emit("open"));
    act(() => FakeSource.last().fail(0)); // CONNECTING: the browser retries by itself
    expect(result.current.connection).toBe("reconnecting");
    act(() => {
      vi.advanceTimersByTime(60_000);
    });
    expect(FakeSource.instances).toHaveLength(1);
  });

  it("opens a new stream after a growing delay when the browser gave up", () => {
    vi.useFakeTimers();
    const { result } = renderHook(() => useScanEvents(SCAN, { factory, baseBackoffMs: 1000, maxBackoffMs: 4000 }));
    act(() => FakeSource.last().fail(2)); // CLOSED
    expect(result.current.connection).toBe("reconnecting");
    expect(FakeSource.instances).toHaveLength(1);
    act(() => {
      vi.advanceTimersByTime(999);
    });
    expect(FakeSource.instances).toHaveLength(1);
    act(() => {
      vi.advanceTimersByTime(1);
    });
    expect(FakeSource.instances).toHaveLength(2);
    act(() => FakeSource.last().fail(2)); // fails again without ever opening: wait twice as long
    act(() => {
      vi.advanceTimersByTime(1999);
    });
    expect(FakeSource.instances).toHaveLength(2);
    act(() => {
      vi.advanceTimersByTime(1);
    });
    expect(FakeSource.instances).toHaveLength(3);
    // the second stream's backlog replaces the lines it sent before
    act(() => {
      const source = FakeSource.last();
      source.emit("open");
      source.emit("log", { job_id: JOB_A, tool: "semgrep", lines: ["a", "b"], backlog: true });
    });
    act(() => FakeSource.last().fail(2));
    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(FakeSource.instances).toHaveLength(4);
    act(() => FakeSource.last().emit("log", { job_id: JOB_A, tool: "semgrep", lines: ["a", "b", "c"], backlog: true }));
    expect(result.current.lines.map((line) => line.text)).toEqual(["a", "b", "c"]);
  });

  it("shows an error event from the server and does not reconnect", () => {
    vi.useFakeTimers();
    const { result } = renderHook(() => useScanEvents(SCAN, { factory }));
    act(() => FakeSource.last().emit("error", { detail: "Scan not found" }));
    expect(result.current.serverError).toBe("Scan not found");
    expect(FakeSource.last().closed).toBe(true);
    act(() => {
      vi.advanceTimersByTime(60_000);
    });
    expect(FakeSource.instances).toHaveLength(1);
  });

  it("does not reconnect after done even if the closed stream reports an error", () => {
    vi.useFakeTimers();
    renderHook(() => useScanEvents(SCAN, { factory }));
    act(() => FakeSource.last().emit("done", { state: "failed" }));
    act(() => FakeSource.last().fail(2));
    act(() => {
      vi.advanceTimersByTime(60_000);
    });
    expect(FakeSource.instances).toHaveLength(1);
  });

  it("closes the stream when the page goes away", () => {
    const { unmount } = renderHook(() => useScanEvents(SCAN, { factory }));
    const source = FakeSource.last();
    unmount();
    expect(source.closed).toBe(true);
  });

  it("does nothing without a scan or when disabled", () => {
    renderHook(() => useScanEvents(undefined, { factory }));
    renderHook(() => useScanEvents(SCAN, { factory, enabled: false }));
    expect(FakeSource.instances).toHaveLength(0);
  });
});
