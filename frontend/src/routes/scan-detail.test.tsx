import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { apiFetch, ApiError, type ApiInit } from "../api/client";
import type { EventSourceLike } from "../lib/sse";
import { ScanDetailView } from "./scan-detail";

vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return { ...actual, apiFetch: vi.fn() };
});

class FakeSource implements EventSourceLike {
  static instances: FakeSource[] = [];
  readyState = 1;
  private listeners = new Map<string, ((event: Event) => void)[]>();
  constructor(readonly url: string) {
    FakeSource.instances.push(this);
  }
  addEventListener(type: string, listener: (event: Event) => void): void {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]);
  }
  close(): void {
    this.readyState = 2;
  }
  emit(type: string, data?: unknown): void {
    const event = new Event(type);
    if (data !== undefined) Object.assign(event, { data: JSON.stringify(data) });
    for (const listener of this.listeners.get(type) ?? []) listener(event);
  }
}
const factory = (url: string) => new FakeSource(url);

const page = <T,>(items: T[]) => ({ items, next_cursor: null });

const job = (id: string, tool: string, patch: Record<string, unknown> = {}) => ({
  id,
  tool,
  state: "running",
  import_state: "pending",
  attempts: 1,
  exit_code: null,
  outcome_reason: null,
  partial: false,
  counts: {},
  image: `example/${tool}:1`,
  image_digest: "sha256:" + "ab".repeat(32),
  tool_version: "1.2.3",
  content_versions: { semgrep_rules: "2026-10-05" },
  applied_exclusions: [],
  coverage_note: null,
  dd_test_id: null,
  created_at: "2026-10-07T10:00:00Z",
  started_at: "2026-10-07T10:00:05Z",
  finished_at: null,
  ...patch,
});

function scan(patch: Record<string, unknown> = {}) {
  return {
    id: "scan-1",
    application_id: "app-1",
    version_id: "ver-1",
    target_id: "t1",
    profile_name: "code-standard",
    profile_version: 1,
    kind: "sast",
    mode: null,
    trigger: "user",
    trigger_detail: null,
    state: "running",
    verdict: "pending",
    started_by_id: null,
    requested_tools: ["semgrep", "gitleaks"],
    commit_sha: null,
    source_ref: null,
    counts: {},
    coverage_notes: [],
    error: null,
    created_at: "2026-10-07T10:00:00Z",
    started_at: "2026-10-07T10:00:05Z",
    finished_at: null,
    cancel_requested_at: null,
    jobs: [job("job-1", "semgrep"), job("job-2", "gitleaks", { state: "queued", started_at: null })],
    artifacts: [],
    replayed: false,
    collapsed: false,
    ...patch,
  };
}

type Handler = (init: ApiInit) => unknown;

function install(detail: unknown, overrides: Record<string, Handler> = {}) {
  const calls: { key: string; init: ApiInit }[] = [];
  const handlers: Record<string, Handler> = {
    "GET /me": () => ({
      id: "u1",
      name: "Ana",
      email: "ana@example.com",
      role: "Analyst",
      roles: ["Analyst"],
      csrf_token: "t",
      last_login: null,
      defectdojo_url: "https://dojo.example.com/",
    }),
    "GET /scans/scan-1": () => detail,
    "GET /applications": () =>
      page([{ id: "app-1", name: "Payroll", type: "internal", hosting: null, dd_product_id: 42 }]),
    "GET /versions/ver-1": () => ({ id: "ver-1", application_id: "app-1", label: "1.4.2" }),
    "GET /reports": () => page([]),
    ...overrides,
  };
  vi.mocked(apiFetch).mockImplementation(((path: string, init: ApiInit = {}) => {
    const key = `${(init.method ?? "GET").toUpperCase()} ${path}`;
    calls.push({ key, init });
    const handler = handlers[key];
    if (!handler) return Promise.reject(new Error(`unexpected call ${key}`));
    try {
      return Promise.resolve(handler(init));
    } catch (error) {
      return Promise.reject(error instanceof Error ? error : new Error(String(error)));
    }
  }) as unknown as typeof apiFetch);
  return calls;
}

function renderView() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  return render(
    <QueryClientProvider client={client}>
      <ScanDetailView scanId="scan-1" eventSourceFactory={factory} />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  FakeSource.instances = [];
});

describe("ScanDetailView", () => {
  it("shows the application, the state of every tool and the versions", async () => {
    install(scan());
    renderView();
    expect(await screen.findByRole("heading", { name: "Payroll" })).toBeInTheDocument();
    expect(await screen.findByText(/Version 1\.4\.2/)).toBeInTheDocument();
    const table = screen.getByRole("table", { name: "Status of each tool" });
    const semgrep = within(table).getByText("Semgrep").closest("tr");
    expect(semgrep).not.toBeNull();
    expect(within(semgrep as HTMLElement).getByText("Running")).toBeInTheDocument();
    expect(within(semgrep as HTMLElement).getByText(/1\.2\.3/)).toBeInTheDocument();
    expect(within(semgrep as HTMLElement).getByText(/Semgrep rules 2026-10-05/)).toBeInTheDocument();
    const gitleaks = within(table).getByText("Gitleaks").closest("tr");
    expect(within(gitleaks as HTMLElement).getByText("Queued")).toBeInTheDocument();
    expect(await screen.findByRole("link", { name: "Open in DefectDojo" })).toHaveAttribute(
      "href",
      "https://dojo.example.com/product/42",
    );
  });

  it("shows live log lines of the stream, with the tool in front", async () => {
    install(scan());
    renderView();
    await screen.findByRole("heading", { name: "Payroll" });
    expect(FakeSource.instances[0]?.url).toBe("/api/v1/scans/scan-1/events");
    act(() => {
      const source = FakeSource.instances[0];
      source?.emit("open");
      source?.emit("log", { job_id: "job-1", tool: "semgrep", lines: ["Scanning 120 files"], backlog: true });
      source?.emit("log", { job_id: "job-1", tool: "semgrep", lines: ["Found 4 findings"] });
    });
    const log = screen.getByRole("log", { name: "Scan log" });
    expect(log).toHaveTextContent("[semgrep] Scanning 120 files");
    expect(log).toHaveTextContent("[semgrep] Found 4 findings");
    expect(screen.getByTestId("log-connection")).toHaveTextContent("Live");
  });

  it("can show the log of one tool only", async () => {
    install(scan());
    const user = userEvent.setup();
    renderView();
    await screen.findByRole("heading", { name: "Payroll" });
    act(() => {
      const source = FakeSource.instances[0];
      source?.emit("log", { job_id: "job-1", tool: "semgrep", lines: ["from semgrep"] });
      source?.emit("log", { job_id: "job-2", tool: "gitleaks", lines: ["from gitleaks"] });
    });
    await user.selectOptions(screen.getByLabelText("Show the log of"), "job-2");
    const log = screen.getByRole("log", { name: "Scan log" });
    expect(log).toHaveTextContent("from gitleaks");
    expect(log).not.toHaveTextContent("from semgrep");
  });

  it("cancels after a second click", async () => {
    const calls = install(scan(), {
      "POST /scans/scan-1/cancel": () => scan({ state: "cancelled", cancel_requested_at: "2026-10-07T10:05:00Z" }),
    });
    const user = userEvent.setup();
    renderView();
    await user.click(await screen.findByRole("button", { name: "Cancel scan" }));
    expect(calls.some((call) => call.key === "POST /scans/scan-1/cancel")).toBe(false);
    await user.click(screen.getByRole("button", { name: "Yes, cancel the scan" }));
    expect(await screen.findByText("Cancelled")).toBeInTheDocument();
    expect(calls.some((call) => call.key === "POST /scans/scan-1/cancel")).toBe(true);
    expect(screen.queryByRole("button", { name: "Cancel scan" })).not.toBeInTheDocument();
  });

  it("shows the result of a finished scan: counts, verdict, import state and the report", async () => {
    install(
      scan({
        state: "completed",
        verdict: "fail",
        finished_at: "2026-10-07T10:09:00Z",
        counts: { critical: 1, high: 3, medium: 0, low: 2, info: 0, total: 6 },
        jobs: [
          job("job-1", "semgrep", { state: "completed", import_state: "imported", counts: { high: 3, total: 3 }, exit_code: 0, dd_test_id: 7 }),
          job("job-2", "gitleaks", { state: "completed", import_state: "imported", counts: { critical: 1, low: 2, total: 3 }, exit_code: 0 }),
        ],
      }),
      {
        "GET /reports": () =>
          page([
            {
              id: "rep-9",
              scan_id: "scan-1",
              status: "ready",
              review_state: "reviewed",
              title: "Payroll 1.4.2 report",
              ref: "SS-1",
              created_at: "2026-10-07T10:10:00Z",
            },
          ]),
      },
    );
    renderView();
    const counts = await screen.findByTestId("severity-counts");
    expect(counts).toHaveTextContent("Critical1");
    expect(counts).toHaveTextContent("High3");
    expect(counts).toHaveTextContent("Total 6");
    expect(screen.getByText("Complete")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Payroll 1.4.2 report" })).toHaveAttribute("href", "/reports/rep-9");
    expect(screen.getByRole("link", { name: "Open the report" })).toHaveAttribute("href", "/reports/rep-9");
    expect(await screen.findByRole("link", { name: "Semgrep results in DefectDojo" })).toHaveAttribute(
      "href",
      "https://dojo.example.com/test/7",
    );
    expect(screen.queryByRole("button", { name: "Cancel scan" })).not.toBeInTheDocument();
  });

  it("says when the scan does not exist", async () => {
    install(null, {
      "GET /scans/scan-1": () => {
        throw new ApiError(404, { title: "Not Found", detail: "Scan not found" });
      },
    });
    renderView();
    expect((await screen.findAllByText("Scan not found")).length).toBeGreaterThan(0);
  });
});
