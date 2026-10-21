import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";

import { apiFetch, type ApiInit } from "../api/client";
import type { FeedHealth, ImageVersion, ToolHealth } from "../api/operations";
import { ContentPage } from "./settings/content";
import { approvalRule, ImagesPage } from "./settings/images";
import { digestDiffers, feedStatus, ScannerHealthPage } from "./settings/scanner-health";
import { DeltaView, vendorCopyAvailable, VendorAssessmentsPage } from "./vendor-assessments";

vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return { ...actual, apiFetch: vi.fn() };
});

const page = <T,>(items: T[]) => ({ items, next_cursor: null });

type Handler = (init: ApiInit) => unknown;

function install(handlers: Record<string, Handler>) {
  const calls: { key: string; init: ApiInit }[] = [];
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

function renderPage(ui: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

const feed = (changes: Partial<FeedHealth> = {}): FeedHealth => ({
  feed: "grype_db",
  label: "Grype vulnerability database",
  tool: "syft-grype",
  version: "v6.1.0",
  path: null,
  source_commit: null,
  built_at: null,
  fetched_at: null,
  activated_at: null,
  age_seconds: 3600,
  limit_days: 7,
  stale: false,
  regression_result: "passed",
  update_failed: false,
  ...changes,
});

const tool = (changes: Partial<ToolHealth> = {}): ToolHealth => ({
  tool: "semgrep",
  role: "scanner",
  description: "Static analysis",
  image: "docker.io/semgrep/semgrep",
  tag: "1.0",
  digest: "sha256:" + "a".repeat(64),
  digest_source: "lock file",
  last_job_digest: null,
  approved_image: null,
  max_parallel: 2,
  last_success_at: null,
  last_failure_at: null,
  feed: null,
  ...changes,
});

const image = (changes: Partial<ImageVersion> = {}): ImageVersion => ({
  id: "img-1",
  tool: "gitleaks",
  image: "docker.io/zricethezav/gitleaks",
  tag: "8.30.0",
  digest: "sha256:" + "b".repeat(64),
  source: "proposal",
  state: "pending",
  scope: null,
  reason: "newer tag",
  previous_tag: "8.29.0",
  previous_digest: "sha256:" + "c".repeat(64),
  regression_result: "passed",
  regression_detail: {},
  active: false,
  proposed_at: "2026-10-01T00:00:00Z",
  approved_by_id: null,
  approved_at: null,
  notes: null,
  lock_line: "x",
  ...changes,
});

describe("scanner health helpers", () => {
  it("ranks a failed update above stale data", () => {
    expect(feedStatus(feed({ stale: true, update_failed: true })).label).toBe("Update failed");
    expect(feedStatus(feed({ stale: true })).label).toBe("Too old");
    expect(feedStatus(feed({ version: null })).label).toBe("Not loaded yet");
    expect(feedStatus(feed()).label).toBe("Current");
  });

  it("notices a last job that ran another digest", () => {
    expect(digestDiffers(tool({ last_job_digest: "sha256:" + "d".repeat(64) }))).toBe(true);
    expect(digestDiffers(tool())).toBe(false);
  });
});

describe("ScannerHealthPage", () => {
  it("lists the feeds and the scanners", async () => {
    install({
      "GET /scanner-health": () => ({
        status: "attention",
        generated_at: "2026-10-08T00:00:00Z",
        tools: [tool()],
        feeds: [feed({ stale: true })],
        notes: ["The Grype database is older than 7 days."],
      }),
    });
    renderPage(<ScannerHealthPage />);
    expect(await screen.findByText("Needs attention")).toBeInTheDocument();
    expect(screen.getByText("Too old")).toBeInTheDocument();
    expect(screen.getByText(/older than 7 days/)).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Scanners" })).toHaveTextContent("semgrep");
  });
});

describe("ContentPage", () => {
  it("starts an update and offers only the feeds that are still updated", async () => {
    const calls = install({
      "GET /content-versions": () => page([]),
      "POST /content-versions/updates": () => ({ feed: "grype_db", queued: true, message: "The update was queued." }),
    });
    const user = userEvent.setup();
    renderPage(<ContentPage />);
    await user.click(await screen.findByRole("button", { name: "Update Grype vulnerability database" }));
    expect(await screen.findByText("The update was queued.")).toBeInTheDocument();
    expect(calls.find((c) => c.key === "POST /content-versions/updates")?.init.body).toEqual({ feed: "grype_db" });
    expect(screen.getAllByRole("button", { name: /^Update / })).toHaveLength(3);
    expect(screen.queryByText(/NVD/)).not.toBeInTheDocument();
  });
});

describe("approvalRule", () => {
  it("approves a passed run, asks for a hand test after a skipped run and blocks the rest", () => {
    expect(approvalRule(image({ regression_result: "passed" }))).toBe("ok");
    expect(approvalRule(image({ regression_result: "skipped" }))).toBe("acknowledge");
    expect(approvalRule(image({ regression_result: "failed" }))).toBe("blocked");
    expect(approvalRule(image({ regression_result: "testing" }))).toBe("blocked");
  });
});

describe("ImagesPage", () => {
  it("approves a proposal whose regression run passed", async () => {
    const calls = install({
      "GET /image-versions": () => page([image()]),
      "POST /image-versions/img-1/approve": () => image({ state: "active", active: true }),
    });
    const user = userEvent.setup();
    renderPage(<ImagesPage />);
    await user.click(await screen.findByRole("button", { name: /Approve gitleaks/ }));
    await waitFor(() => expect(calls.some((c) => c.key === "POST /image-versions/img-1/approve")).toBe(true));
    expect(calls.find((c) => c.key === "POST /image-versions/img-1/approve")?.init.body).toEqual({
      acknowledge_skipped: false,
    });
  });

  it("keeps Approve disabled for a failed run and until a skipped run is acknowledged", async () => {
    install({
      "GET /image-versions": () =>
        page([
          image({ id: "img-f", tool: "failedtool", regression_result: "failed" }),
          image({ id: "img-s", tool: "skippedtool", regression_result: "skipped" }),
        ]),
    });
    const user = userEvent.setup();
    renderPage(<ImagesPage />);
    expect(await screen.findByRole("button", { name: /Approve failedtool/ })).toBeDisabled();
    const approveSkipped = screen.getByRole("button", { name: /Approve skippedtool/ });
    expect(approveSkipped).toBeDisabled();
    await user.click(screen.getByRole("checkbox", { name: /I tested skippedtool/ }));
    expect(approveSkipped).toBeEnabled();
  });
});

describe("vendor assessments", () => {
  it("offers the vendor copy only for a reviewed, ready report", () => {
    const base = { status: "ready", review_state: "reviewed" } as never;
    expect(vendorCopyAvailable(base)).toBe(true);
    expect(vendorCopyAvailable({ status: "ready", review_state: "automatic" } as never)).toBe(false);
    expect(vendorCopyAvailable({ status: "pending", review_state: "reviewed" } as never)).toBe(false);
  });

  it("shows the counts and the fixed findings of a delta", () => {
    render(
      <DeltaView
        delta={{
          application_id: "a",
          scan_id: "s2",
          previous_scan_id: "s1",
          version_id: "v2",
          previous_version_id: "v1",
          counts: { fixed: 1, remaining: 2, new: 0, reopened: 0 },
          fixed: [
            {
              key: "k1",
              severity: "high",
              title: "SQL injection",
              tool: "semgrep",
              location: "src/Dao.java:10",
              state: "fixed",
              previous_state: "active",
              hash_code: "h",
              occurrences: 1,
            },
          ],
          remaining: [],
          new: [],
          reopened: [],
          triaged: [],
          compared_tools: ["semgrep"],
          skipped_tools: ["sonarqube"],
          notes: [],
          truncated: false,
        }}
      />,
    );
    expect(screen.getByText(/Fixed 1, remaining 2, new 0/)).toBeInTheDocument();
    expect(screen.getByText("SQL injection")).toBeInTheDocument();
    expect(screen.getByText(/Not compared.*sonarqube/)).toBeInTheDocument();
  });

  it("registers a product and lists the assessments", async () => {
    const calls = install({
      "GET /vendor-assessments": () =>
        page([
          {
            id: "rep-1",
            application_id: "app-1",
            version_id: "ver-1",
            scan_id: "scan-1",
            ref: null,
            title: null,
            status: "ready",
            review_state: "reviewed",
            proposed_verdict: "conditional",
            verdict: "conditional",
            vendor_copy: true,
            created_at: "2026-10-01T00:00:00Z",
            html_ready: true,
            pdf_ready: true,
            vendor_id: "v1",
            vendor_name: "Acme",
            product: "Ledger",
            hosting: "deployable",
            version_label: "2.0",
          },
        ]),
      "POST /vendor-assessments/intake": () => ({
        vendor: { id: "v1", name: "Acme" },
        application: { id: "app-1", name: "Ledger" },
        version: { id: "ver-1", label: "2.0" },
        vendor_created: true,
        application_created: true,
        version_created: true,
        next_steps: ["Add the repository as a target."],
      }),
    });
    const user = userEvent.setup();
    renderPage(<VendorAssessmentsPage />);
    expect(await screen.findByText("Vendor copy (PDF)")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Vendor copy of Ledger as HTML" }).getAttribute("href")).toContain(
      "copy=vendor",
    );
    await user.type(screen.getByLabelText("Vendor"), "Acme");
    await user.type(screen.getByLabelText("Product"), "Ledger");
    await user.type(screen.getByLabelText("Version"), "2.0");
    await user.click(screen.getByRole("button", { name: "Register" }));
    expect(await screen.findByText("Add the repository as a target.")).toBeInTheDocument();
    expect(calls.find((c) => c.key === "POST /vendor-assessments/intake")?.init.body).toMatchObject({
      vendor_name: "Acme",
      product: "Ledger",
      version: "2.0",
      hosting: "deployable",
    });
  });
});
