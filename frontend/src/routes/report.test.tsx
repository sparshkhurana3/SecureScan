import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { apiFetch, ApiError, type ApiInit } from "../api/client";
import { ReportView } from "./report";

vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return { ...actual, apiFetch: vi.fn() };
});

const baseReport = {
  id: "rep-1",
  application_id: "app-1",
  version_id: "ver-1",
  scan_id: "scan-1",
  kind: "application",
  ref: "SS-2026-0001",
  title: "Payroll 1.0 report",
  status: "ready",
  error: null,
  review_state: "automatic",
  proposed_verdict: "fail",
  verdict: "fail",
  verdict_overridden: false,
  override_reason: null,
  reviewer_id: null,
  reviewed_at: null,
  conditions: [],
  vendor_copy: false,
  internal_notes: null,
  previous_report_id: null,
  created_at: "2026-10-07T10:00:00Z",
  updated_at: "2026-10-07T10:00:00Z",
  html_ready: true,
  pdf_ready: true,
};

const snapshot = {
  findings: [
    { key: "k1", tool_label: "Semgrep", severity: "high", severity_label: "High", title: "SQL injection", location: "app.py:12" },
    { key: "k2", tool_label: "Gitleaks", severity: "critical", severity_label: "Critical", title: "Hard-coded secret", location: "config.py:3" },
  ],
};

type Handler = (init: ApiInit) => unknown;

function install(report: Record<string, unknown> = baseReport, overrides: Record<string, Handler> = {}) {
  const calls: { key: string; init: ApiInit }[] = [];
  const handlers: Record<string, Handler> = {
    "GET /reports/rep-1": () => report,
    "GET /reports/rep-1/snapshot": () => snapshot,
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

function renderReport() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  return render(
    <QueryClientProvider client={client}>
      <ReportView reportId="rep-1" />
    </QueryClientProvider>,
  );
}

describe("ReportView", () => {
  it("shows the report in a fully sandboxed frame and offers the PDF", async () => {
    install();
    renderReport();
    const frame = await screen.findByTitle("Report");
    expect(frame.tagName).toBe("IFRAME");
    expect(frame).toHaveAttribute("sandbox", "");
    expect(frame).toHaveAttribute("src", "/api/v1/reports/rep-1/html");
    expect(screen.getByRole("link", { name: "Download PDF" })).toHaveAttribute("href", "/api/v1/reports/rep-1/pdf");
    expect(screen.getByTestId("report-verdict")).toHaveTextContent("Fail");
  });

  it("says when the report is still being made and shows no frame", async () => {
    install({ ...baseReport, status: "pending", html_ready: false, pdf_ready: false });
    renderReport();
    expect(await screen.findByText(/The report is being made/)).toBeInTheDocument();
    expect(screen.queryByTitle("Report")).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Download PDF" })).not.toBeInTheDocument();
  });

  it("explains a failed report", async () => {
    install({ ...baseReport, status: "failed", error: "The template could not be rendered.", html_ready: false });
    renderReport();
    expect(await screen.findByText("The template could not be rendered.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try to make it again" })).toBeInTheDocument();
  });

  it("confirms the proposed verdict", async () => {
    const calls = install(baseReport, {
      "POST /reports/rep-1/review": () => ({ ...baseReport, review_state: "reviewed", reviewed_at: "2026-10-07T11:00:00Z" }),
    });
    const user = userEvent.setup();
    renderReport();
    expect(await screen.findByLabelText("Confirm the proposed verdict (Fail)")).toBeChecked();
    await user.click(screen.getByRole("button", { name: "Save the review" }));
    await waitFor(() => expect(calls.some((call) => call.key === "POST /reports/rep-1/review")).toBe(true));
    const body = calls.find((call) => call.key === "POST /reports/rep-1/review")?.init.body;
    expect(body).toEqual({ decision: "confirm", conditions: [], internal_notes: "" });
    expect(await screen.findByText(/Review saved/)).toBeInTheDocument();
  });

  it("cannot confirm when the policy proposed nothing", async () => {
    install({ ...baseReport, proposed_verdict: "pending", verdict: "pending" });
    renderReport();
    expect(await screen.findByLabelText("Confirm the proposed verdict")).toBeDisabled();
    expect(screen.getByLabelText("Set a verdict myself")).toBeChecked();
  });

  it("needs a verdict and a reason to override and sends nothing until they are given", async () => {
    const calls = install();
    const user = userEvent.setup();
    renderReport();
    await user.click(await screen.findByLabelText("Set a verdict myself"));
    await user.click(screen.getByRole("button", { name: "Save the review" }));
    expect(await screen.findByText("Choose pass, conditional pass or fail.")).toBeInTheDocument();
    expect(screen.getByText(/Overriding the verdict needs a reason/)).toBeInTheDocument();
    expect(calls.some((call) => call.key.startsWith("POST"))).toBe(false);
  });

  it("overrides with a reason and a condition per finding", async () => {
    const calls = install(baseReport, { "POST /reports/rep-1/review": () => ({ ...baseReport, review_state: "reviewed" }) });
    const user = userEvent.setup();
    renderReport();
    await user.click(await screen.findByLabelText("Set a verdict myself"));
    await user.selectOptions(screen.getByLabelText("Verdict"), "conditional");
    await user.type(screen.getByLabelText("Reason for the override"), "Vendor agreed to fix the injection");
    await waitFor(() => expect(screen.getByRole("button", { name: "Add a condition" })).toBeEnabled());
    await user.click(screen.getByRole("button", { name: "Add a condition" }));
    await screen.findByRole("option", { name: /SQL injection/ });
    await user.selectOptions(screen.getByLabelText("Finding of condition 1"), "k1");
    fireEvent.change(screen.getByLabelText("Deadline"), { target: { value: "2099-01-15" } });
    await user.click(screen.getByRole("button", { name: "Save the review" }));
    await waitFor(() => expect(calls.some((call) => call.key === "POST /reports/rep-1/review")).toBe(true));
    expect(calls.find((call) => call.key === "POST /reports/rep-1/review")?.init.body).toEqual({
      decision: "override",
      verdict: "conditional",
      reason: "Vendor agreed to fix the injection",
      conditions: [{ finding_hash: "k1", deadline: "2099-01-15" }],
      internal_notes: "",
    });
  });

  it("lists the most severe findings first and refuses a deadline in the past", async () => {
    const calls = install();
    const user = userEvent.setup();
    renderReport();
    await waitFor(() => expect(screen.getByRole("button", { name: "Add a condition" })).toBeEnabled());
    await user.click(screen.getByRole("button", { name: "Add a condition" }));
    const options = await screen.findAllByRole("option");
    const names = options.map((option) => option.textContent ?? "");
    expect(names.findIndex((name) => name.includes("Hard-coded secret"))).toBeLessThan(
      names.findIndex((name) => name.includes("SQL injection")),
    );
    await user.selectOptions(screen.getByLabelText("Finding of condition 1"), "k2");
    fireEvent.change(screen.getByLabelText("Deadline"), { target: { value: "2020-01-01" } });
    await user.click(screen.getByRole("button", { name: "Save the review" }));
    expect(await screen.findByText("The deadline is in the past.")).toBeInTheDocument();
    expect(calls.some((call) => call.key.startsWith("POST"))).toBe(false);
  });

  it("hides conditions for a passing verdict", async () => {
    install({ ...baseReport, proposed_verdict: "pass", verdict: "pass" });
    renderReport();
    expect(await screen.findByText("A passing verdict has no conditions.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add a condition" })).not.toBeInTheDocument();
  });

  it("shows the refusal of the API as it was written", async () => {
    const detail = "Overriding the verdict needs a reason";
    install(baseReport, {
      "POST /reports/rep-1/review": () => {
        throw new ApiError(422, {
          title: "Unprocessable Entity",
          detail,
          errors: [{ field: "conditions.0.deadline", message: "the deadline is in the past" }],
        });
      },
    });
    const user = userEvent.setup();
    renderReport();
    await user.click(await screen.findByRole("button", { name: "Save the review" }));
    expect(await screen.findByTestId("problem-detail")).toHaveTextContent(detail);
    expect(screen.getByText(/the deadline is in the past/)).toBeInTheDocument();
  });

  it("offers a vendor copy for a vendor report only", async () => {
    install({ ...baseReport, kind: "vendor" });
    renderReport();
    expect(await screen.findByRole("checkbox", { name: "Make a copy for the vendor" })).toBeInTheDocument();
  });
});
