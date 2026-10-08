import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";

import { apiFetch, ApiError, type ApiInit } from "../api/client";
import { DastPage } from "./dast";

vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return { ...actual, apiFetch: vi.fn() };
});

const page = <T,>(items: T[]) => ({ items, next_cursor: null });

const target = (id: string, locator: string, environment: "production" | "uat") => ({
  id,
  version_id: "ver-1",
  kind: "url",
  name: null,
  locator,
  environment,
  credential_id: null,
  login_profile_id: null,
  upload_artifact_id: null,
  scope_includes: [],
  scope_excludes: [],
  api_spec_type: null,
  api_spec_locator: null,
  rate_limit_rps: null,
  blackout_windows: [],
  dast_cron: null,
  host_approved: false,
  vendor_authorization_artifact_id: null,
  vendor_authorized_until: null,
  archived_at: null,
});

const profile = (mode: string) => ({
  id: `p-${mode}`,
  name: `dast-${mode}`,
  version: 1,
  kind: "dast",
  mode,
  description: null,
  tools: ["zap"],
  active: true,
  sha256: "x",
  created_at: "2026-10-01T00:00:00Z",
});

type Handler = (init: ApiInit) => unknown;

function install(overrides: Record<string, Handler> = {}) {
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
      defectdojo_url: "https://dojo.example.com",
    }),
    "GET /applications": () =>
      page([{ id: "app-1", name: "Shop", type: "internal", hosting: null, vendor_id: null, vendor_product: null }]),
    "GET /vendors": () => page([]),
    "GET /targets": () =>
      page([target("t-prod", "https://shop.example.com", "production"), target("t-uat", "https://uat.shop.example.com", "uat")]),
    "GET /versions/ver-1": () => ({ id: "ver-1", application_id: "app-1", label: "2.4.0" }),
    "GET /profiles": () => page(["baseline", "full", "api", "nuclei"].map(profile)),
    "GET /scans": () => page([]),
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

function renderPage(ui: ReactNode = <DastPage />) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

async function chooseTarget(user: ReturnType<typeof userEvent.setup>, id: string) {
  const select = await screen.findByLabelText("Web address");
  await waitFor(() => expect(within(select).getAllByRole("option").length).toBeGreaterThan(2));
  await user.selectOptions(select, id);
}

describe("DastPage scan form", () => {
  it("offers only the baseline for a production address", async () => {
    install();
    const user = userEvent.setup();
    renderPage();
    await chooseTarget(user, "t-prod");
    expect(await screen.findByLabelText(/Baseline/)).toBeInTheDocument();
    expect(screen.queryByLabelText(/Full active scan/)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/API scan/)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/Nuclei/)).not.toBeInTheDocument();
    expect(screen.getByText(/accept the unauthenticated baseline scan only/)).toBeInTheDocument();
  });

  it("offers baseline, full, API and Nuclei for a UAT address", async () => {
    install();
    const user = userEvent.setup();
    renderPage();
    await chooseTarget(user, "t-uat");
    for (const name of [/Baseline/, /Full active scan/, /API scan/, /Nuclei/]) {
      expect(await screen.findByLabelText(name)).toBeEnabled();
    }
  });

  it("drops a chosen mode when the next address does not allow it", async () => {
    install();
    const user = userEvent.setup();
    renderPage();
    await chooseTarget(user, "t-uat");
    await user.click(await screen.findByLabelText(/Full active scan/));
    const start = screen.getByRole("button", { name: "Start scan" });
    expect(start).toBeEnabled();
    await user.selectOptions(screen.getByLabelText("Web address"), "t-prod");
    expect(screen.getByRole("button", { name: "Start scan" })).toBeDisabled();
  });

  it("keeps the start button disabled until a mode is chosen", async () => {
    install();
    const user = userEvent.setup();
    renderPage();
    await chooseTarget(user, "t-uat");
    expect(screen.getByRole("button", { name: "Start scan" })).toBeDisabled();
    await user.click(await screen.findByLabelText(/Baseline/));
    expect(screen.getByRole("button", { name: "Start scan" })).toBeEnabled();
  });

  it("shows the refusal of the API as it was written", async () => {
    const refusal = "Production targets accept the unauthenticated ZAP baseline scan only. Full scans, API scans and Nuclei run on UAT targets.";
    const calls = install({
      "POST /scans": () => {
        throw new ApiError(422, { title: "Unprocessable Entity", detail: refusal, code: "dast.production_baseline_only" });
      },
    });
    const user = userEvent.setup();
    renderPage();
    await chooseTarget(user, "t-uat");
    await user.click(await screen.findByLabelText(/Full active scan/));
    await user.click(screen.getByRole("button", { name: "Start scan" }));
    expect(await screen.findByTestId("problem-detail")).toHaveTextContent(refusal);
    const post = calls.find((call) => call.key === "POST /scans");
    expect(post?.init.body).toEqual({ version_id: "ver-1", target_id: "t-uat", profile: "dast-full" });
    expect(post?.init.headers?.["Idempotency-Key"]).toBeTruthy();
  });

  it("disables a mode whose scan profile is not installed", async () => {
    install({ "GET /profiles": () => page([profile("baseline")]) });
    const user = userEvent.setup();
    renderPage();
    await chooseTarget(user, "t-uat");
    expect(await screen.findByLabelText(/Baseline/)).toBeEnabled();
    expect(screen.getByLabelText(/Full active scan/)).toBeDisabled();
  });

  it("asks for a tag when the address has none", async () => {
    install({ "GET /targets": () => page([{ ...target("t-none", "https://x.example.com", "uat"), environment: null }]) });
    const user = userEvent.setup();
    renderPage();
    await chooseTarget(user, "t-none");
    expect(await screen.findByText(/no environment tag/)).toBeInTheDocument();
  });
});

describe("DastPage target form", () => {
  it("allows a login profile only once the address is tagged UAT", async () => {
    install();
    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByRole("button", { name: "Register a web address" }));
    const login = await screen.findByLabelText("Login profile (UAT only)");
    expect(login).toBeDisabled();
    await user.selectOptions(screen.getByLabelText("Environment tag"), "production");
    expect(login).toBeDisabled();
    await user.selectOptions(screen.getByLabelText("Environment tag"), "uat");
    expect(login).toBeEnabled();
  });

  it("explains what is missing before sending anything", async () => {
    const calls = install();
    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByRole("button", { name: "Register a web address" }));
    await user.click(await screen.findByRole("button", { name: "Register address" }));
    expect(await screen.findByText(/Enter the address to scan/)).toBeInTheDocument();
    expect(screen.getByText(/Tag the target as production or UAT/)).toBeInTheDocument();
    expect(screen.getByText(/Enter the application name/)).toBeInTheDocument();
    expect(calls.some((call) => call.key.startsWith("POST"))).toBe(false);
  });

  it("asks for the vendor's authorization when the application is a SaaS product", async () => {
    install();
    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByRole("button", { name: "Register a web address" }));
    expect(screen.queryByText("Vendor authorization (SaaS product)")).not.toBeInTheDocument();
    await user.click(await screen.findByLabelText(/Vendor \(a supplier develops it\)/));
    await user.click(screen.getByLabelText(/SaaS \(the vendor hosts it\)/));
    expect(await screen.findByText("Vendor authorization (SaaS product)")).toBeInTheDocument();
    expect(screen.getByLabelText("Authorization document")).toBeInTheDocument();
    expect(screen.getByLabelText("Vendor contact")).toBeInTheDocument();
  });
});
