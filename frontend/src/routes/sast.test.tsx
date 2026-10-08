import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { apiFetch, type ApiInit } from "../api/client";
import { SastPage } from "./sast";

vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return { ...actual, apiFetch: vi.fn() };
});

const page = <T,>(items: T[]) => ({ items, next_cursor: null });

function install(overrides: Record<string, () => unknown> = {}) {
  const calls: string[] = [];
  const handlers: Record<string, () => unknown> = {
    "GET /applications": () =>
      page([
        { id: "app-1", name: "Payroll", type: "internal", hosting: null },
        { id: "app-2", name: "Acme CRM", type: "vendor", hosting: "saas", vendor_product: "CRM" },
      ]),
    "GET /vendors": () => page([{ id: "ven-1", name: "Acme" }]),
    "GET /profiles": () =>
      page([
        {
          id: "p1",
          name: "code-standard",
          version: 1,
          kind: "sast",
          mode: null,
          description: null,
          tools: ["semgrep", "gitleaks"],
          active: true,
          sha256: "x",
          created_at: "2026-10-01T00:00:00Z",
        },
      ]),
    "GET /scans": () => page([]),
    "GET /reports": () => page([]),
    "GET /integrations/github/repositories": () =>
      page([
        { application_id: "app-1", github_repo_id: 11, full_name: "sona/payroll", default_branch: "main", removed: false, archived: false },
      ]),
    "GET /versions/ver-1": () => ({ id: "ver-1", label: "main" }),
    ...overrides,
  };
  vi.mocked(apiFetch).mockImplementation(((path: string, init: ApiInit = {}) => {
    const key = `${(init.method ?? "GET").toUpperCase()} ${path}`;
    calls.push(key);
    const handler = handlers[key];
    return handler ? Promise.resolve(handler()) : Promise.reject(new Error(`unexpected call ${key}`));
  }) as unknown as typeof apiFetch);
  return calls;
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  return render(
    <QueryClientProvider client={client}>
      <SastPage />
    </QueryClientProvider>,
  );
}

describe("SastPage", () => {
  it("offers every tool of the profile, ticked", async () => {
    install();
    renderPage();
    expect(await screen.findByRole("checkbox", { name: "Semgrep" })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "Gitleaks" })).toBeChecked();
  });

  it("lets the person leave a tool out", async () => {
    install();
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("checkbox", { name: "Gitleaks" }));
    expect(screen.getByRole("checkbox", { name: "Gitleaks" })).not.toBeChecked();
    expect(screen.getByRole("checkbox", { name: "Semgrep" })).toBeChecked();
  });

  it("names what is missing and sends nothing", async () => {
    const calls = install();
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: "Start scan" }));
    expect(await screen.findByText("Enter the repository address.")).toBeInTheDocument();
    expect(screen.getByText("Enter the application name.")).toBeInTheDocument();
    expect(screen.getByText(/Enter a version label/)).toBeInTheDocument();
    expect(calls.some((call) => call.startsWith("POST"))).toBe(false);
  });

  it("shows the vendor access choices only for a vendor application", async () => {
    install();
    const user = userEvent.setup();
    renderPage();
    expect(await screen.findByText(/Internal repositories are read through the company's GitHub App/)).toBeInTheDocument();
    expect(screen.queryByText("Access to the vendor's repository")).not.toBeInTheDocument();

    await user.selectOptions(await screen.findByLabelText("Application"), "app-2");
    expect(await screen.findByText("Access to the vendor's repository")).toBeInTheDocument();
    expect(screen.getByLabelText("Generate a read-only deploy key")).toBeInTheDocument();
    expect(screen.queryByLabelText("Vendor token")).not.toBeInTheDocument();
    await user.click(screen.getByLabelText("Enter a token the vendor issued"));
    const token = screen.getByLabelText("Vendor token");
    expect(token).toHaveAttribute("type", "password");
    expect(screen.getByLabelText("Token expires on")).toBeInTheDocument();
  });

  it("asks for the vendor and the hosting of a new vendor application", async () => {
    install();
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByLabelText(/Vendor \(a supplier develops it\)/));
    expect(await screen.findByLabelText("Vendor")).toBeInTheDocument();
    expect(screen.getByLabelText(/Deployable/)).toBeInTheDocument();
    expect(screen.getByLabelText(/SaaS \(the vendor hosts it\)/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Start scan" }));
    expect(await screen.findByText("Choose the vendor or add a new one.")).toBeInTheDocument();
    expect(screen.getByText("Say whether the product is deployable or SaaS.")).toBeInTheDocument();
  });

  it("switches the source: zip upload and image reference", async () => {
    install();
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByLabelText("A zip file of the source code"));
    expect(screen.getByLabelText("Zip file")).toHaveAttribute("type", "file");
    await user.click(screen.getByLabelText("A Docker image"));
    expect(screen.getByLabelText("Image reference")).toBeInTheDocument();
    await user.click(screen.getByLabelText("An image file (docker save, .tar)"));
    expect(screen.getByLabelText("Image file")).toHaveAttribute("type", "file");
  });

  it("fixes the application to the one of a connected repository", async () => {
    install();
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByLabelText("A connected GitHub repository"));
    const repository = await screen.findByLabelText("Repository");
    await screen.findByRole("option", { name: /sona\/payroll/ });
    await user.selectOptions(repository, "11");
    const application = await screen.findByLabelText("Application");
    expect(application).toHaveAttribute("readonly");
    expect(application).toHaveValue("Payroll");
    expect(screen.getByLabelText("Version label")).toHaveValue("main");
  });
});
