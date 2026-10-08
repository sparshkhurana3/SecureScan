import { render, screen } from "@testing-library/react";
import { createMemoryHistory } from "@tanstack/react-router";

import { App, createQueryClient } from "./App";
import { createAppRouter } from "./router";
import { loginUrl } from "./routes/login";

function mockSignedOut() {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      () =>
        new Response(JSON.stringify({ title: "Unauthorized", status: 401 }), {
          status: 401,
          headers: { "content-type": "application/problem+json" },
        }),
    ),
  );
}

describe("App", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("sends a signed-out visitor to a login page with the wordmark, the name and one button", async () => {
    mockSignedOut();
    const router = createAppRouter({ history: createMemoryHistory({ initialEntries: ["/history"] }) });
    render(<App router={router} queryClient={createQueryClient()} />);

    const signIn = await screen.findByRole("link", { name: "Sign in with Microsoft" });
    expect(signIn).toHaveAttribute("href", "/api/v1/auth/login?next=%2Fhistory");
    expect(screen.getByAltText("SonaComstar")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "SecureScan" })).toBeInTheDocument();
    // Nothing else on the page.
    expect(screen.getAllByRole("link")).toHaveLength(1);
    expect(screen.queryAllByRole("button")).toHaveLength(0);
  });

  it("builds the login address from a safe return path only", () => {
    expect(loginUrl("/history?tab=findings")).toBe("/api/v1/auth/login?next=%2Fhistory%3Ftab%3Dfindings");
    expect(loginUrl("/")).toBe("/api/v1/auth/login");
    expect(loginUrl("https://evil.example/")).toBe("/api/v1/auth/login");
    expect(loginUrl("//evil.example/")).toBe("/api/v1/auth/login");
    expect(loginUrl(undefined)).toBe("/api/v1/auth/login");
  });
});
