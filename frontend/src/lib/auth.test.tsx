import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  RouterProvider,
} from "@tanstack/react-router";
import { render, screen } from "@testing-library/react";

import type { Me } from "../api/me";
import { AuthContext, type AuthValue, roleSatisfies, RequireRole } from "./auth";

function user(role: Me["role"]): Me {
  return {
    id: "u1",
    name: "Asha Rao",
    email: "asha@example.com",
    role,
    defectdojoUrl: "https://dojo.example.com",
    lastLogin: null,
  };
}

function renderAt(path: string, auth: Partial<AuthValue>) {
  const value: AuthValue = {
    user: null,
    isLoading: false,
    error: null,
    refetch: () => undefined,
    ...auth,
  };
  const rootRoute = createRootRoute({ component: () => <Outlet /> });
  const routeTree = rootRoute.addChildren([
    createRoute({ getParentRoute: () => rootRoute, path: "/", component: () => <p>Home page</p> }),
    createRoute({ getParentRoute: () => rootRoute, path: "/login", component: () => <p>Login page</p> }),
    createRoute({
      getParentRoute: () => rootRoute,
      path: "/settings",
      component: () => (
        <RequireRole role="Admin">
          <p>Admin area</p>
        </RequireRole>
      ),
    }),
    createRoute({
      getParentRoute: () => rootRoute,
      path: "/work",
      component: () => (
        <RequireRole role="Analyst">
          <p>Analyst area</p>
        </RequireRole>
      ),
    }),
  ]);
  const router = createRouter({ routeTree, history: createMemoryHistory({ initialEntries: [path] }) });
  return render(
    <AuthContext.Provider value={value}>
      <RouterProvider router={router} />
    </AuthContext.Provider>,
  );
}

describe("roleSatisfies", () => {
  it("lets an Admin do what an Analyst can, but not the other way round", () => {
    expect(roleSatisfies("Admin", "Admin")).toBe(true);
    expect(roleSatisfies("Admin", "Analyst")).toBe(true);
    expect(roleSatisfies("Analyst", "Analyst")).toBe(true);
    expect(roleSatisfies("Analyst", "Admin")).toBe(false);
  });
});

describe("RequireRole", () => {
  it("shows the page to an Admin", async () => {
    renderAt("/settings", { user: user("Admin") });
    expect(await screen.findByText("Admin area")).toBeInTheDocument();
  });

  it("sends an Analyst away from an Admin page to Home", async () => {
    renderAt("/settings", { user: user("Analyst") });
    expect(await screen.findByText("Home page")).toBeInTheDocument();
    expect(screen.queryByText("Admin area")).not.toBeInTheDocument();
  });

  it("sends a signed-out visitor to the login page", async () => {
    renderAt("/work", { user: null });
    expect(await screen.findByText("Login page")).toBeInTheDocument();
    expect(screen.queryByText("Analyst area")).not.toBeInTheDocument();
  });

  it("shows an Analyst page to an Analyst", async () => {
    renderAt("/work", { user: user("Analyst") });
    expect(await screen.findByText("Analyst area")).toBeInTheDocument();
  });

  it("shows nothing of the page while the session is being checked", async () => {
    renderAt("/settings", { isLoading: true });
    expect(await screen.findByRole("status")).toHaveTextContent("Loading");
    expect(screen.queryByText("Admin area")).not.toBeInTheDocument();
    expect(screen.queryByText("Login page")).not.toBeInTheDocument();
  });

  it("reports a failed session check instead of pretending to be signed out", async () => {
    renderAt("/settings", { error: new Error("network down") });
    expect(await screen.findByRole("alert")).toHaveTextContent("network down");
    expect(screen.queryByText("Login page")).not.toBeInTheDocument();
  });
});
