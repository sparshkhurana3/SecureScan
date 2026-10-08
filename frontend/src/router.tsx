import {
  createRootRoute,
  createRoute,
  createRouter,
  Link,
  Navigate,
  Outlet,
  type RouterHistory,
} from "@tanstack/react-router";
import type { ComponentType } from "react";

import { Layout } from "./components/Layout";
import { ErrorNotice } from "./components/ui/page";
import { RequireRole } from "./lib/auth";
import { parseSearchString, stringifySearchObject } from "./lib/utils";
import { DastPage } from "./routes/dast";
import { HistoryPage } from "./routes/history";
import { HomePage } from "./routes/home";
import { LoginPage } from "./routes/login";
import { ReportPage } from "./routes/report";
import { SastPage } from "./routes/sast";
import { ScanDetailPage } from "./routes/scan-detail";
import { AccountsPage } from "./routes/settings/accounts";
import { AuditPage } from "./routes/settings/audit";
import { ContentPage } from "./routes/settings/content";
import { DefectDojoSettingsPage } from "./routes/settings/defectdojo";
import { GitHubPage } from "./routes/settings/github";
import { HealthPage } from "./routes/settings/health";
import { ImagesPage } from "./routes/settings/images";
import { SettingsLayout } from "./routes/settings/layout";
import { PoliciesPage } from "./routes/settings/policies";
import { ProfilesPage } from "./routes/settings/profiles";
import { RepositoriesPage } from "./routes/settings/repositories";
import { ScannerHealthPage } from "./routes/settings/scanner-health";
import { SchedulesPage } from "./routes/settings/schedules";
import { TemplatesPage } from "./routes/settings/templates";
import { VendorAssessmentsPage } from "./routes/vendor-assessments";

/*
 * Route paths (other pages link to these):
 *   /login                  public
 *   /                       Home
 *   /sast, /dast            scan pages
 *   /vendor-assessments     vendor intake, assessments and the fixed/remaining delta
 *   /history                Historical data (filters live in the query string)
 *   /scans/$scanId          scan detail
 *   /reports/$reportId      report view
 *   /settings/...           Admin only (Analysts are sent Home)
 */

function NotFound() {
  return (
    <main className="mx-auto max-w-md p-12 text-center">
      <h1 className="mb-2 text-2xl font-semibold">Page not found</h1>
      <p className="mb-4 text-muted-foreground">There is nothing at this address.</p>
      <Link to="/" className="underline">
        Go to Home
      </Link>
    </main>
  );
}

function RouteError({ error }: { error: Error }) {
  return (
    <div className="mx-auto max-w-xl p-8">
      <ErrorNotice error={error} title="This page could not be shown" />
      <p className="mt-4 text-center">
        <Link to="/" className="underline">
          Go to Home
        </Link>
      </p>
    </div>
  );
}

const rootRoute = createRootRoute({
  component: () => <Outlet />,
  notFoundComponent: NotFound,
});

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/login",
  component: LoginPage,
});

// Every signed-in page: the guard (Analyst or Admin) and the page shell.
const appRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: "app",
  component: () => (
    <RequireRole role="Analyst">
      <Layout>
        <Outlet />
      </Layout>
    </RequireRole>
  ),
});

const homeRoute = createRoute({ getParentRoute: () => appRoute, path: "/", component: HomePage });
const sastRoute = createRoute({ getParentRoute: () => appRoute, path: "/sast", component: SastPage });
const dastRoute = createRoute({ getParentRoute: () => appRoute, path: "/dast", component: DastPage });
const vendorRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/vendor-assessments",
  component: VendorAssessmentsPage,
});
const historyRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/history",
  component: HistoryPage,
});
const scanRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/scans/$scanId",
  component: ScanDetailPage,
});
const reportRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/reports/$reportId",
  component: ReportPage,
});

// Settings is for Admins: an Analyst who opens any /settings address is sent Home.
const settingsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/settings",
  component: () => (
    <RequireRole role="Admin">
      <SettingsLayout />
    </RequireRole>
  ),
});

const settingsIndexRoute = createRoute({
  getParentRoute: () => settingsRoute,
  path: "/",
  component: () => <Navigate to="/settings/templates" replace />,
});

function settingsChild(path: string, component: ComponentType) {
  return createRoute({ getParentRoute: () => settingsRoute, path, component });
}

const routeTree = rootRoute.addChildren([
  loginRoute,
  appRoute.addChildren([
    homeRoute,
    sastRoute,
    dastRoute,
    vendorRoute,
    historyRoute,
    scanRoute,
    reportRoute,
    settingsRoute.addChildren([
      settingsIndexRoute,
      settingsChild("/templates", TemplatesPage),
      settingsChild("/policies", PoliciesPage),
      settingsChild("/profiles", ProfilesPage),
      settingsChild("/defectdojo", DefectDojoSettingsPage),
      settingsChild("/accounts", AccountsPage),
      settingsChild("/github", GitHubPage),
      settingsChild("/repositories", RepositoriesPage),
      settingsChild("/schedules", SchedulesPage),
      settingsChild("/audit", AuditPage),
      settingsChild("/health", HealthPage),
      settingsChild("/scanner-health", ScannerHealthPage),
      settingsChild("/content", ContentPage),
      settingsChild("/images", ImagesPage),
    ]),
  ]),
]);

/** A router for the portal. Tests pass a memory history. */
export function createAppRouter(options: { history?: RouterHistory } = {}) {
  return createRouter({
    routeTree,
    history: options.history,
    // Filters are plain `?tool=a&tool=b` pairs, not JSON.
    parseSearch: parseSearchString,
    stringifySearch: stringifySearchObject,
    defaultErrorComponent: RouteError,
    defaultNotFoundComponent: NotFound,
  });
}

export const router = createAppRouter();
