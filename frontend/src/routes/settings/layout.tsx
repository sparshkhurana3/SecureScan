import { Link, Outlet } from "@tanstack/react-router";

export const SETTINGS_PAGES = [
  { to: "/settings/templates", label: "Report templates" },
  { to: "/settings/policies", label: "Verdict policies" },
  { to: "/settings/profiles", label: "Scan profiles" },
  { to: "/settings/defectdojo", label: "DefectDojo and imports" },
  { to: "/settings/accounts", label: "DefectDojo accounts" },
  { to: "/settings/github", label: "GitHub connection" },
  { to: "/settings/repositories", label: "Repositories" },
  { to: "/settings/schedules", label: "Schedules" },
  { to: "/settings/audit", label: "Audit log" },
  { to: "/settings/health", label: "System health" },
  { to: "/settings/scanner-health", label: "Scanner health" },
  { to: "/settings/content", label: "Scanner content" },
  { to: "/settings/images", label: "Scanner images" },
] as const;

const linkClass =
  "block rounded-md px-3 py-2 text-sm no-underline hover:bg-muted data-[status=active]:bg-accent data-[status=active]:text-accent-foreground";

/** Settings: a list of pages on the left (above the page on a narrow screen) and the page itself. */
export function SettingsLayout() {
  return (
    <div className="grid gap-8 md:grid-cols-[14rem_minmax(0,1fr)]">
      <nav aria-label="Settings" className="md:sticky md:top-4 md:self-start">
        <h2 className="mb-2 px-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          Settings
        </h2>
        <ul className="m-0 flex list-none flex-wrap gap-1 p-0 md:flex-col">
          {SETTINGS_PAGES.map((page) => (
            <li key={page.to}>
              <Link to={page.to} className={linkClass}>
                {page.label}
              </Link>
            </li>
          ))}
        </ul>
      </nav>
      <div className="min-w-0">
        <Outlet />
      </div>
    </div>
  );
}
