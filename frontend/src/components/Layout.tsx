import { Link } from "@tanstack/react-router";
import { type ReactNode, useState } from "react";

import { errorMessage } from "../api/client";
import { BRAND } from "../brand/brand";
import { useMe, useSignOut } from "../lib/auth";
import { BrandMark } from "./BrandMark";
import { Button } from "./ui/button";

const navLinkClass =
  "rounded-md px-3 py-2 text-sm font-medium text-muted-foreground no-underline hover:bg-muted hover:text-foreground data-[status=active]:bg-muted data-[status=active]:text-foreground data-[status=active]:underline data-[status=active]:underline-offset-8";

/** The page shell of every signed-in route: header with navigation, the user and sign-out. */
export function Layout({ children }: { children: ReactNode }) {
  const { user } = useMe();
  const signOut = useSignOut();
  const [signOutError, setSignOutError] = useState<string | null>(null);

  const onSignOut = () => {
    setSignOutError(null);
    signOut().catch((error: unknown) => setSignOutError(errorMessage(error)));
  };

  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded-md focus:bg-accent focus:px-3 focus:py-2 focus:text-accent-foreground"
      >
        Skip to content
      </a>
      <header className="border-b border-border">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3">
          <Link to="/" aria-label="SecureScan home" className="flex items-center gap-3 no-underline">
            <BrandMark />
            <span className="flex flex-col leading-tight">
              <span className="text-sm font-semibold text-foreground">{BRAND.productName}</span>
              <span className="text-xs text-muted-foreground">{BRAND.companyName}</span>
            </span>
          </Link>
          <nav aria-label="Main" className="flex flex-wrap items-center gap-1">
            <Link to="/sast" className={navLinkClass}>
              SAST scan
            </Link>
            <Link to="/dast" className={navLinkClass}>
              DAST scan
            </Link>
            <Link to="/vendor-assessments" className={navLinkClass}>
              Vendor assessments
            </Link>
            <Link to="/history" className={navLinkClass}>
              Historical data
            </Link>
            {user?.role === "Admin" ? (
              <Link to="/settings" className={navLinkClass}>
                Settings
              </Link>
            ) : null}
          </nav>
          <div className="ml-auto flex items-center gap-3 text-sm">
            {user ? (
              <p className="m-0" title={user.email || undefined}>
                <span className="font-medium">{user.name}</span>
                <span className="ml-2 rounded border border-border px-1.5 py-0.5 text-xs">
                  {user.role}
                </span>
              </p>
            ) : null}
            <Button variant="outline" size="sm" onClick={onSignOut}>
              Sign out
            </Button>
          </div>
        </div>
        {signOutError ? (
          <p role="alert" className="mx-auto max-w-7xl px-4 pb-2 text-sm">
            Could not sign out: {signOutError}
          </p>
        ) : null}
      </header>
      <main id="main" tabIndex={-1} className="mx-auto w-full max-w-7xl flex-1 px-4 py-8">
        {children}
      </main>
    </div>
  );
}
