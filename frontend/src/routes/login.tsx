import { Navigate, useRouterState } from "@tanstack/react-router";

import { apiUrl } from "../api/client";
import { Wordmark } from "../components/Wordmark";
import { Button } from "../components/ui/button";
import { useMe } from "../lib/auth";
import { safeNextPath } from "../lib/utils";

/** The login address, remembering where the person was going (a same-site path only). */
export function loginUrl(next: unknown): string {
  const target = safeNextPath(next);
  return apiUrl("/auth/login", target === "/" ? undefined : { next: target });
}

/** The wordmark, the product name and one button. Nothing else. */
export function LoginPage() {
  const { user } = useMe();
  const search = useRouterState({ select: (state) => state.location.search }) as Record<
    string,
    unknown
  >;
  if (user) return <Navigate to="/" replace />;
  return (
    <main className="grid min-h-screen place-items-center bg-background px-4 text-foreground">
      <div className="flex flex-col items-center gap-6 text-center">
        <Wordmark height={40} />
        <h1 className="text-3xl font-semibold tracking-tight">SecureScan</h1>
        <Button asChild size="lg">
          <a href={loginUrl(search.next)}>Sign in with Microsoft</a>
        </Button>
      </div>
    </main>
  );
}
