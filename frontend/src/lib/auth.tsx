import { useQueryClient } from "@tanstack/react-query";
import { Navigate, useNavigate, useRouterState } from "@tanstack/react-router";
import { createContext, type ReactNode, useContext, useMemo } from "react";

import { errorMessage } from "../api/client";
import { type Me, meQueryKey, type Role, signOut, useMeQuery } from "../api/me";
import { Button } from "../components/ui/button";

export type { Me, Role };

export type AuthValue = {
  /** The signed-in user, or null (not signed in, or still loading). */
  user: Me | null;
  isLoading: boolean;
  /** Set when the session could not be checked (network or server error, not "signed out"). */
  error: unknown;
  refetch: () => void;
};

export const AuthContext = createContext<AuthValue | null>(null);

/** Loads `GET /api/v1/me` once and shares it. Mount inside `QueryClientProvider`. */
export function AuthProvider({ children }: { children: ReactNode }) {
  const query = useMeQuery();
  const refetch = query.refetch;
  const value = useMemo<AuthValue>(
    () => ({
      user: query.data ?? null,
      isLoading: query.isPending,
      error: query.error,
      refetch: () => void refetch(),
    }),
    [query.data, query.isPending, query.error, refetch],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useMe(): AuthValue {
  const value = useContext(AuthContext);
  if (value === null) throw new Error("useMe must be used inside AuthProvider");
  return value;
}

/** Admin satisfies every role; an Analyst satisfies Analyst only. */
export function roleSatisfies(actual: Role, required: Role): boolean {
  return actual === "Admin" || actual === required;
}

/**
 * Route guard. Not signed in: to the login page, remembering where you were. Signed in without the
 * required role: back to Home. While the session is checked nothing of the page is shown.
 */
export function RequireRole({ role, children }: { role: Role; children: ReactNode }) {
  const { user, isLoading, error, refetch } = useMe();
  const href = useRouterState({ select: (state) => state.location.href });
  if (isLoading) {
    return (
      <p role="status" className="p-8 text-center text-muted-foreground">
        Loading...
      </p>
    );
  }
  if (error) {
    return (
      <div role="alert" className="mx-auto max-w-md p-8 text-center">
        <p className="mb-4">Your session could not be checked. {errorMessage(error)}</p>
        <Button onClick={refetch}>Try again</Button>
      </div>
    );
  }
  if (!user) return <Navigate to="/login" search={{ next: href }} replace />;
  if (!roleSatisfies(user.role, role)) return <Navigate to="/" replace />;
  return <>{children}</>;
}

/** Ends the session on the server, forgets everything cached for this user and shows the login page. */
export function useSignOut() {
  const client = useQueryClient();
  const navigate = useNavigate();
  return async () => {
    await signOut(); // throws when the server could not end the session; the caller shows it
    client.clear();
    client.setQueryData(meQueryKey, null);
    await navigate({ to: "/login" });
  };
}
