import { QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";

import { ApiError } from "./api/client";
import { meQueryKey } from "./api/me";
import { AuthProvider } from "./lib/auth";
import { router as defaultRouter } from "./router";

/**
 * One query client for the portal. A 401 from any call means the session ended: the user is cleared,
 * and the route guard sends the person to the login page.
 */
export function createQueryClient(): QueryClient {
  const client: QueryClient = new QueryClient({
    queryCache: new QueryCache({
      onError: (error) => {
        if (error instanceof ApiError && error.status === 401) {
          client.setQueryData(meQueryKey, null);
        }
      },
    }),
    defaultOptions: {
      queries: {
        staleTime: 10_000,
        refetchOnWindowFocus: false,
        retry: (failureCount, error) =>
          error instanceof ApiError && error.status < 500 ? false : failureCount < 2,
      },
    },
  });
  return client;
}

const defaultClient = createQueryClient();

export function App({
  router = defaultRouter,
  queryClient = defaultClient,
}: {
  router?: typeof defaultRouter;
  queryClient?: QueryClient;
}) {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <RouterProvider router={router} />
      </AuthProvider>
    </QueryClientProvider>
  );
}
