import { useEffect } from 'react';
import { RouterProvider } from '@tanstack/react-router';

import { useAuth } from '@/auth/useAuth';
import { RoutePending } from '@/components/common/RoutePending';
import { router } from '@/router';

/**
 * Mounts the router, but not before the session question is settled.
 *
 * On a cold load with a token in storage the answer takes a `/auth/me` round
 * trip, and the route guard has no useful answer before it returns — mounting
 * early would either flash the shell at a signed-out visitor or bounce a
 * signed-in one to `/login`.
 *
 * Must be rendered inside `<AuthProvider>`; see `main.tsx`.
 */
export function AppRouter() {
  const { status } = useAuth();

  // A sign-in or sign-out does not itself navigate; re-running the matched
  // routes' `beforeLoad` is what turns it into one.
  useEffect(() => {
    void router.invalidate();
  }, [status]);

  if (status === 'loading') {
    return <RoutePending />;
  }

  return <RouterProvider router={router} />;
}
