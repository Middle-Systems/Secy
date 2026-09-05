import { useEffect, useState } from 'react';

import { authApi } from '@/auth/auth.api';
import type { AuthConfig } from '@/auth/types';

/**
 * Reads `GET /auth/config` so the login screen can hide the register tab when
 * the backend has registration turned off.
 *
 * Optimistic default: registration is assumed available until the backend says
 * otherwise, so a slow or failed config call never hides a control that works.
 * Hiding the tab is a courtesy — `POST /auth/register` answers 403 regardless,
 * and the form surfaces that.
 */
export function useAuthConfig(): AuthConfig {
  const [config, setConfig] = useState<AuthConfig>({ registrationEnabled: true });

  useEffect(() => {
    let cancelled = false;

    authApi
      .config()
      .then((next) => {
        if (!cancelled) setConfig(next);
      })
      .catch(() => {
        // Keep the optimistic default.
      });

    return () => {
      cancelled = true;
    };
  }, []);

  return config;
}
