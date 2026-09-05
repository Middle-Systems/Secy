import { createContext } from 'react';

import type { AuthContextValue } from '@/auth/types';

/**
 * `null` when no provider is mounted — `useAuth()` turns that into a thrown
 * error rather than handing back a silently signed-out session.
 */
export const AuthContext = createContext<AuthContextValue | null>(null);
