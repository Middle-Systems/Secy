import { useContext } from 'react';

import { AuthContext } from '@/auth/auth-context';
import type { AuthContextValue } from '@/auth/types';

/** Read the current session. Throws if called outside `<AuthProvider>`. */
export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) {
    throw new Error('useAuth() must be used inside <AuthProvider>');
  }
  return value;
}
