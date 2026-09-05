/**
 * Token persistence.
 *
 * Every access is guarded: `localStorage` throws outright in a private window
 * with site data blocked, and is simply absent in a non-browser test
 * environment. A failure here is never fatal — it costs the user a re-login,
 * so it degrades to "no stored session".
 */

const TOKEN_KEY = 'secy.auth.token';

export function readStoredToken(): string | null {
  try {
    return window.localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function writeStoredToken(token: string): void {
  try {
    window.localStorage.setItem(TOKEN_KEY, token);
  } catch {
    // Non-persistent session; nothing else to do.
  }
}

export function clearStoredToken(): void {
  try {
    window.localStorage.removeItem(TOKEN_KEY);
  } catch {
    // Already unreachable — nothing to clear.
  }
}
