/**
 * Where to land after signing in.
 *
 * Only same-origin absolute paths are honoured. The `redirect` search param
 * arrives in the URL and is therefore attacker-supplied: without this check a
 * crafted `/login?redirect=https://evil.example` would turn the login screen
 * into an open redirect that borrows Secy's credibility — the victim signs in
 * on the real site and is handed straight to the attacker's.
 */
export const DEFAULT_REDIRECT = '/dashboard';

export function safeRedirect(target: string | undefined | null): string {
  if (!target) return DEFAULT_REDIRECT;

  // A leading `//` is protocol-relative: `//evil.example` is off-site.
  if (!target.startsWith('/') || target.startsWith('//')) return DEFAULT_REDIRECT;

  // `/\evil.example` is normalised to a host by some browsers.
  if (target.startsWith('/\\')) return DEFAULT_REDIRECT;

  // Bouncing back to the screen we just left would loop.
  if (target === '/login' || target.startsWith('/login?')) return DEFAULT_REDIRECT;

  return target;
}
