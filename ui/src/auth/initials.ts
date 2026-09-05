import type { AuthUser } from '@/auth/types';

/** What the header shows next to the avatar. */
export function displayNameOf(user: Pick<AuthUser, 'displayName' | 'email'> | null): string {
  if (!user) return '';
  const name = user.displayName?.trim();
  if (name) return name;
  const at = user.email.indexOf('@');
  return at > 0 ? user.email.slice(0, at) : user.email;
}

/**
 * Up to two letters for the avatar circle: the first letters of a two-word
 * name ("Alex Analyst" -> "AA"), or the first two of a single word
 * ("jdesive" -> "JD"). Non-letters are ignored so "jack.desive" still reads as
 * two words.
 */
export function initialsOf(user: Pick<AuthUser, 'displayName' | 'email'> | null): string {
  const source = displayNameOf(user);
  if (!source) return '?';

  const words = source.split(/[^\p{L}\p{N}]+/u).filter(Boolean);
  if (words.length === 0) return '?';
  if (words.length === 1) return words[0].slice(0, 2).toUpperCase();
  return (words[0][0] + words[words.length - 1][0]).toUpperCase();
}
