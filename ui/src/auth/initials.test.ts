import { describe, expect, it } from 'vitest';

import { displayNameOf, initialsOf } from '@/auth/initials';

const user = (displayName: string | null, email = 'alex.analyst@example.com') => ({
  displayName,
  email,
});

describe('displayNameOf', () => {
  it('prefers the display name', () => {
    expect(displayNameOf(user('Alex Analyst'))).toBe('Alex Analyst');
  });

  it('falls back to the local part of the email', () => {
    expect(displayNameOf(user(null))).toBe('alex.analyst');
    expect(displayNameOf(user('   '))).toBe('alex.analyst');
  });

  it('is empty with no user', () => {
    expect(displayNameOf(null)).toBe('');
  });
});

describe('initialsOf', () => {
  it('takes the outer initials of a multi-word name', () => {
    expect(initialsOf(user('Alex Analyst'))).toBe('AA');
    expect(initialsOf(user('Ada Byron Lovelace'))).toBe('AL');
  });

  it('takes the first two letters of a single word', () => {
    expect(initialsOf(user('jdesive'))).toBe('JD');
  });

  it('splits an email local part on its punctuation', () => {
    expect(initialsOf(user(null))).toBe('AA');
  });

  it('degrades rather than throwing', () => {
    expect(initialsOf(null)).toBe('?');
    expect(initialsOf(user('!!!', '!!!'))).toBe('?');
  });
});
