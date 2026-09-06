import { afterEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { renderApp } from '@/test/render';

const TOKEN = 'header.payload.signature';

const ACCOUNT = {
  id: '00000000-0000-4000-8000-0000000000aa',
  email: 'analyst@example.com',
  displayName: 'Alex Analyst',
  role: 'USER' as const,
  enabled: true,
  createdAt: '2025-01-01T00:00:00',
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

/**
 * Answers the `/auth/**` calls the login screen makes and nothing else — any
 * other endpoint comes back empty, which is enough for the placeholder views
 * used here.
 */
function stubBackend(loginResponse: () => Response) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url.includes('/auth/config')) return json({ registrationEnabled: true });
    if (url.includes('/auth/login')) return loginResponse();
    return json({});
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

afterEach(() => {
  vi.unstubAllGlobals();
  try {
    window.localStorage.clear();
  } catch {
    // Nothing stored.
  }
});

describe('authentication', () => {
  it('sends a signed-out visitor to /login and remembers where they were headed', async () => {
    stubBackend(() => json({}, 401));

    const { router } = renderApp('/compliance', { authenticated: false });

    await waitFor(() => {
      expect(router.state.location.pathname).toBe('/login');
    });
    // The intended destination survives the bounce.
    expect(router.state.location.search).toEqual({ redirect: '/compliance' });

    // The login screen renders outside the shell.
    expect(await screen.findByLabelText('Email')).toBeInTheDocument();
    expect(screen.queryByRole('navigation', { name: 'Main' })).not.toBeInTheDocument();
  }, 30000);

  it('signs in and lands on the originally requested route', async () => {
    stubBackend(() => json({ token: TOKEN, expiresAt: '2099-01-01T00:00:00Z', user: ACCOUNT }));

    const { router } = renderApp('/compliance', { authenticated: false });

    const email = await screen.findByLabelText('Email');
    await userEvent.type(email, ACCOUNT.email);
    await userEvent.type(screen.getByLabelText('Password'), 'a-good-password');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));

    await waitFor(() => {
      expect(router.state.location.pathname).toBe('/compliance');
    });

    // The shell is back, showing the real account rather than a placeholder.
    expect(await screen.findByText('Alex Analyst')).toBeInTheDocument();
    expect(window.localStorage.getItem('secy.auth.token')).toBe(TOKEN);
  }, 30000);

  it('reports a rejected sign-in instead of redirecting', async () => {
    stubBackend(() => json({ message: 'Invalid email or password' }, 401));

    renderApp('/compliance', { authenticated: false });

    await userEvent.type(await screen.findByLabelText('Email'), ACCOUNT.email);
    await userEvent.type(screen.getByLabelText('Password'), 'wrong-password');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid email or password');
    expect(window.localStorage.getItem('secy.auth.token')).toBeNull();
  }, 30000);

  it('signs out from the header menu and returns to /login', async () => {
    stubBackend(() => json({}, 401));

    const { router } = renderApp('/compliance');

    await userEvent.click(await screen.findByRole('button', { name: /Account menu for/ }));
    await userEvent.click(await screen.findByText('Sign out'));

    await waitFor(() => {
      expect(router.state.location.pathname).toBe('/login');
    });
  }, 30000);
});
