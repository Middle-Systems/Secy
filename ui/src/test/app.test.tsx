import { describe, expect, it } from 'vitest';
import { screen, waitFor } from '@testing-library/react';

import { renderApp } from '@/test/render';

describe('app shell', () => {
  it('renders the shell chrome and mounts the dashboard view', async () => {
    renderApp('/dashboard');

    // Header — rendered eagerly around the route outlet (which shows the
    // router's pending fallback until the lazy dashboard chunk loads).
    await waitFor(() => {
      expect(screen.getByAltText('Secy')).toBeInTheDocument();
    });
    expect(screen.getByPlaceholderText('Search CVEs, CWEs, or Products...')).toBeInTheDocument();
    expect(screen.getByText('jdesive')).toBeInTheDocument();

    // Sidenav
    expect(screen.getByRole('navigation', { name: 'Main' })).toBeInTheDocument();
    expect(screen.getByText('CVE Database')).toBeInTheDocument();
    expect(screen.getByText('KEV Database')).toBeInTheDocument();

    // Footer
    expect(screen.getByText('All systems operational')).toBeInTheDocument();

    // Routed view — once the lazily code-split chunk resolves the dashboard
    // mounts and shows its global-sync loader while the stats query is in flight.
    expect(
      await screen.findByText(
        'Synchronizing Global Threat Intelligence…',
        {},
        { timeout: 45000 },
      ),
    ).toBeInTheDocument();
  }, 60000);

  it('redirects / to /dashboard', async () => {
    const { router } = renderApp('/');

    await waitFor(() => {
      expect(router.state.location.pathname).toBe('/dashboard');
    });
  });

  it('renders the 404 page for an unknown route', async () => {
    renderApp('/nope');

    await waitFor(() => {
      expect(screen.getByText('404 — page not found')).toBeInTheDocument();
    });
  });
});
