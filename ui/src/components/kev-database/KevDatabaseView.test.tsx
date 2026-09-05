import { afterEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import type { KEV, Page } from '@/api/types';
import { renderWithProviders } from '@/test/render';

const useKevPage = vi.fn();
const mutateAsync = vi.fn().mockResolvedValue(undefined);

vi.mock('@/api/queries', () => ({
  useKevPage: (...args: unknown[]) => useKevPage(...args),
  useIngestKev: () => ({ mutateAsync, isPending: false }),
}));

import { KevDatabaseView } from './KevDatabaseView';

function kev(overrides: Partial<KEV> = {}): KEV {
  return {
    cveId: 'CVE-2026-1234',
    vendor: 'Acme',
    product: 'Widget',
    name: 'Remote code execution in Widget',
    added: '2026-08-01T00:00:00',
    description: 'A bad bug.',
    requiredActions: 'Apply updates per vendor instructions.',
    dueDate: '2026-08-22T00:00:00',
    knownRansomwareCampaignUse: 'Known',
    notes: 'Tracked by CISA.',
    ...overrides,
  };
}

function page(content: KEV[]): Page<KEV> {
  return {
    content,
    totalElements: content.length,
    totalPages: 1,
    number: 0,
    size: 15,
    numberOfElements: content.length,
    first: true,
    last: true,
    empty: content.length === 0,
  };
}

function mockQuery(over: Record<string, unknown>) {
  useKevPage.mockReturnValue({
    data: undefined,
    isPending: false,
    isFetching: false,
    isError: false,
    refetch: vi.fn().mockResolvedValue({ error: null }),
    ...over,
  });
}

afterEach(() => {
  vi.clearAllMocks();
});

describe('KevDatabaseView', () => {
  it('renders rows with the ransomware badge and opens the remediation modal', async () => {
    mockQuery({ data: page([kev()]) });
    renderWithProviders(<KevDatabaseView />);

    expect(screen.getByText('CVE-2026-1234')).toBeInTheDocument();
    expect(screen.getByText('Confirmed')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'View Steps' }));

    await waitFor(() => {
      expect(screen.getByText(/Remediation Strategy/)).toBeInTheDocument();
    });
    expect(screen.getByText('Apply updates per vendor instructions.')).toBeInTheDocument();
  });

  it('shows the empty message', () => {
    mockQuery({ data: page([]) });
    renderWithProviders(<KevDatabaseView />);
    expect(screen.getByText('No entries found.')).toBeInTheDocument();
  });

  it('shows an inline error when the query fails with no data', () => {
    mockQuery({ isError: true, data: undefined });
    renderWithProviders(<KevDatabaseView />);
    expect(screen.getByText('Unable to load the KEV catalog')).toBeInTheDocument();
  });
});
