import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import type { ActionableDetail, ActionableItem, Page } from '@/api/types';
import { renderWithProviders } from '@/test/render';

const useActionablePage = vi.fn();
const useActionableDetail = vi.fn();
const useAssets = vi.fn();

vi.mock('@/api/queries', () => ({
  useActionablePage: (...args: unknown[]) => useActionablePage(...args),
  useActionableDetail: (...args: unknown[]) => useActionableDetail(...args),
  useAssets: (...args: unknown[]) => useAssets(...args),
}));

// The asset drilldown panel is exercised by its own component tests; stub it
// here so this file stays focused on the Actionable list/filter behaviour.
vi.mock('@/components/infrastructure/AssetDetailPanel', () => ({
  AssetDetailPanel: () => null,
}));

import { ActionableView } from './ActionableView';

function item(overrides: Partial<ActionableItem> = {}): ActionableItem {
  return {
    id: 'alert-1',
    cveId: 'CVE-2021-44228',
    description: 'Apache Log4j2 JNDI features do not protect against attacker controlled LDAP…',
    baseSeverity: 'CRITICAL',
    cvssScore: 10.0,
    epssScore: 0.97,
    epssPercentile: 0.999,
    kev: true,
    kevDueDate: '2021-12-24',
    knownRansomwareUse: 'Known',
    exploitMaturity: 'IN_THE_WILD',
    fixState: 'FIXED',
    fixedVersions: '2.17.1',
    fixSource: 'SCANNER',
    matchConfidence: 'EXACT',
    actionableReason: 'KEV_AND_EPSS_HIGH',
    productId: 'prod-1',
    productName: 'Acme Web',
    assetId: null,
    assetName: null,
    componentId: 'comp-1',
    componentName: 'log4j-core',
    componentVersion: '2.14.1',
    componentPurl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
    createdAt: '2026-09-05T14:22:31.118',
    ...overrides,
  };
}

const row2 = item({
  id: 'alert-2',
  cveId: 'CVE-2024-0001',
  baseSeverity: 'MEDIUM',
  cvssScore: 5.3,
  epssScore: 0.2,
  epssPercentile: 0.6,
  kev: false,
  kevDueDate: null,
  knownRansomwareUse: null,
  exploitMaturity: 'POC',
  fixState: 'NO_FIX',
  fixedVersions: null,
  fixSource: null,
  matchConfidence: 'RANGE',
  actionableReason: 'EPSS_HIGH',
  productName: 'Acme API',
  componentName: 'left-pad',
  componentVersion: '1.0.0',
});

const row3 = item({
  id: 'alert-3',
  cveId: 'CVE-2023-9999',
  baseSeverity: 'HIGH',
  cvssScore: 7.5,
  epssScore: 0.15,
  epssPercentile: 0.4,
  kev: false,
  kevDueDate: null,
  knownRansomwareUse: null,
  exploitMaturity: 'NONE',
  fixState: 'FIXED',
  fixedVersions: '3.2.0',
  fixSource: 'CPE_RANGE',
  matchConfidence: 'HEURISTIC',
  actionableReason: 'EPSS_HIGH',
  productName: 'Acme CLI',
  componentName: 'some-lib',
  componentVersion: '3.0.0',
});

function page(content: ActionableItem[]): Page<ActionableItem> {
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

const detail: ActionableDetail = {
  id: 'alert-1',
  actionable: true,
  actionableReason: 'KEV_AND_EPSS_HIGH',
  cvssScore: 10.0,
  epssScore: 0.97,
  epssPercentile: 0.999,
  exploitMaturity: 'IN_THE_WILD',
  fixState: 'FIXED',
  fixedVersions: '2.17.1',
  fixSource: 'SCANNER',
  matchConfidence: 'EXACT',
  lifecycleState: 'ACTIVE',
  kevDueDate: '2021-12-24',
  knownRansomwareUse: 'Known',
  createdAt: '2026-09-05T14:22:31.118',
  cve: {
    id: 'CVE-2021-44228',
    sourceIdentifier: 'security@apache.org',
    published: '2021-12-10T10:15:09',
    lastModified: '2023-11-07T03:39:22',
    vulnStatus: 'Analyzed',
    description: 'Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.',
    baseSeverity: 'CRITICAL',
    cvssScore: 10.0,
    exploitabilityScore: 3.9,
    impactScore: 6.0,
    cwe: 'CWE-502',
    accessVector: 'NETWORK',
    accessComplexity: 'LOW',
    authenticationRequired: 'NONE',
    confidentialityImpact: 'HIGH',
    integrityImpact: 'HIGH',
    availabilityImpact: 'HIGH',
    userInteractionRequired: false,
  },
  affectedComponents: [
    {
      alertId: 'alert-1',
      componentId: 'comp-1',
      name: 'log4j-core',
      version: '2.14.1',
      purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
      sbomId: 'sbom-1',
      productId: 'prod-1',
      productName: 'Acme Web',
      assetId: null,
      assetName: null,
    },
  ],
  kev: null,
  epss: null,
  references: [],
};

function mockPage(over: Record<string, unknown> = {}) {
  useActionablePage.mockReturnValue({
    data: page([item(), row2]),
    isPending: false,
    isFetching: false,
    isError: false,
    refetch: vi.fn().mockResolvedValue({ error: null }),
    ...over,
  });
}

beforeEach(() => {
  useAssets.mockReturnValue({ data: { content: [] }, isPending: false, isError: false });
});

afterEach(() => {
  vi.clearAllMocks();
  try {
    window.localStorage.clear();
  } catch {
    /* nothing stored */
  }
});

describe('ActionableView', () => {
  it('renders rows with the severity / EPSS / KEV / exploit / fix cells', () => {
    mockPage();
    useActionableDetail.mockReturnValue({ data: undefined, isPending: true, isError: false });
    renderWithProviders(<ActionableView />);

    expect(screen.getByText('CVE-2021-44228')).toBeInTheDocument();
    expect(screen.getByText('CVE-2024-0001')).toBeInTheDocument();

    // severity
    expect(screen.getByText('Critical')).toBeInTheDocument();
    expect(screen.getByText('Medium')).toBeInTheDocument();

    // EPSS score + percentile
    expect(screen.getByText('97%')).toBeInTheDocument();
    expect(screen.getByText('p99.9')).toBeInTheDocument();

    // KEV: row 1's due date is in the past -> overdue
    expect(screen.getByText('Overdue')).toBeInTheDocument();

    // exploit maturity badges
    expect(screen.getByText('In the wild')).toBeInTheDocument();
    expect(screen.getByText('PoC')).toBeInTheDocument();

    // fix badges
    expect(screen.getByText('2.17.1')).toBeInTheDocument();
    expect(screen.getByText('none yet')).toBeInTheDocument();
  });

  it('passes fixState=FIXED when "Only with a fix" is toggled on', async () => {
    mockPage();
    useActionableDetail.mockReturnValue({ data: undefined, isPending: true, isError: false });
    renderWithProviders(<ActionableView />);

    expect(useActionablePage).toHaveBeenLastCalledWith(
      expect.objectContaining({ fixState: undefined }),
    );

    await userEvent.click(screen.getByRole('switch', { name: 'Only with a fix' }));

    await waitFor(() => {
      expect(useActionablePage).toHaveBeenLastCalledWith(
        expect.objectContaining({ fixState: 'FIXED' }),
      );
    });
  });

  it('opens the detail panel when a row is clicked', async () => {
    mockPage();
    useActionableDetail.mockReturnValue({ data: detail, isPending: false, isError: false });
    renderWithProviders(<ActionableView />);

    await userEvent.click(screen.getByText('CVE-2021-44228'));

    await waitFor(() => {
      expect(useActionableDetail).toHaveBeenLastCalledWith('alert-1');
    });
    expect(
      await screen.findByText('Why this made the funnel, and what to do about it.'),
    ).toBeInTheDocument();
    expect(screen.getByText('Affected components (1)')).toBeInTheDocument();
  });

  it('renders HEURISTIC match confidence distinctly from EXACT/RANGE', () => {
    mockPage({ data: page([item(), row2, row3]) });
    useActionableDetail.mockReturnValue({ data: undefined, isPending: true, isError: false });
    renderWithProviders(<ActionableView />);

    expect(screen.getByText('Exact match')).toBeInTheDocument();
    expect(screen.getByText('Range match')).toBeInTheDocument();

    const heuristic = screen.getByText('Heuristic match');
    expect(heuristic).toBeInTheDocument();
    expect(heuristic.closest('span')?.className).toMatch(/amber/);
  });

  it('marks a CPE_RANGE fix as approximate on the Fix badge', () => {
    mockPage({ data: page([row3]) });
    useActionableDetail.mockReturnValue({ data: undefined, isPending: true, isError: false });
    renderWithProviders(<ActionableView />);

    expect(screen.getByText('~3.2.0')).toBeInTheDocument();
  });

  it('renders the asset name in the Affected column for an asset-derived row (assetId set, productId null)', () => {
    const assetRow = item({
      id: 'alert-4',
      cveId: 'CVE-2025-1111',
      productId: null,
      productName: null,
      assetId: 'asset-1',
      assetName: 'acme/api:1.4.2',
      componentName: 'openssl',
      componentVersion: '3.1.3-r0',
    });
    mockPage({ data: page([assetRow]) });
    useActionableDetail.mockReturnValue({ data: undefined, isPending: true, isError: false });
    renderWithProviders(<ActionableView />);

    expect(screen.getByText('acme/api:1.4.2')).toBeInTheDocument();
    expect(screen.queryByText('Acme Web')).not.toBeInTheDocument();
  });
});
