import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';

import { MatchConfidenceBadge } from './MatchConfidenceBadge';

describe('MatchConfidenceBadge', () => {
  it('renders EXACT and RANGE as quiet, non-amber labels', () => {
    const { container: exactContainer } = render(<MatchConfidenceBadge confidence="EXACT" />);
    const { container: rangeContainer } = render(<MatchConfidenceBadge confidence="RANGE" />);

    expect(screen.getByText('Exact match')).toBeInTheDocument();
    expect(screen.getByText('Range match')).toBeInTheDocument();

    expect(exactContainer.querySelector('span')?.className).not.toMatch(/amber/);
    expect(rangeContainer.querySelector('span')?.className).not.toMatch(/amber/);
  });

  it('renders HEURISTIC with a distinct amber cautionary treatment, not the exploit red', () => {
    const { container } = render(<MatchConfidenceBadge confidence="HEURISTIC" />);

    expect(screen.getByText('Heuristic match')).toBeInTheDocument();
    const className = container.querySelector('span')?.className ?? '';
    expect(className).toMatch(/amber/);
    expect(className).not.toMatch(/destructive/);
  });
});
