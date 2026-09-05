import { describe, expect, it } from 'vitest';

import { epssRisk } from './epss.risk';

describe('epssRisk', () => {
  it('buckets scores above 0.1 as critical', () => {
    expect(epssRisk(0.5)).toMatchObject({ level: 'critical', label: 'Critical Probability' });
    expect(epssRisk(0.10001)).toMatchObject({ level: 'critical' });
  });

  it('buckets scores in (0.05, 0.1] as high', () => {
    expect(epssRisk(0.08)).toMatchObject({ level: 'high', label: 'High Probability' });
    expect(epssRisk(0.05001)).toMatchObject({ level: 'high' });
  });

  it('buckets scores in (0.01, 0.05] as elevated', () => {
    expect(epssRisk(0.03)).toMatchObject({ level: 'elevated', label: 'Elevated' });
    expect(epssRisk(0.01001)).toMatchObject({ level: 'elevated' });
  });

  it('buckets scores at or below 0.01 as low', () => {
    expect(epssRisk(0.001)).toMatchObject({ level: 'low', label: 'Low Risk' });
    expect(epssRisk(0)).toMatchObject({ level: 'low' });
  });

  describe('exact boundary values fall into the lower bucket (strict >)', () => {
    it('0.1 → high, not critical', () => {
      expect(epssRisk(0.1).level).toBe('high');
    });

    it('0.05 → elevated, not high', () => {
      expect(epssRisk(0.05).level).toBe('elevated');
    });

    it('0.01 → low, not elevated', () => {
      expect(epssRisk(0.01).level).toBe('low');
    });
  });

  it('treats non-finite input as low', () => {
    expect(epssRisk(Number.NaN).level).toBe('low');
  });

  it('exposes a pill colour class and a Progress-indicator bar class', () => {
    const risk = epssRisk(0.2);
    expect(risk.colorClass).toContain('text-severity-critical');
    expect(risk.barClass).toContain('[&>div]:bg-severity-critical');
  });
});
