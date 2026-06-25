import { describe, expect, it } from 'vitest';
import { className, confidenceLabel, severityColor } from './format';

describe('format', () => {
  it('renders OCSF class names (string and newtype)', () => {
    expect(className('authentication')).toBe('authentication');
    expect(className({ other: 1008 })).toBe('other');
    expect(className(undefined)).toBe('unknown');
  });

  it('buckets confidence', () => {
    expect(confidenceLabel(0.9)).toBe('high');
    expect(confidenceLabel(0.6)).toBe('medium');
    expect(confidenceLabel(0.2)).toBe('low');
  });

  it('maps severity to a CSS var', () => {
    expect(severityColor('High')).toContain('--sev-high');
    expect(severityColor(undefined)).toContain('--sev-unknown');
  });
});
