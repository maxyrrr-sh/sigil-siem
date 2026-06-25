import { describe, expect, it } from 'vitest';
import { tacticFor } from './attack';

describe('tacticFor', () => {
  it('maps techniques to tactics (mirrors the Rust mapping)', () => {
    expect(tacticFor('T1110.001')).toBe('credential-access');
    expect(tacticFor('T1548.003')).toBe('privilege-escalation');
    expect(tacticFor('T1059')).toBe('execution');
    expect(tacticFor('T1071')).toBe('command-and-control');
  });

  it('handles unknown / missing techniques', () => {
    expect(tacticFor('T9999')).toBe('unknown');
    expect(tacticFor(null)).toBe('unknown');
    expect(tacticFor(undefined)).toBe('unknown');
  });
});
