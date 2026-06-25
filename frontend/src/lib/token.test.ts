import { afterEach, describe, expect, it, vi } from 'vitest';
import { getToken, handleUnauthorized, setToken, setUnauthorizedHandler } from './token';

afterEach(() => {
  setToken(null);
  setUnauthorizedHandler(() => {});
});

describe('token store', () => {
  it('round-trips and clears the token', () => {
    expect(getToken()).toBeNull();
    setToken('abc.def.ghi');
    expect(getToken()).toBe('abc.def.ghi');
    setToken(null);
    expect(getToken()).toBeNull();
  });

  it('invokes the unauthorized handler', () => {
    const fn = vi.fn();
    setUnauthorizedHandler(fn);
    handleUnauthorized();
    expect(fn).toHaveBeenCalledOnce();
  });
});
