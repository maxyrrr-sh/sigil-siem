import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from './api';
import { setToken, setUnauthorizedHandler } from './token';

function mockFetch(status: number, body: unknown) {
  const fn = vi.fn((_url: string, _init: RequestInit) =>
    Promise.resolve(
      new Response(JSON.stringify(body), {
        status,
        headers: { 'content-type': 'application/json' },
      }),
    ),
  );
  vi.stubGlobal('fetch', fn);
  return fn;
}

afterEach(() => {
  vi.unstubAllGlobals();
  setToken(null);
  setUnauthorizedHandler(() => {});
});

describe('api client', () => {
  it('posts credentials to the versioned login endpoint', async () => {
    const fetchMock = mockFetch(200, {
      token: 't',
      token_type: 'Bearer',
      expires_in: 3600,
      user: { username: 'admin', roles: ['admin'] },
    });
    const res = await api.login('admin', 'pw');
    expect(res.token).toBe('t');
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe('/api/v1/auth/login');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({ username: 'admin', password: 'pw' });
  });

  it('attaches the bearer token when present', async () => {
    setToken('xyz');
    const fetchMock = mockFetch(200, { events: 1, alerts: 0 });
    await api.count();
    const [, init] = fetchMock.mock.calls[0]!;
    expect((init.headers as Record<string, string>).authorization).toBe('Bearer xyz');
  });

  it('fires the unauthorized handler and throws on 401', async () => {
    const onUnauth = vi.fn();
    setUnauthorizedHandler(onUnauth);
    mockFetch(401, { error: 'missing or invalid token' });
    await expect(api.me()).rejects.toThrow('missing or invalid token');
    expect(onUnauth).toHaveBeenCalledOnce();
  });
});
