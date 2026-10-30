// @vitest-environment node
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';

// Fork feature: POST /api/account/change-password delegates to the external
// provider in PASSWORD_CHANGE_URL (lib/external-password-change). The wire
// contract with the provider is fixed: { email, currentPassword, newPassword }
// -> 200 | 401 | 400.

const logger = vi.hoisted(() => ({ warn: vi.fn(), error: vi.fn(), debug: vi.fn(), info: vi.fn() }));
vi.mock('@/lib/logger', () => ({ logger }));

const getStalwartCredentials = vi.hoisted(() => vi.fn());
vi.mock('@/lib/stalwart/credentials', () => ({
  getStalwartCredentials: (...args: unknown[]) => getStalwartCredentials(...args),
}));

import { POST } from '@/app/api/account/change-password/route';

const HOST = 'mail.example.com';
const PROVIDER = 'http://api:3001/api/self-service/mailbox-password';
const CURRENT = 'current-Secret-1';
const NEXT = 'next-Secret-2';

const fetchMock = vi.fn();

function creds(overrides: Record<string, unknown> = {}) {
  return {
    serverUrl: 'https://mail.example.com',
    authHeader: 'Basic dXNlckBleGFtcGxlLmNvbTpjdXJyZW50',
    username: 'user@example.com',
    accountName: 'user@example.com',
    hasSessionCookie: true,
    slot: 1,
    trusted: true,
    ...overrides,
  };
}

function request(body: unknown, headers: Record<string, string> = {}): NextRequest {
  return new NextRequest(`https://${HOST}/api/account/change-password`, {
    method: 'POST',
    headers: {
      host: HOST,
      'content-type': 'application/json',
      'sec-fetch-site': 'same-origin',
      'x-jmap-cookie-slot': '1',
      ...headers,
    },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
}

function providerAnswers(status: number, body?: unknown) {
  fetchMock.mockResolvedValueOnce(
    new Response(body === undefined ? null : JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    }),
  );
}

function sentToProvider(): { url: string; init: RequestInit; body: Record<string, unknown> } {
  const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
  return { url, init, body: JSON.parse(String(init.body)) };
}

function everythingLogged(): string {
  return JSON.stringify([logger.warn, logger.error, logger.debug, logger.info].flatMap((fn) => fn.mock.calls));
}

beforeEach(() => {
  vi.clearAllMocks();
  fetchMock.mockReset();
  vi.stubGlobal('fetch', fetchMock);
  vi.stubEnv('PASSWORD_CHANGE_URL', PROVIDER);
  getStalwartCredentials.mockResolvedValue(creds());
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe('POST /api/account/change-password', () => {
  it('does not exist when PASSWORD_CHANGE_URL is unset, and touches neither session nor network', async () => {
    vi.stubEnv('PASSWORD_CHANGE_URL', '');
    const res = await POST(request({ currentPassword: CURRENT, newPassword: NEXT }));

    expect(res.status).toBe(404);
    expect(getStalwartCredentials).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('treats a whitespace-only PASSWORD_CHANGE_URL as unset', async () => {
    vi.stubEnv('PASSWORD_CHANGE_URL', '   ');
    const res = await POST(request({ currentPassword: CURRENT, newPassword: NEXT }));
    expect(res.status).toBe(404);
  });

  it('rejects a cross-origin request before reading the session', async () => {
    const res = await POST(request(
      { currentPassword: CURRENT, newPassword: NEXT },
      { 'sec-fetch-site': 'same-site', origin: 'https://evil.example.com' },
    ));

    expect(res.status).toBe(403);
    expect(getStalwartCredentials).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('answers 401 without a signed-in session', async () => {
    getStalwartCredentials.mockResolvedValueOnce(null);
    const res = await POST(request({ currentPassword: CURRENT, newPassword: NEXT }));

    expect(res.status).toBe(401);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('resolves the account from the request (slot header) through the session cookie', async () => {
    providerAnswers(200, { ok: true });
    const req = request({ currentPassword: CURRENT, newPassword: NEXT });
    await POST(req);

    expect(getStalwartCredentials).toHaveBeenCalledWith(req);
  });

  it.each([
    ['a non-JSON body', 'not json'],
    ['a missing new password', { currentPassword: CURRENT }],
    ['an empty current password', { currentPassword: '', newPassword: NEXT }],
    ['a non-string password', { currentPassword: CURRENT, newPassword: 12345678 }],
    ['a null body', 'null'],
  ])('answers 400 for %s', async (_label, body) => {
    const res = await POST(request(body));

    expect(res.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('POSTs { email, currentPassword, newPassword } to the provider and answers ok', async () => {
    vi.stubEnv('PASSWORD_CHANGE_URL', `${PROVIDER}/`);
    providerAnswers(200, { ok: true });

    const res = await POST(request({ currentPassword: CURRENT, newPassword: NEXT }));

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const { url, init, body } = sentToProvider();
    expect(url).toBe(PROVIDER);
    expect(init.method).toBe('POST');
    expect(new Headers(init.headers).get('content-type')).toBe('application/json');
    expect(init.redirect).toBe('error');
    expect(body).toEqual({ email: 'user@example.com', currentPassword: CURRENT, newPassword: NEXT });
  });

  it('names the account the session resolved to, never one from the body', async () => {
    getStalwartCredentials.mockResolvedValueOnce(creds({ username: 'user', accountName: 'user@example.com' }));
    providerAnswers(200, { ok: true });

    await POST(request({ email: 'victim@example.com', accountId: 'x', currentPassword: CURRENT, newPassword: NEXT }));

    expect(sentToProvider().body).toEqual({ email: 'user@example.com', currentPassword: CURRENT, newPassword: NEXT });
  });

  it('forwards a 401 (wrong current password) with the provider message', async () => {
    providerAnswers(401, { message: 'Invalid email or current password', error: 'Unauthorized', statusCode: 401 });

    const res = await POST(request({ currentPassword: 'wrong', newPassword: NEXT }));

    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'Invalid email or current password' });
  });

  it('forwards a 400 (policy rejection) with the provider message', async () => {
    providerAnswers(400, { message: 'newPassword must be at least 8 characters', error: 'Bad Request', statusCode: 400 });

    const res = await POST(request({ currentPassword: CURRENT, newPassword: 'short' }));

    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: 'newPassword must be at least 8 characters' });
  });

  it('falls back to a generic message when a 401 or 400 carries none', async () => {
    fetchMock.mockResolvedValueOnce(new Response('nope', { status: 401 }));

    const res = await POST(request({ currentPassword: 'wrong', newPassword: NEXT }));

    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'Failed to change password' });
  });

  it.each([500, 503, 404, 403, 302])('maps a provider %i to a generic 502', async (status) => {
    providerAnswers(status, { message: 'stack trace: db at 10.0.0.5' });

    const res = await POST(request({ currentPassword: CURRENT, newPassword: NEXT }));

    expect(res.status).toBe(502);
    expect(await res.json()).toEqual({ error: 'Failed to change password' });
    expect(everythingLogged()).toContain(String(status));
  });

  it('answers 502 when the provider cannot be reached', async () => {
    fetchMock.mockRejectedValueOnce(Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } }));

    const res = await POST(request({ currentPassword: CURRENT, newPassword: NEXT }));

    expect(res.status).toBe(502);
    expect(await res.json()).toEqual({ error: 'Failed to change password' });
    expect(everythingLogged()).toContain('ECONNREFUSED');
  });

  it('never logs a password, whatever happens', async () => {
    providerAnswers(200, { ok: true });
    await POST(request({ currentPassword: CURRENT, newPassword: NEXT }));
    providerAnswers(500, {});
    await POST(request({ currentPassword: CURRENT, newPassword: NEXT }));
    fetchMock.mockRejectedValueOnce(new Error('boom'));
    await POST(request({ currentPassword: CURRENT, newPassword: NEXT }));

    expect(logger.info).toHaveBeenCalled();
    expect(logger.warn).toHaveBeenCalled();
    expect(logger.error).toHaveBeenCalled();
    const logged = everythingLogged();
    expect(logged).not.toContain(CURRENT);
    expect(logged).not.toContain(NEXT);
  });
});
