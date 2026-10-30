import { beforeEach, describe, expect, it, vi } from 'vitest';

// Fork feature: the browser half of the PASSWORD_CHANGE_URL delegation.

const config = vi.hoisted(() => ({ value: {} as Record<string, unknown>, fail: false }));
vi.mock('@/hooks/use-config', () => ({
  fetchConfig: vi.fn(async () => {
    if (config.fail) throw new Error('config unreachable');
    return config.value;
  }),
}));

const apiFetch = vi.hoisted(() => vi.fn());
vi.mock('@/lib/browser-navigation', () => ({ apiFetch }));

const slotHeaders = vi.hoisted(() => ({ value: { 'X-JMAP-Cookie-Slot': '2' } as Record<string, string> }));
vi.mock('@/lib/auth/active-account-slot', () => ({
  getActiveAccountSlotHeaders: () => slotHeaders.value,
}));

import { changePasswordViaExternalProvider, isExternalPasswordChangeEnabled } from '../external-password-change-client';

beforeEach(() => {
  config.value = {};
  config.fail = false;
  apiFetch.mockReset();
  slotHeaders.value = { 'X-JMAP-Cookie-Slot': '2' };
});

describe('isExternalPasswordChangeEnabled', () => {
  it('is off when /api/config does not carry the flag (PASSWORD_CHANGE_URL unset)', async () => {
    expect(await isExternalPasswordChangeEnabled()).toBe(false);
  });

  it('is on when /api/config says so', async () => {
    config.value = { externalPasswordChange: true };
    expect(await isExternalPasswordChangeEnabled()).toBe(true);
  });

  it('stays off when the config cannot be read', async () => {
    config.fail = true;
    expect(await isExternalPasswordChangeEnabled()).toBe(false);
  });
});

describe('changePasswordViaExternalProvider', () => {
  it('POSTs only the two passwords to the server route, for the active account slot', async () => {
    apiFetch.mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));

    await changePasswordViaExternalProvider('old', 'new-password');

    expect(apiFetch).toHaveBeenCalledWith('/api/account/change-password', {
      method: 'POST',
      headers: { 'X-JMAP-Cookie-Slot': '2', 'Content-Type': 'application/json' },
      body: JSON.stringify({ currentPassword: 'old', newPassword: 'new-password' }),
    });
  });

  it('throws the server message on failure', async () => {
    apiFetch.mockResolvedValueOnce(new Response(JSON.stringify({ error: 'Invalid email or current password' }), { status: 401 }));

    await expect(changePasswordViaExternalProvider('wrong', 'new-password'))
      .rejects.toThrow('Invalid email or current password');
  });

  it('throws a generic message when the error body is not JSON', async () => {
    apiFetch.mockResolvedValueOnce(new Response('<html>Bad gateway</html>', { status: 502 }));

    await expect(changePasswordViaExternalProvider('old', 'new-password'))
      .rejects.toThrow('Failed to change password');
  });
});
