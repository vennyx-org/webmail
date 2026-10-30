import { apiFetch } from '@/lib/browser-navigation';
import { getActiveAccountSlotHeaders } from '@/lib/auth/active-account-slot';
import { fetchConfig } from '@/hooks/use-config';
import { IS_LITE } from '@/lib/lite';

/**
 * Browser half of the external password-change provider (fork feature; the
 * server half and the provider contract live in lib/external-password-change).
 */

/**
 * Whether this deployment changes passwords through PASSWORD_CHANGE_URL
 * rather than Stalwart's JMAP. /api/config only carries the flag when the
 * variable is set; anything else (unset, Lite build, config unreadable)
 * keeps the upstream Stalwart path.
 */
export async function isExternalPasswordChangeEnabled(): Promise<boolean> {
  if (IS_LITE) return false;
  try {
    return (await fetchConfig()).externalPasswordChange === true;
  } catch {
    return false;
  }
}

/**
 * Change the active account's password through the server route, which
 * forwards it to the provider. The slot header picks the account the same
 * way the JMAP passthrough does. Throws with the server's message on failure.
 */
export async function changePasswordViaExternalProvider(currentPassword: string, newPassword: string): Promise<void> {
  const response = await apiFetch('/api/account/change-password', {
    method: 'POST',
    headers: { ...getActiveAccountSlotHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ currentPassword, newPassword }),
  });
  if (response.ok) return;

  let message = 'Failed to change password';
  try {
    const body = (await response.json()) as { error?: unknown } | null;
    if (typeof body?.error === 'string' && body.error) message = body.error;
  } catch {
    /* non-JSON error body */
  }
  throw new Error(message);
}
