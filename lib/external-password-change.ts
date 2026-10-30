/**
 * External password-change provider (server side).
 *
 * Stalwart can authenticate against a READ-ONLY directory (SQL/LDAP/...)
 * whose passwords are owned by a separate provisioning system. There, JMAP
 * `x:AccountPassword/set` fails "Operation not allowed", so the deployment
 * sets `PASSWORD_CHANGE_URL` and the webmail delegates password changes to
 * that HTTP endpoint instead (app/api/account/change-password).
 *
 * Unset (the default) changes nothing: the browser keeps using the Stalwart
 * JMAP passthrough exactly as upstream does.
 *
 * Contract with `PASSWORD_CHANGE_URL` (do not change - providers implement it):
 *   Request  POST application/json
 *     { "email": string, "currentPassword": string, "newPassword": string }
 *   Response
 *     200           success
 *     401           current password incorrect (message forwarded)
 *     400           new password rejected by policy (message forwarded)
 *     anything else upstream failure (502)
 *
 * The contract carries no TOTP code. Accounts with TOTP on keep Stalwart's
 * own path, which verifies the code (see changePassword in
 * stores/account-security-store.ts).
 */

const PROVIDER_TIMEOUT_MS = 15_000;
const MAX_FORWARDED_MESSAGE_LENGTH = 300;
const FALLBACK_MESSAGE = 'Failed to change password';

/** The configured provider URL, or null when password changes stay on Stalwart. */
export function getPasswordChangeUrl(): string | null {
  const url = (process.env.PASSWORD_CHANGE_URL ?? '').trim().replace(/\/+$/, '');
  return url || null;
}

export interface PasswordChangeResult {
  /** HTTP status for the browser: 200, 400, 401 or 502. */
  status: 200 | 400 | 401 | 502;
  /** Message for the user on failure; never contains a password. */
  error?: string;
  /** The provider's own status, for the log. */
  upstreamStatus: number;
}

/** The provider's own message, when it sent a short string one. */
async function readProviderMessage(response: Response): Promise<string | null> {
  try {
    const body = (await response.json()) as { message?: unknown; error?: unknown } | null;
    const message = body?.message ?? body?.error;
    if (typeof message === 'string' && message.trim()) {
      return message.trim().slice(0, MAX_FORWARDED_MESSAGE_LENGTH);
    }
  } catch {
    /* non-JSON error body */
  }
  return null;
}

/**
 * POST the change to the provider. `email` must be the signed-in account as
 * the server resolved it, never a value taken from the request body.
 * Network errors and timeouts throw; the caller maps them to a 502.
 */
export async function changePasswordViaProvider(
  url: string,
  email: string,
  currentPassword: string,
  newPassword: string,
): Promise<PasswordChangeResult> {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ email, currentPassword, newPassword }),
    // A redirect would re-send the passwords to wherever it points.
    redirect: 'error',
    cache: 'no-store',
    signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS),
  });

  if (response.ok) {
    // Drain the body so the connection can be reused.
    await response.body?.cancel().catch(() => {});
    return { status: 200, upstreamStatus: response.status };
  }

  const message = await readProviderMessage(response);
  if (response.status === 401 || response.status === 400) {
    return {
      status: response.status === 401 ? 401 : 400,
      error: message ?? FALLBACK_MESSAGE,
      upstreamStatus: response.status,
    };
  }
  // A provider-side failure: its message may describe internals, so the user
  // gets the generic one.
  return { status: 502, error: FALLBACK_MESSAGE, upstreamStatus: response.status };
}
