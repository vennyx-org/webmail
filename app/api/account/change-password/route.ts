import { NextRequest, NextResponse } from 'next/server';
import { logger } from '@/lib/logger';
import { rejectCrossOriginRequest } from '@/lib/security/same-origin';
import { getStalwartCredentials } from '@/lib/stalwart/credentials';
import { changePasswordViaProvider, getPasswordChangeUrl } from '@/lib/external-password-change';
import { loginClientAddress } from '@/lib/auth/client-address';
import { createFailureBudget, LOGIN_BUDGET_RETRY_AFTER_SECONDS } from '@/lib/auth/verify-budget';

/**
 * The provider checks `currentPassword`, so this route is a password oracle
 * for the account it names. Only a rejected current password spends the
 * budget, per client address and per account (an attacker rotating addresses
 * still runs out on the account). Same window as the sign-in budget.
 */
const clientBudget = createFailureBudget({ clientMax: 5, globalMax: Infinity });
const accountBudget = createFailureBudget({ clientMax: 5, globalMax: Infinity });

/**
 * POST /api/account/change-password
 *
 * Changes the signed-in account's password through the external provider
 * configured in `PASSWORD_CHANGE_URL` (contract: lib/external-password-change).
 * For a Stalwart fronting a read-only auth directory whose passwords are owned
 * by another system, where JMAP `x:AccountPassword/set` fails "Operation not
 * allowed".
 *
 * Without `PASSWORD_CHANGE_URL` the route does not exist (404): the browser
 * then changes passwords through the Stalwart JMAP passthrough, exactly as
 * upstream does. /api/config tells it which path to take.
 *
 * Body: `{ currentPassword: string, newPassword: string }`. The account is the
 * one whose credentials the session cookie of the requested slot
 * (`X-JMAP-Cookie-Slot`) holds; the body cannot name another. The provider
 * still checks the current password, so the session alone changes nothing.
 * Credentials stay server side and nothing here logs a password.
 *
 * Only sessions against an admin-configured (trusted) JMAP server reach the
 * provider: with ALLOW_CUSTOM_JMAP_ENDPOINT a user could otherwise sign in to
 * a server of their own and have this route test passwords for any address.
 *
 * TOTP is not checked here. The store keeps TOTP-enabled accounts on
 * Stalwart's own path, and the deployments this exists for (a read-only
 * SQL/LDAP directory) cannot enable TOTP on an account at all.
 */
export async function POST(request: NextRequest) {
  // CSRF gate (GHSA-9mvj-98f5-9q6g): this acts with the session cookie.
  const crossOrigin = rejectCrossOriginRequest(request);
  if (crossOrigin) return crossOrigin;

  const providerUrl = getPasswordChangeUrl();
  if (!providerUrl) {
    return NextResponse.json({ error: 'Not found' }, { status: 404 });
  }

  const creds = await getStalwartCredentials(request);
  if (!creds) {
    return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
  }
  if (!creds.trusted) {
    return NextResponse.json({ error: 'Not available for this server' }, { status: 403 });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
  }
  const { currentPassword, newPassword } = (body ?? {}) as { currentPassword?: unknown; newPassword?: unknown };
  if (typeof currentPassword !== 'string' || typeof newPassword !== 'string' || !currentPassword || !newPassword) {
    return NextResponse.json({ error: 'currentPassword and newPassword are required' }, { status: 400 });
  }

  // The name the sign-in resolved to (for Basic auth the exact user the
  // stored credentials authenticate as), not anything the request claims.
  const email = creds.accountName || creds.username;

  const refundClient = clientBudget.reserve(loginClientAddress(request));
  const refundAccount = refundClient ? accountBudget.reserve(email.toLowerCase()) : null;
  if (!refundClient || !refundAccount) {
    refundClient?.();
    return NextResponse.json(
      { error: 'Too many attempts' },
      { status: 429, headers: { 'Retry-After': String(LOGIN_BUDGET_RETRY_AFTER_SECONDS) } },
    );
  }
  const refund = () => { refundClient(); refundAccount(); };

  try {
    const result = await changePasswordViaProvider(providerUrl, email, currentPassword, newPassword);
    // Only a rejected current password spends the budget.
    if (result.status !== 401) refund();
    if (result.status === 200) {
      logger.info('Password changed via external provider', { slot: creds.slot });
      return NextResponse.json({ ok: true });
    }
    if (result.status === 502) {
      logger.warn('External password provider failed', { slot: creds.slot, status: result.upstreamStatus });
    }
    return NextResponse.json({ error: result.error }, { status: result.status });
  } catch (error) {
    refund();
    const err = error as Error & { cause?: { code?: string } };
    logger.error('External password provider unreachable', {
      error: err?.name === 'TimeoutError' ? 'timeout' : err?.message ?? 'Unknown',
      causeCode: err?.cause?.code,
    });
    return NextResponse.json({ error: 'Failed to change password' }, { status: 502 });
  }
}
