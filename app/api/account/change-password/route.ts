import { NextRequest, NextResponse } from 'next/server';
import { logger } from '@/lib/logger';
import { rejectCrossOriginRequest } from '@/lib/security/same-origin';
import { getStalwartCredentials } from '@/lib/stalwart/credentials';
import { changePasswordViaProvider, getPasswordChangeUrl } from '@/lib/external-password-change';

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

  try {
    const result = await changePasswordViaProvider(providerUrl, email, currentPassword, newPassword);
    if (result.status === 200) {
      logger.info('Password changed via external provider', { slot: creds.slot });
      return NextResponse.json({ ok: true });
    }
    if (result.status === 502) {
      logger.warn('External password provider failed', { slot: creds.slot, status: result.upstreamStatus });
    }
    return NextResponse.json({ error: result.error }, { status: result.status });
  } catch (error) {
    const err = error as Error & { cause?: { code?: string } };
    logger.error('External password provider unreachable', {
      error: err?.name === 'TimeoutError' ? 'timeout' : err?.message ?? 'Unknown',
      causeCode: err?.cause?.code,
    });
    return NextResponse.json({ error: 'Failed to change password' }, { status: 502 });
  }
}
