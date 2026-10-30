/**
 * Fork: server-managed Sieve scripts that every filters script includes.
 *
 * Only one Sieve script can be active per account. A deployment that keeps
 * its own per-account script (for example one that files mail its mail
 * hook marked as spam into Junk) loses it the moment a user saves a filter
 * or an auto-reply here, because that activates the filters script instead.
 * Naming the script in SIEVE_SERVER_INCLUDES makes every generated filters
 * script start with `include :personal :optional "<name>";`, the same way
 * the vacation script is kept running. `:optional` keeps a script valid on
 * an account that does not have it.
 *
 * Unset (the default), nothing changes: the config response and every
 * generated script stay exactly upstream's.
 */

/** Marks the include block, so the parser does not re-import it as an external rule. */
export const SERVER_INCLUDES_MARKER = '# Server-managed scripts';
export const SERVER_INCLUDES_MARKER_RE = /#\s*Server-managed scripts/i;

/** A Sieve script name we are willing to put in a quoted string unescaped. */
const SCRIPT_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

/** Names from SIEVE_SERVER_INCLUDES (comma-separated), invalid ones dropped. Server side only. */
export function getServerSieveIncludes(): string[] {
  const raw = process.env.SIEVE_SERVER_INCLUDES ?? '';
  const names = raw
    .split(',')
    .map(name => name.trim())
    .filter(name => SCRIPT_NAME_RE.test(name));
  return [...new Set(names)];
}

/** The same check for a list that came back from /api/config. */
export function isServerSieveIncludes(value: unknown): value is string[] {
  return Array.isArray(value) && value.every(name => typeof name === 'string' && SCRIPT_NAME_RE.test(name));
}

const INCLUDE_LINE_RE = /^include\s+:personal\s+:optional\s+"([^"]+)";$/;

/** Names in the script's server-managed include block (the lines right after the marker). */
export function serverIncludeNamesIn(script: string): Set<string> {
  const names = new Set<string>();
  const lines = script.split(/\r?\n/);
  const start = lines.findIndex(line => SERVER_INCLUDES_MARKER_RE.test(line));
  if (start === -1) return names;
  for (const line of lines.slice(start + 1)) {
    const match = line.trim().match(INCLUDE_LINE_RE);
    if (!match) break;
    names.add(match[1]);
  }
  return names;
}

/** True when `raw` holds nothing but includes of `names` (and comments), i.e. a piece of that block. */
export function isServerIncludeBlock(raw: string, names: Set<string>): boolean {
  if (names.size === 0) return false;
  const statements = raw
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(line => line && !line.startsWith('#'));
  return statements.length > 0 && statements.every(line => {
    const match = line.match(INCLUDE_LINE_RE);
    return !!match && names.has(match[1]);
  });
}

