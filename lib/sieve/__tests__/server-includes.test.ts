import { afterEach, describe, expect, it, vi } from 'vitest';
import { parseScript } from '../parser';
import { generateScript } from '../generator';
import { getServerSieveIncludes, isServerSieveIncludes } from '../server-includes';
import type { FilterRule } from '@/lib/jmap/sieve-types';

const rule: FilterRule = {
  id: 'bw-1',
  name: 'Archive',
  enabled: true,
  matchType: 'all',
  conditions: [{ field: 'from', comparator: 'contains', value: 'news@example.com' }],
  actions: [{ type: 'move', value: 'Archive' }],
  stopProcessing: false,
};

const includeLines = (script: string) => script.split('\n').filter(l => l.startsWith('include :personal :optional'));

describe('server-managed Sieve includes (fork)', () => {
  afterEach(() => vi.unstubAllEnvs());

  it('adds nothing when no server includes are configured', () => {
    const script = generateScript([rule], undefined, {});
    expect(script).not.toContain('include');
    expect(script).not.toContain('Server-managed');
  });

  it('includes each server script first, with "include" required', () => {
    const script = generateScript([rule], undefined, { serverIncludes: ['mila-junk-filter', 'other'] });

    expect(includeLines(script)).toEqual([
      'include :personal :optional "mila-junk-filter";',
      'include :personal :optional "other";',
    ]);
    expect(script).toMatch(/require \[[^\]]*"include"/);
    expect(script.indexOf('mila-junk-filter')).toBeLessThan(script.indexOf('# Rule: Archive'));
  });

  it('keeps the includes alongside the vacation include', () => {
    const script = generateScript([], undefined, { serverIncludes: ['mila-junk-filter'], includeVacation: true });
    expect(includeLines(script)).toEqual([
      'include :personal :optional "mila-junk-filter";',
      'include :personal :optional "vacation";',
    ]);
  });

  it('round-trips without importing the includes as external rules or duplicating them', () => {
    const options = { serverIncludes: ['mila-junk-filter', 'other'] };
    let script = generateScript([rule], undefined, options);
    for (let i = 0; i < 3; i++) {
      const parsed = parseScript(script);
      expect(parsed.isOpaque).toBe(false);
      expect(parsed.rules.filter(r => r.origin && r.origin !== 'bulwark')).toEqual([]);
      script = generateScript(parsed.rules, parsed.vacation, { ...options, externalRequires: parsed.externalRequires });
    }
    expect(includeLines(script)).toHaveLength(2);
  });

  it('keeps a user-written include of another script as an external rule', () => {
    const generated = generateScript([rule], undefined, { serverIncludes: ['mila-junk-filter'] });
    const script = `${generated}\n# rule:[Mine]\ninclude :personal :optional "my-own";\n`;
    const parsed = parseScript(script);
    const external = parsed.rules.filter(r => r.origin && r.origin !== 'bulwark');
    expect(external).toHaveLength(1);
    expect(external[0].rawBlock).toContain('"my-own"');
  });

  it('drops the includes once the setting is removed', () => {
    const withIncludes = generateScript([rule], undefined, { serverIncludes: ['mila-junk-filter'] });
    const parsed = parseScript(withIncludes);
    const without = generateScript(parsed.rules, parsed.vacation, { externalRequires: parsed.externalRequires });
    expect(without).not.toContain('include');
  });

  it('never writes a name that could break out of the quoted string', () => {
    const script = generateScript([rule], undefined, { serverIncludes: ['ok-name', 'bad"; discard; #', ''] });
    expect(includeLines(script)).toEqual(['include :personal :optional "ok-name";']);
  });

  it('reads SIEVE_SERVER_INCLUDES, dropping invalid and duplicate names', () => {
    vi.stubEnv('SIEVE_SERVER_INCLUDES', ' mila-junk-filter, ,bad name,mila-junk-filter,x.y_z ');
    expect(getServerSieveIncludes()).toEqual(['mila-junk-filter', 'x.y_z']);
    vi.stubEnv('SIEVE_SERVER_INCLUDES', '');
    expect(getServerSieveIncludes()).toEqual([]);
  });

  it('validates the list /api/config returns', () => {
    expect(isServerSieveIncludes(['mila-junk-filter'])).toBe(true);
    expect(isServerSieveIncludes(['a"b'])).toBe(false);
    expect(isServerSieveIncludes('mila-junk-filter')).toBe(false);
  });
});
