/* What "audited" covers for the @noble/curves this lab ships.
 *
 * The README said "Uses @noble/curves for audited field arithmetic", with no
 * version. The library records its latest independent audit as "at version
 * 2.3.0, in Aug 2026, by [Trail of Bits]", scope "everything"; this lab pins
 * ^2.4.0, one release past it.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const read = (rel: string) => readFileSync(new URL(rel, import.meta.url), 'utf8');
const nobleReadme = read('../node_modules/@noble/curves/README.md');
const readmeSource = read('../README.md');
const pkg = JSON.parse(read('../package.json'));

describe('the @noble/curves audit claim', () => {
  it('pins a version later than the latest audit the library records', () => {
    expect(pkg.dependencies['@noble/curves']).toBe('^2.4.0');
    expect(nobleReadme).toContain('The library has been audited');
    expect(nobleReadme).toMatch(/at version 2\.3\.0, in Aug 2026, by \[Trail of Bits\]/);
    expect(nobleReadme).not.toMatch(/at version 2\.4\.\d+, in [A-Z]/);
  });

  it('states that version in the README', () => {
    const flat = readmeSource.replace(/\s+/g, ' ');
    expect(flat).not.toContain('for audited field arithmetic');
    expect(flat).toContain('at version 2.3.0, in Aug 2026, by [Trail of Bits]');
    expect(flat).toContain('pinned `^2.4.0`');
  });
});
