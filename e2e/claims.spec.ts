import { expect, test, type Locator, type Page } from '@playwright/test';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { p256 } from '@noble/curves/nist.js';

/**
 * Claim gate. The a11y suite proves the page is reachable; this one proves the
 * page is *right*. Every load-bearing statement the demo makes is re-derived
 * here from values the page itself printed, using arithmetic written in this
 * file (extended-Euclid inverses, an independent toy group law, @noble/curves
 * for the 256-bit points) rather than imported from `src/`. So if the recovery
 * formulas in `src/attack.ts` or `src/toycurve.ts` drift, the page's numbers
 * stop agreeing with this file's numbers and these tests go red.
 *
 * Claims covered:
 *   - Exhibit 1: a signature verifies; a tampered message does not.
 *   - Exhibit 2: 18 plotted points + 𝒪 = the claimed group order n = 19, and
 *     the k·G walk visits exactly the plotted set.
 *   - Exhibit 3 (headline): a reused nonce recovers the private key — checked
 *     as recovered d == victim d, d·G == the published public key, and both
 *     captured signatures verifying under that key.
 *   - Exhibit 4: RFC 6979 is reproducible, and the same attack fails against it.
 */

// --- arithmetic, independent of src/ ---------------------------------------

const mod = (a: bigint, n: bigint): bigint => ((a % n) + n) % n;

/** Extended Euclid — deliberately a different algorithm to src/'s Fermat pow. */
function modInv(a: bigint, n: bigint): bigint {
  let [oldR, r] = [mod(a, n), n];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) throw new Error('no inverse');
  return mod(oldS, n);
}

const bitLen = (v: bigint): number => v.toString(2).length;

async function hashToScalar(message: string, n: bigint): Promise<bigint> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(message));
  let v = 0n;
  for (const b of new Uint8Array(digest)) v = (v << 8n) | BigInt(b);
  const excess = 256 - bitLen(n);
  return excess > 0 ? v >> BigInt(excess) : v;
}

const CURVES = { secp256k1, p256 } as const;
type CurveKey = keyof typeof CURVES;

const orderOf = (c: CurveKey): bigint => CURVES[c].Point.Fn.ORDER;

/** x-coordinate of k·G, reduced mod n — i.e. the r a signer with nonce k gets. */
const rOfNonce = (k: bigint, c: CurveKey): bigint =>
  mod(CURVES[c].Point.BASE.multiply(mod(k, orderOf(c))).toAffine().x, orderOf(c));

/** Compressed public key hex for private scalar d. */
function pubHexOf(d: bigint, c: CurveKey): string {
  const bytes = new Uint8Array(32);
  let v = d;
  for (let i = 31; i >= 0; i -= 1) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return Array.from(CURVES[c].getPublicKey(bytes), (b) => b.toString(16).padStart(2, '0')).join('');
}

/** Textbook ECDSA verification, done here rather than in the app. */
function verifySig(e: bigint, r: bigint, s: bigint, d: bigint, c: CurveKey): boolean {
  const n = orderOf(c);
  if (r <= 0n || r >= n || s <= 0n || s >= n) return false;
  const w = modInv(s, n);
  const P = CURVES[c].Point;
  const point = P.BASE.multiply(mod(e * w, n)).add(P.BASE.multiply(mod(d, n)).multiply(mod(r * w, n)));
  if (point.equals(P.ZERO)) return false;
  return mod(point.toAffine().x, n) === r;
}

/** Mirrors the page's shortHex(bigint, size) so displayed strings can be checked. */
function shortHex(value: bigint, size = 12): string {
  const h = value.toString(16);
  return h.length <= size * 2 ? h : `${h.slice(0, size)}...${h.slice(-size)}`;
}

// --- toy curve y² = x³ + 2x + 2 (mod 17), reimplemented here ---------------

const P_TOY = 17;
const N_TOY = 19;
type Pt = { x: number; y: number } | null;

const tmod = (a: number, m: number): number => ((a % m) + m) % m;
const tinv = (a: number, m: number): number => {
  for (let i = 1; i < m; i += 1) if (tmod(a * i, m) === 1) return i;
  throw new Error(`no inverse for ${a} mod ${m}`);
};

function tadd(A: Pt, B: Pt): Pt {
  if (A === null) return B;
  if (B === null) return A;
  if (A.x === B.x && tmod(A.y + B.y, P_TOY) === 0) return null;
  const lam =
    A.x === B.x && A.y === B.y
      ? tmod((3 * A.x * A.x + 2) * tinv(tmod(2 * A.y, P_TOY), P_TOY), P_TOY)
      : tmod((B.y - A.y) * tinv(tmod(B.x - A.x, P_TOY), P_TOY), P_TOY);
  const x = tmod(lam * lam - A.x - B.x, P_TOY);
  return { x, y: tmod(lam * (A.x - x) - A.y, P_TOY) };
}

function tmul(k: number, P: Pt = { x: 5, y: 1 }): Pt {
  let acc: Pt = null;
  for (let i = 0; i < tmod(k, N_TOY); i += 1) acc = tadd(acc, P);
  return acc;
}

function toyVerify(e: number, r: number, s: number, Q: Pt): boolean {
  if (r <= 0 || r >= N_TOY || s <= 0 || s >= N_TOY) return false;
  const w = tinv(s, N_TOY);
  const point = tadd(tmul(tmod(e * w, N_TOY)), tmul(tmod(r * w, N_TOY), Q));
  return point !== null && tmod(point.x, N_TOY) === r;
}

// --- page helpers ----------------------------------------------------------

const textOf = async (page: Page, sel: string): Promise<string> =>
  ((await page.locator(sel).textContent()) ?? '').trim();

/** Trailing "… = 13" on one of the toy panel's mono lines (ignoring a "← …" aside). */
function trailingInt(line: string): number {
  const m = line.split('←')[0].trim().match(/=\s*(-?\d+)$/);
  if (!m) throw new Error(`no trailing integer in: ${line}`);
  return Number(m[1]);
}

async function monoLines(scope: Locator): Promise<string[]> {
  return (await scope.locator('p.mono').allTextContents()).map((t) => t.trim());
}

async function setSlider(page: Page, id: string, value: number): Promise<void> {
  const el = page.locator(id);
  await el.fill(String(value));
  await el.dispatchEvent('input');
}

async function setToy(page: Page, d: number, k: number, e1: number, e2: number): Promise<void> {
  await setSlider(page, '#toy-d', d);
  await setSlider(page, '#toy-k', k);
  await setSlider(page, '#toy-e1', e1);
  await setSlider(page, '#toy-e2', e2);
}

/** Runs the 256-bit compromise and returns everything the page printed. */
async function runCompromise(page: Page, curve: CurveKey) {
  await page.selectOption('#curve-select', curve);
  const before = await textOf(page, '#attack-fullnums');
  await page.click('#btn-attack');
  // Wait for a *new* dump, so a second run cannot be read as the first one.
  await page.waitForFunction(
    ([prev, name]) => {
      const t = document.querySelector('#attack-fullnums')?.textContent ?? '';
      return t !== prev && t.includes(`curve            : ${name}`);
    },
    [before, curve],
  );
  await expect(page.locator('#victim-key')).toHaveClass(/exposed/);
  const dump = await textOf(page, '#attack-fullnums');
  const grab = (label: string): bigint => {
    const m = dump.match(new RegExp(`^${label}[^:]*:\\s*(\\d+)$`, 'm'));
    if (!m) throw new Error(`missing "${label}" in:\n${dump}`);
    return BigInt(m[1]);
  };
  return {
    dump,
    e1: grab('e1 = H\\("Transfer \\$10 to Bob"\\)'),
    e2: grab('e2 = H\\("Transfer \\$20 to Charlie"\\)'),
    n: grab('n \\(order\\)'),
    r: grab('r  \\(shared\\)'),
    s1: grab('s1'),
    s2: grab('s2'),
    k: grab('recovered k'),
    dRecovered: grab('recovered d'),
    dVictim: grab("victim's real d"),
    exposedKeyHex: await textOf(page, '#victim-key'),
    victimPub: await textOf(page, '#victim-pub'),
  };
}

// ---------------------------------------------------------------------------
// Exhibit 1 — sign / verify, and the paths that must fail
// ---------------------------------------------------------------------------

test('Exhibit 1: a signature verifies, a tampered message does not', async ({ page }) => {
  await page.goto('./');
  const status = page.locator('#verify-status');

  await expect(status).toHaveText('Generate a keypair to begin.');
  await expect(page.locator('#public-key')).toHaveText('not generated');
  await expect(page.locator('#sig-view')).toHaveText('none');

  // Failure path: verifying with nothing signed.
  await page.click('#btn-verify');
  await expect(status).toHaveText('Sign something first.');
  await expect(status).toHaveClass(/bad/);

  // Failure path: signing with no key, by either nonce strategy.
  await page.click('#btn-sign-random');
  await expect(status).toHaveText('Generate a keypair first.');
  await expect(status).toHaveClass(/bad/);
  await page.click('#btn-sign-det');
  await expect(status).toHaveText('Generate a keypair first.');

  await page.click('#btn-generate');
  await expect(status).toHaveText('Keypair generated on secp256k1.');
  // Compressed secp256k1 point: 33 bytes, and the page says so.
  await expect(page.locator('#public-key')).toHaveText(/^[0-9a-f]{12}\.\.\.[0-9a-f]{12} \(33 bytes\)$/);

  await page.click('#btn-sign-random');
  await expect(page.locator('#sig-view')).toHaveText(
    /^\([0-9a-f]{12}\.\.\.[0-9a-f]{12}, [0-9a-f]{12}\.\.\.[0-9a-f]{12}\)$/,
  );
  await expect(status).toHaveText('Signature generated with random nonce.');

  await page.click('#btn-verify');
  await expect(status).toHaveText('✓ VALID signature');
  await expect(status).toHaveClass(/ok/);

  // Tamper the signed message: the same signature must now be rejected.
  await page.fill('#msg-sign', 'Authenticated by Mallory');
  await page.click('#btn-verify');
  await expect(status).toHaveText('✗ INVALID signature');
  await expect(status).toHaveClass(/bad/);

  // Restoring the message makes it valid again — proving the rejection above
  // was caused by the tamper and not by a stuck verifier.
  await page.fill('#msg-sign', 'Authenticated by Paul Clark');
  await page.click('#btn-verify');
  await expect(status).toHaveText('✓ VALID signature');
});

test('Exhibit 1: RFC 6979 signing is reproducible, and switching curve resets state', async ({
  page,
}) => {
  await page.goto('./');
  const sig = page.locator('#sig-view');
  const status = page.locator('#verify-status');

  await page.click('#btn-generate');
  await page.click('#btn-sign-det');
  await expect(status).toHaveText('Signature generated with RFC 6979 deterministic nonce.');
  const first = await sig.textContent();
  await page.click('#btn-verify');
  await expect(status).toHaveText('✓ VALID signature');

  // Same key, same message ⇒ byte-identical signature (the RFC 6979 promise).
  await page.click('#btn-sign-det');
  await expect(sig).toHaveText(first!);

  // A different message must move the signature.
  await page.fill('#msg-sign', 'Authenticated by Paul Clark (v2)');
  await page.click('#btn-sign-det');
  await expect(sig).not.toHaveText(first!);
  await page.click('#btn-verify');
  await expect(status).toHaveText('✓ VALID signature');

  // Curve switch clears the old key/signature rather than mixing curves.
  await page.selectOption('#curve-select', 'p256');
  await expect(status).toHaveText('Curve switched to p256. Generate a fresh keypair.');
  await expect(page.locator('#public-key')).toHaveText('not generated');
  await expect(sig).toHaveText('none');
  await page.click('#btn-verify');
  await expect(status).toHaveText('Sign something first.');

  // …and P-256 round-trips too.
  await page.click('#btn-generate');
  await expect(page.locator('#public-key')).toHaveText(/\(33 bytes\)$/);
  await page.click('#btn-sign-det');
  await page.click('#btn-verify');
  await expect(status).toHaveText('✓ VALID signature');
});

// ---------------------------------------------------------------------------
// Exhibit 2 — the plotted group is the group the page claims
// ---------------------------------------------------------------------------

test('Exhibit 2: 18 plotted points + the point at infinity = the claimed order 19', async ({
  page,
}) => {
  await page.goto('./');

  // The page states 18 affine points and prime order n = 19; the plot must agree.
  await expect(page.locator('#viz-discrete circle.vd-dot')).toHaveCount(18);
  await expect(page.locator('#exhibit-geometry .hint')).toContainText('The 18 dots are the affine points');
  await expect(page.locator('#exhibit-geometry .hint')).toContainText('n = 19');

  // Walk k = 1..18 and read the point the page reports for each k.
  const walk: string[] = [];
  for (let k = 1; k <= 18; k += 1) {
    await setSlider(page, '#vd-slider', k);
    const label = await textOf(page, '#vd-label');
    const m = label.match(/^(\d+)·G = \((\d+), (\d+)\)\./);
    expect(m, `unparsed k·G label: ${label}`).not.toBeNull();
    expect(Number(m![1])).toBe(k);
    const point = tmul(k);
    // Independently recomputed here, not read from src/toycurve.ts.
    expect(`${point!.x},${point!.y}`).toBe(`${m![2]},${m![3]}`);
    walk.push(`${m![2]},${m![3]}`);
    await expect(page.locator('#viz-discrete circle.vd-target')).toHaveCount(1);
  }

  // Parts sum to the whole: the 18 multiples of G are distinct and are exactly
  // the 18 plotted dots, so with 𝒪 the group has the stated order 19.
  expect(new Set(walk).size).toBe(18);
  const plotted = await page.locator('#viz-discrete circle.vd-dot').evaluateAll((nodes) =>
    nodes.map((n) => `${n.getAttribute('cx')},${n.getAttribute('cy')}`),
  );
  const targetsSeen = new Set<string>();
  for (let k = 1; k <= 18; k += 1) {
    await setSlider(page, '#vd-slider', k);
    const t = await page
      .locator('#viz-discrete circle.vd-target')
      .evaluate((n) => `${n.getAttribute('cx')},${n.getAttribute('cy')}`);
    targetsSeen.add(t);
    expect(plotted, `k=${k} highlights a point that is not plotted`).toContain(t);
  }
  expect(targetsSeen.size).toBe(18);
  expect(new Set(plotted).size).toBe(18);
  expect(targetsSeen.size + 1).toBe(19); // + 𝒪 = n

  // 18·G must be −G: same x, y values summing to the field prime 17.
  expect(tmul(18)).toEqual({ x: 5, y: 16 });
  expect(tmul(1)!.y + tmul(18)!.y).toBe(P_TOY);
});

test('Exhibit 2: the real-curve panel reports the point it draws, for chords and tangents', async ({
  page,
}) => {
  await page.goto('./');
  await expect(page.locator('#vc-label')).toContainText('P + Q = (');
  const chord = await textOf(page, '#vc-label');

  await page.locator('#vc-double').check();
  await expect(page.locator('#vc-label')).toContainText('Doubling: 2P = (');
  const tangent = await textOf(page, '#vc-label');
  expect(tangent).not.toBe(chord);
  await expect(page.locator('#viz-continuous svg')).toHaveAttribute('aria-label', /Doubling P/);

  // Moving P must move the reported sum.
  await setSlider(page, '#vc-slider', 3.5);
  await expect(page.locator('#vc-label')).not.toHaveText(tangent);
  await page.locator('#vc-double').uncheck();
  await expect(page.locator('#viz-continuous svg')).toHaveAttribute('aria-label', /Adding P and Q/);
});

// ---------------------------------------------------------------------------
// Exhibit 3 — the headline: nonce reuse really recovers the key
// ---------------------------------------------------------------------------

for (const curve of ['secp256k1', 'p256'] as CurveKey[]) {
  test(`Exhibit 3: nonce reuse recovers the victim key on ${curve}`, async ({ page }) => {
    await page.goto('./');
    await expect(page.locator('#victim-key')).toHaveClass(/censored/);
    await expect(page.locator('#step1')).toHaveText('Waiting...');

    const run = await runCompromise(page, curve);
    const n = orderOf(curve);
    expect(run.n).toBe(n);

    // 1. The page's own verdict: recovered d equals the victim's real d. Both
    //    numbers come from this run, nothing is hardcoded.
    expect(run.dRecovered).toBe(run.dVictim);
    expect(run.dump).toContain('✓ identical — private key fully recovered');
    await expect(page.locator('#step4')).toContainText("This equals Alice's real private key.");

    // 2. Recompute the recovery independently from the published values only
    //    (r, s1, s2, e1, e2) — the attacker's view.
    const k = mod((run.e1 - run.e2) * modInv(mod(run.s1 - run.s2, n), n), n);
    const d = mod((run.s1 * k - run.e1) * modInv(run.r, n), n);
    expect(k).toBe(run.k);
    expect(d).toBe(run.dVictim);

    // 3. The recovered nonce is the nonce that actually produced r: r = (k·G).x.
    expect(rOfNonce(run.k, curve)).toBe(run.r);

    // 4. The recovered key derives the public key the page published for Alice.
    const pub = pubHexOf(run.dRecovered, curve);
    expect(pub).toHaveLength(66);
    expect(run.victimPub).toBe(`${pub.slice(0, 18)}...${pub.slice(-18)}`);

    // 5. Both captured signatures verify under that key — they are real ECDSA
    //    signatures, not props.
    expect(verifySig(run.e1, run.r, run.s1, run.dRecovered, curve)).toBe(true);
    expect(verifySig(run.e2, run.r, run.s2, run.dRecovered, curve)).toBe(true);
    // …and neither verifies against the other's message hash.
    expect(verifySig(run.e2, run.r, run.s1, run.dRecovered, curve)).toBe(false);

    // 6. The hashes shown are the SHA-256 of the messages named in step 1.
    expect(run.e1).toBe(await hashToScalar('Transfer $10 to Bob', n));
    expect(run.e2).toBe(await hashToScalar('Transfer $20 to Charlie', n));
    expect(run.e1).not.toBe(run.e2);

    // 7. The exposed private key is the recovered scalar, zero-padded to 32 bytes.
    expect(run.exposedKeyHex).toBe(run.dRecovered.toString(16).padStart(64, '0'));

    // 8. The timeline's truncated values match the full values in the dump.
    await expect(page.locator('#step2')).toContainText(`share the same r = ${shortHex(run.r)}`);
    await expect(page.locator('#step1')).toContainText(`r=${shortHex(run.r)}`);
    await expect(page.locator('#step1')).toContainText(`s1=${shortHex(run.s1)}`);
    await expect(page.locator('#step1')).toContainText(`s2=${shortHex(run.s2)}`);
    await expect(page.locator('#step3')).toContainText(shortHex(run.k, 16));
    await expect(page.locator('#step4')).toContainText(shortHex(run.dRecovered, 16));

    // 9. The forgery is accepted under the victim's key.
    await expect(page.locator('#step5')).toContainText('TRUE — forgery accepted.');
    await expect(page.locator('#step5')).toContainText('Transfer $1,000,000 to Eve');
  });
}

test('Exhibit 3: two runs use fresh victims — the demo is not replaying one canned key', async ({
  page,
}) => {
  await page.goto('./');
  const first = await runCompromise(page, 'secp256k1');
  const second = await runCompromise(page, 'secp256k1');
  expect(second.dVictim).not.toBe(first.dVictim);
  expect(second.r).not.toBe(first.r);
  // Same messages, so the hashes are stable across runs even though keys are not.
  expect(second.e1).toBe(first.e1);
  expect(second.dRecovered).toBe(second.dVictim);
});

// ---------------------------------------------------------------------------
// Exhibit 3 (toy) — every displayed integer re-derived here
// ---------------------------------------------------------------------------

async function readToyPanel(page: Page) {
  const out = page.locator('#toy-attack-output');
  const header = (await out.locator('p.mono').first().textContent()) ?? '';
  const qm = header.match(/Q = (\d+)·G = \((\d+), (\d+)\)/);
  if (!qm) throw new Error(`unparsed Q line: ${header}`);
  const card1 = await monoLines(out.locator('.step-card').nth(0));
  const card2 = await monoLines(out.locator('.step-card').nth(1));
  const recover = await monoLines(out.locator('.recover-card').nth(0));
  const forgeLines = await monoLines(out.locator('.recover-card').nth(1));
  const fm = forgeLines[0].match(/e₃ = (\d+) with d = (\d+) and a new nonce k′ = (\d+) → \(r, s\) = \((\d+), (\d+)\)/);
  if (!fm) throw new Error(`unparsed forgery line: ${forgeLines[0]}`);
  return {
    dShown: Number(qm[1]),
    Q: { x: Number(qm[2]), y: Number(qm[3]) },
    r1: trailingInt(card1[0]),
    s1: trailingInt(card1[1]),
    sig1Valid: card1[2].endsWith('valid'),
    r2: trailingInt(card2[0]),
    s2: trailingInt(card2[1]),
    sig2Valid: card2[2].endsWith('valid'),
    kRecovered: trailingInt(recover[0]),
    dRecovered: trailingInt(recover[1]),
    forgedHash: Number(fm[1]),
    forgedWithD: Number(fm[2]),
    forgedNonce: Number(fm[3]),
    forgedR: Number(fm[4]),
    forgedS: Number(fm[5]),
    forgeryAccepted: forgeLines[1].trim().endsWith('accepted'),
    badge: (await out.locator('.badge').textContent()) ?? '',
  };
}

test('Toy attack: every displayed integer is correct, and the recovered key is the real key', async ({
  page,
}) => {
  await page.goto('./');

  const cases: Array<[number, number, number, number]> = [
    [7, 11, 5, 9],
    [3, 4, 0, 13],
    [18, 15, 12, 1],
    [1, 2, 18, 3],
  ];

  for (const [d, k, e1, e2] of cases) {
    await setToy(page, d, k, e1, e2);
    await expect(page.locator('#toy-attack-output .badge.ok')).toHaveCount(1);
    const p = await readToyPanel(page);
    const label = `d=${d} k=${k} e1=${e1} e2=${e2}`;

    // The published key really is d·G.
    expect(p.dShown, label).toBe(d);
    expect(p.Q, label).toEqual(tmul(d));

    // r and both s values match signing done here, from scratch.
    const r = tmod(tmul(k)!.x, N_TOY);
    const kInv = tinv(k, N_TOY);
    expect(p.r1, label).toBe(r);
    expect(p.r2, label).toBe(r); // reused nonce ⇒ identical r, the public tell
    expect(p.s1, label).toBe(tmod(kInv * tmod(e1 + r * d, N_TOY), N_TOY));
    expect(p.s2, label).toBe(tmod(kInv * tmod(e2 + r * d, N_TOY), N_TOY));
    await expect(page.locator('#toy-attack-output .tell')).toContainText('same r! nonce reused');

    // Both captured signatures verify — checked here, not taken on trust.
    expect(p.sig1Valid, label).toBe(true);
    expect(p.sig2Valid, label).toBe(true);
    expect(toyVerify(e1, p.r1, p.s1, p.Q), label).toBe(true);
    expect(toyVerify(e2, p.r2, p.s2, p.Q), label).toBe(true);

    // The recovery: k and d re-derived from the public values alone.
    const kRec = tmod(tmod(e1 - e2, N_TOY) * tinv(tmod(p.s1 - p.s2, N_TOY), N_TOY), N_TOY);
    const dRec = tmod(tmod(p.s1 * kRec - e1, N_TOY) * tinv(r, N_TOY), N_TOY);
    expect(p.kRecovered, label).toBe(kRec);
    expect(p.kRecovered, label).toBe(k); // the actual reused nonce
    expect(p.dRecovered, label).toBe(dRec);
    expect(p.dRecovered, label).toBe(d); // the actual private key
    expect(p.badge, label).toContain(`Recovered d = ${d} equals the real private key d = ${d}`);

    // The forgery: a fresh hash, a *different* nonce, and a signature that
    // verifies under the victim's published Q.
    expect(p.forgedWithD, label).toBe(d);
    expect(p.forgedNonce, label).not.toBe(k);
    expect(p.forgedHash, label).toBe(tmod(e1 + e2 + 3, N_TOY));
    expect(p.forgeryAccepted, label).toBe(true);
    expect(toyVerify(p.forgedHash, p.forgedR, p.forgedS, p.Q), label).toBe(true);
    // A forged signature is bound to its hash: reuse it on another hash and it fails.
    expect(toyVerify(tmod(p.forgedHash + 1, N_TOY), p.forgedR, p.forgedS, p.Q), label).toBe(false);
  }
});

test('Toy attack: every failure path is reachable and says why', async ({ page }) => {
  await page.goto('./');
  const out = page.locator('#toy-attack-output');

  // 1. Identical hashes: the two equations collapse into one.
  await setToy(page, 7, 11, 5, 5);
  await expect(out.locator('.status.bad')).toHaveText(
    'Pick two different messages: the attack needs distinct hashes e₁ ≠ e₂.',
  );
  await expect(out.locator('.badge')).toHaveCount(0);

  // 2. Nonce with r == 0 (k·G lands on x = 0, which is on this curve).
  expect(tmod(tmul(7)!.x, N_TOY)).toBe(0);
  await setToy(page, 7, 7, 5, 9);
  await expect(out.locator('.status.bad')).toHaveText(
    'Degenerate nonce: r == 0 — pick another nonce. Try another k.',
  );

  // 3. Nonce with s == 0: e + r·d ≡ 0 (mod n) for the first signature.
  const rFor11 = tmod(tmul(11)!.x, N_TOY);
  expect(tmod(4 + rFor11 * 7, N_TOY)).toBe(0);
  await setToy(page, 7, 11, 4, 9);
  await expect(out.locator('.status.bad')).toHaveText(
    'Degenerate nonce: s == 0 — pick another nonce. Try another k.',
  );
  await expect(out.locator('.badge')).toHaveCount(0);

  // Recovering afterwards proves the panel is not stuck in the failure state.
  await setToy(page, 7, 11, 5, 9);
  await expect(out.locator('.badge.ok')).toContainText('The secret is fully exposed.');
  await expect(out.locator('.status.bad')).toHaveCount(0);
});

// ---------------------------------------------------------------------------
// Exhibit 4 — RFC 6979 as the fix
// ---------------------------------------------------------------------------

test('Exhibit 4: deterministic nonces repeat r for one message and never across messages', async ({
  page,
}) => {
  await page.goto('./');
  const randomList = page.locator('#random-list li');
  const detList = page.locator('#det-list li');

  // The warmup entry lands asynchronously; clear the slate first.
  await expect(detList).toHaveCount(1);
  await page.click('#btn-reset-sample');
  await expect(detList).toHaveCount(0);
  await expect(randomList).toHaveCount(0);
  await expect(page.locator('#safe-attack-status')).toHaveText('No test run yet.');

  const rOf = (line: string): string => {
    const m = line.match(/r=([0-9a-f.]+),/);
    if (!m) throw new Error(`no r in ${line}`);
    return m[1];
  };

  // Same message twice under RFC 6979 ⇒ identical k, r and s.
  await page.click('#btn-det-sample');
  await expect(detList).toHaveCount(1);
  await page.click('#btn-det-sample');
  await expect(detList).toHaveCount(2);
  const det = await detList.allTextContents();
  expect(det[0]).toBe(det[1]);
  expect(det[0]).toMatch(/^k=[0-9a-f]{12}\.\.\.[0-9a-f]{12}, r=/);

  // A different message ⇒ a different nonce ⇒ a different r. This is exactly
  // why the nonce-reuse attack has nothing to grab.
  await page.fill('#msg-compare', 'Nonce discipline is survival. (2)');
  await page.click('#btn-det-sample');
  await expect(detList).toHaveCount(3);
  const detAfter = await detList.allTextContents();
  expect(rOf(detAfter[0])).not.toBe(rOf(detAfter[1]));

  // Random nonces move r even for one fixed message.
  await page.click('#btn-random-sample');
  await expect(randomList).toHaveCount(1);
  await page.click('#btn-random-sample');
  await expect(randomList).toHaveCount(2);
  const rnd = await randomList.allTextContents();
  expect(rOf(rnd[0])).not.toBe(rOf(rnd[1]));

  // Counter consistency: every sample click produced exactly one row, split
  // across the two lists with nothing lost or double-counted.
  const totalClicks = 3 + 2;
  expect((await detList.count()) + (await randomList.count())).toBe(totalClicks);
  expect(await detList.count()).toBe(3);
  expect(await randomList.count()).toBe(2);

  // Reset empties both lists and the verdict together.
  await page.click('#btn-reset-sample');
  await expect(detList).toHaveCount(0);
  await expect(randomList).toHaveCount(0);
});

test('Exhibit 4: the nonce-reuse attack fails against RFC 6979 and says why', async ({ page }) => {
  await page.goto('./');
  const status = page.locator('#safe-attack-status');
  await expect(status).toHaveText('No test run yet.');

  await page.click('#btn-safe-attack');
  await expect(status).toContainText('Attack blocked by construction');
  await expect(status).toContainText('different messages ⇒ different nonces ⇒ r1 ≠ r2');
  await expect(status).toContainText('there is no shared nonce to exploit');
  await expect(status).toHaveClass(/ok/);
  // The failure branch must not be what we are reading.
  await expect(status).not.toContainText('Unexpected result');

  // The order it prints is the real secp256k1 order, truncated as the page does.
  await expect(status).toContainText(`n=${shortHex(orderOf('secp256k1'), 14)}`);

  // Same verdict on P-256, with that curve's order.
  await page.selectOption('#curve-select', 'p256');
  await page.click('#btn-safe-attack');
  await expect(status).toContainText('Attack blocked by construction');
  await expect(status).toContainText(`n=${shortHex(orderOf('p256'), 14)}`);
  await expect(status).toHaveClass(/ok/);
});
