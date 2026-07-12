/**
 * Proves the toy curve is a valid teaching surrogate: correct group structure,
 * working ECDSA, and a successful nonce-reuse key recovery — all on integers
 * small enough to check by hand.
 */
import { describe, it, expect } from 'vitest';
import {
  TOY,
  add,
  allPoints,
  isOnCurve,
  multiplesOfG,
  negate,
  scalarMul,
  toyRecover,
  toySign,
  toyVerify,
} from '../src/toycurve';

describe('toy curve group structure', () => {
  it('generator is on the curve', () => {
    expect(isOnCurve(TOY.G)).toBe(true);
  });

  it('has 18 finite points (order n = 19 counting 𝒪)', () => {
    expect(allPoints().length).toBe(18);
  });

  it('every point lies on the curve', () => {
    expect(allPoints().every(isOnCurve)).toBe(true);
  });

  it('n·G = 𝒪 (identity)', () => {
    expect(scalarMul(TOY.n, TOY.G)).toBeNull();
  });

  it('G has full order n (no earlier multiple is 𝒪)', () => {
    const earlier = Array.from({ length: TOY.n - 1 }, (_, i) => scalarMul(i + 1, TOY.G));
    expect(earlier.every((P) => P !== null)).toBe(true);
  });

  it('G generates all 18 finite points', () => {
    const seq = multiplesOfG();
    const distinct = new Set(seq.map((P) => (P ? `${P.x},${P.y}` : 'O')));
    expect(distinct.size).toBe(18);
  });

  it('P + (−P) = 𝒪', () => {
    expect(add(TOY.G, negate(TOY.G))).toBeNull();
  });
});

describe('toy ECDSA sign + verify', () => {
  const d = 7; // private key
  const Q = scalarMul(d, TOY.G); // public key
  const e = 5; // message hash (toy)
  const sig = toySign(d, e, 11);

  it('a valid signature verifies', () => {
    expect(toyVerify(e, { r: sig.r, s: sig.s }, Q)).toBe(true);
  });

  it('the wrong message fails to verify (forgery rejected)', () => {
    expect(toyVerify(e + 1, { r: sig.r, s: sig.s }, Q)).toBe(false);
  });
});

describe('toy nonce-reuse key recovery', () => {
  const d = 7;
  const k = 11; // the reused nonce
  const e1 = 5;
  const e2 = 9;
  const s1 = toySign(d, e1, k);
  const s2 = toySign(d, e2, k);

  it('a reused nonce produces identical r', () => {
    expect(s1.r).toBe(s2.r);
  });

  it('recovers both the nonce and the private key', () => {
    const rec = toyRecover({ r: s1.r, s: s1.s }, e1, { r: s2.r, s: s2.s }, e2);
    expect(rec).not.toBeNull();
    expect(rec?.k).toBe(k);
    expect(rec?.d).toBe(d);
  });

  // Exhaustive: recovery works for EVERY (d, k, e1, e2) where it is defined.
  it('succeeds across ALL valid (d, k, e1, e2)', () => {
    let exhaustiveOk = true;
    for (let dd = 1; dd < TOY.n; dd += 1) {
      for (let kk = 1; kk < TOY.n; kk += 1) {
        for (let a = 0; a < TOY.n; a += 1) {
          for (let bb = 0; bb < TOY.n; bb += 1) {
            if (a === bb) continue; // need distinct messages
            let g1: ReturnType<typeof toySign>;
            let g2: ReturnType<typeof toySign>;
            try {
              g1 = toySign(dd, a, kk);
              g2 = toySign(dd, bb, kk);
            } catch {
              continue; // degenerate r==0 / s==0 nonce — real ECDSA rejects these too
            }
            if (g1.s === g2.s) continue; // s1 == s2 ⇒ singular, skip
            const r = toyRecover({ r: g1.r, s: g1.s }, a, { r: g2.r, s: g2.s }, bb);
            if (!r || r.d !== dd || r.k !== kk) exhaustiveOk = false;
          }
        }
      }
    }
    expect(exhaustiveOk).toBe(true);
  });
});
