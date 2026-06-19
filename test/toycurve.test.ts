/**
 * Proves the toy curve is a valid teaching surrogate: correct group structure,
 * working ECDSA, and a successful nonce-reuse key recovery — all on integers
 * small enough to check by hand.
 *
 * Run: npx tsx test/toycurve.test.ts
 */
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

let failures = 0;
function check(name: string, cond: boolean): void {
  if (cond) {
    console.log(`  ok  ${name}`);
  } else {
    failures += 1;
    console.error(`FAIL  ${name}`);
  }
}

// --- Group structure --------------------------------------------------------
check('generator is on the curve', isOnCurve(TOY.G));
check('finite point count is 18 (order n = 19 with 𝒪)', allPoints().length === 18);
check('every point lies on the curve', allPoints().every(isOnCurve));
check('n·G = 𝒪 (identity)', scalarMul(TOY.n, TOY.G) === null);
check('G has full order n (no earlier multiple is 𝒪)',
  Array.from({ length: TOY.n - 1 }, (_, i) => scalarMul(i + 1, TOY.G)).every((P) => P !== null));

const seq = multiplesOfG();
const distinct = new Set(seq.map((P) => (P ? `${P.x},${P.y}` : 'O')));
check('G generates all 18 finite points', distinct.size === 18);

// P + (−P) = 𝒪
check('P + (−P) = 𝒪', add(TOY.G, negate(TOY.G)) === null);

// --- ECDSA sign + verify ----------------------------------------------------
const d = 7; // private key
const Q = scalarMul(d, TOY.G); // public key
const e = 5; // message hash (toy)
const sig = toySign(d, e, 11);
check('valid signature verifies', toyVerify(e, { r: sig.r, s: sig.s }, Q) === true);
check('wrong message fails to verify', toyVerify(e + 1, { r: sig.r, s: sig.s }, Q) === false);

// --- Nonce-reuse recovery ---------------------------------------------------
const k = 11; // the reused nonce
const e1 = 5;
const e2 = 9;
const s1 = toySign(d, e1, k);
const s2 = toySign(d, e2, k);
check('reused nonce produces identical r', s1.r === s2.r);
const rec = toyRecover({ r: s1.r, s: s1.s }, e1, { r: s2.r, s: s2.s }, e2);
check('recovery returns a result', rec !== null);
check('recovered nonce equals real k', rec?.k === k);
check('recovered private key equals real d', rec?.d === d);

// Exhaustive: recovery works for EVERY (d, k, e1, e2) where it is defined.
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
check('recovery succeeds across ALL valid (d, k, e1, e2)', exhaustiveOk);

console.log(failures === 0 ? '\nALL TOY-CURVE CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
if (failures > 0) process.exit(1);
