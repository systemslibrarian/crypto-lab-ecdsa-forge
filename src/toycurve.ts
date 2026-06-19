/**
 * A *toy* elliptic curve over a tiny prime field, built for teaching.
 *
 * Curve:  y² = x³ + 2x + 2  (mod 17)
 * Order:  n = 19  (prime — so every point generates the whole group and every
 *         non-zero scalar is invertible mod n, which keeps the attack math clean)
 * Base:   G = (5, 1)
 *
 * Every value here is a small integer you can verify by hand. The same algebra
 * runs on the real 256-bit curves in `ecdsa.ts`; only the numbers get bigger.
 *
 * The point at infinity (group identity) is represented as `null`.
 */

export interface ToyPoint {
  x: number;
  y: number;
}

export type ToyMaybePoint = ToyPoint | null; // null === point at infinity (𝒪)

export const TOY = {
  a: 2,
  b: 2,
  p: 17,
  n: 19,
  G: { x: 5, y: 1 } as ToyPoint,
} as const;

export function toyMod(a: number, m: number = TOY.p): number {
  const x = a % m;
  return x < 0 ? x + m : x;
}

/** Modular inverse over a small prime via the extended Euclidean algorithm. */
export function toyModInverse(a: number, m: number): number {
  let [old_r, r] = [toyMod(a, m), m];
  let [old_s, s] = [1, 0];
  while (r !== 0) {
    const q = Math.floor(old_r / r);
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  if (old_r !== 1) throw new Error(`${a} has no inverse mod ${m}`);
  return toyMod(old_s, m);
}

export function isOnCurve(P: ToyMaybePoint): boolean {
  if (P === null) return true;
  const lhs = toyMod(P.y * P.y);
  const rhs = toyMod(P.x * P.x * P.x + TOY.a * P.x + TOY.b);
  return lhs === rhs;
}

export function negate(P: ToyMaybePoint): ToyMaybePoint {
  if (P === null) return null;
  return { x: P.x, y: toyMod(-P.y) };
}

/** Group law: chord-and-tangent addition over F_p. */
export function add(P: ToyMaybePoint, Q: ToyMaybePoint): ToyMaybePoint {
  if (P === null) return Q;
  if (Q === null) return P;
  if (P.x === Q.x && toyMod(P.y + Q.y) === 0) return null; // P + (−P) = 𝒪

  let lambda: number;
  if (P.x === Q.x && P.y === Q.y) {
    // doubling: slope of the tangent
    lambda = toyMod((3 * P.x * P.x + TOY.a) * toyModInverse(2 * P.y, TOY.p));
  } else {
    // chord: slope of the secant
    lambda = toyMod((Q.y - P.y) * toyModInverse(toyMod(Q.x - P.x), TOY.p));
  }
  const x = toyMod(lambda * lambda - P.x - Q.x);
  const y = toyMod(lambda * (P.x - x) - P.y);
  return { x, y };
}

/** Scalar multiplication k·P as repeated addition (double-and-add). */
export function scalarMul(k: number, P: ToyMaybePoint = TOY.G): ToyMaybePoint {
  let result: ToyMaybePoint = null;
  let addend: ToyMaybePoint = P;
  let n = toyMod(k, TOY.n);
  while (n > 0) {
    if (n & 1) result = add(result, addend);
    addend = add(addend, addend);
    n >>= 1;
  }
  return result;
}

/** All finite points on the curve, sorted — used by the discrete-field plot. */
export function allPoints(): ToyPoint[] {
  const pts: ToyPoint[] = [];
  for (let x = 0; x < TOY.p; x += 1) {
    const rhs = toyMod(x * x * x + TOY.a * x + TOY.b);
    for (let y = 0; y < TOY.p; y += 1) {
      if (toyMod(y * y) === rhs) pts.push({ x, y });
    }
  }
  return pts;
}

/** The full cyclic sequence G, 2G, 3G, …, (n−1)G — for the k·G walk plot. */
export function multiplesOfG(): ToyMaybePoint[] {
  const seq: ToyMaybePoint[] = [];
  for (let i = 1; i < TOY.n; i += 1) seq.push(scalarMul(i, TOY.G));
  return seq;
}

export interface ToySignature {
  r: number;
  s: number;
}

export interface ToySignSteps {
  k: number;
  R: ToyMaybePoint;
  r: number;
  e: number;
  d: number;
  kInv: number;
  rd: number;
  s: number;
}

/**
 * Toy ECDSA signing with an explicit nonce k, capturing every intermediate
 * value so the UI can show the full derivation.
 *   R = k·G ;  r = R.x mod n ;  s = k⁻¹·(e + r·d) mod n
 */
export function toySign(d: number, e: number, k: number): ToySignSteps {
  const n = TOY.n;
  const R = scalarMul(k, TOY.G);
  if (R === null) throw new Error('k·G is the identity — pick another nonce');
  const r = toyMod(R.x, n);
  if (r === 0) throw new Error('r == 0 — pick another nonce');
  const kInv = toyModInverse(k, n);
  const rd = toyMod(r * d, n);
  const s = toyMod(kInv * toyMod(e + rd, n), n);
  if (s === 0) throw new Error('s == 0 — pick another nonce');
  return { k, R, r, e, d, kInv, rd, s };
}

/** Toy ECDSA verification: u1·G + u2·Q, then compare x-coord to r. */
export function toyVerify(e: number, sig: ToySignature, Q: ToyMaybePoint): boolean {
  const n = TOY.n;
  const { r, s } = sig;
  if (r <= 0 || r >= n || s <= 0 || s >= n) return false;
  const w = toyModInverse(s, n);
  const u1 = toyMod(e * w, n);
  const u2 = toyMod(r * w, n);
  const point = add(scalarMul(u1, TOY.G), scalarMul(u2, Q));
  if (point === null) return false;
  return toyMod(point.x, n) === r;
}

export interface ToyRecoverySteps {
  r: number;
  sDelta: number;
  eDelta: number;
  k: number;
  rInv: number;
  d: number;
}

/**
 * Recover the private key from two toy signatures that reused a nonce.
 *   k = (e1 − e2)·(s1 − s2)⁻¹ mod n
 *   d = (s1·k − e1)·r⁻¹ mod n
 */
export function toyRecover(
  sig1: ToySignature,
  e1: number,
  sig2: ToySignature,
  e2: number,
): ToyRecoverySteps | null {
  if (sig1.r !== sig2.r) return null;
  const n = TOY.n;
  const r = sig1.r;
  const sDelta = toyMod(sig1.s - sig2.s, n);
  if (sDelta === 0) return null;
  const eDelta = toyMod(e1 - e2, n);
  const k = toyMod(eDelta * toyModInverse(sDelta, n), n);
  const rInv = toyModInverse(r, n);
  const d = toyMod(toyMod(sig1.s * k - e1, n) * rInv, n);
  return { r, sDelta, eDelta, k, rInv, d };
}
