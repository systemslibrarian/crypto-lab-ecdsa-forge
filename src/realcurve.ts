/**
 * Continuous (real-number) elliptic-curve geometry for the "how points add"
 * visualization. Uses the secp256k1 shape  y² = x³ + 7  over the reals so the
 * chord-and-tangent group law is visible as actual lines and reflections.
 *
 * This is geometry for intuition only — real ECDSA works over a finite field
 * (see toycurve.ts), where the same algebra holds but the "curve" is a scatter
 * of points with no picture.
 */

export const A = 0;
export const B = 7;

/** The valid x-domain: x³ + 7 ≥ 0  ⇒  x ≥ −∛7. */
export const X_MIN = -Math.cbrt(B); // ≈ −1.913

/** Upper-branch y for a given x (returns null left of the curve's start). */
export function curveY(x: number): number | null {
  const yy = x * x * x + A * x + B;
  if (yy < 0) return null;
  return Math.sqrt(yy);
}

export interface RealPoint {
  x: number;
  y: number;
}

export interface RealAddition {
  P: RealPoint;
  Q: RealPoint;
  /** Third intersection of the line PQ with the curve (before reflection). */
  third: RealPoint;
  /** R = P + Q, the reflection of `third` across the x-axis. */
  sum: RealPoint;
  slope: number;
  doubling: boolean;
}

/**
 * Real point addition via chord-and-tangent.
 * - distinct P, Q  → secant slope (Qy−Py)/(Qx−Px)
 * - P == Q (double) → tangent slope (3x²+A)/(2y)
 */
export function addReal(P: RealPoint, Q: RealPoint): RealAddition {
  const doubling = P.x === Q.x && P.y === Q.y;
  const slope = doubling
    ? (3 * P.x * P.x + A) / (2 * P.y)
    : (Q.y - P.y) / (Q.x - P.x);
  const xr = slope * slope - P.x - Q.x;
  // y on the line at xr is the third intersection; P+Q reflects it over the x-axis.
  const yLine = slope * (xr - P.x) + P.y;
  return {
    P,
    Q,
    third: { x: xr, y: yLine },
    sum: { x: xr, y: -yLine },
    slope,
    doubling,
  };
}
