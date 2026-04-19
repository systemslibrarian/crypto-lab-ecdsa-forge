import { secp256k1 } from '@noble/curves/secp256k1.js';
import { p256 } from '@noble/curves/nist.js';

export type CurveName = 'secp256k1' | 'p256';

export interface ECDSAKeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  curve: CurveName;
}

export interface ECDSASignature {
  r: bigint;
  s: bigint;
  curve: CurveName;
}

type CurveAPI = typeof secp256k1;

const BYTE_SIZE = 32;
const EIGHT_BITS = 8n;

function getCurve(curve: CurveName): CurveAPI {
  return curve === 'secp256k1' ? secp256k1 : p256;
}

function mod(a: bigint, n: bigint): bigint {
  const x = a % n;
  return x >= 0n ? x : x + n;
}

function bitLength(value: bigint): number {
  return value.toString(2).length;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let out = 0n;
  for (const b of bytes) {
    out = (out << EIGHT_BITS) | BigInt(b);
  }
  return out;
}

export function bigIntToBytes(value: bigint, size = BYTE_SIZE): Uint8Array {
  const out = new Uint8Array(size);
  let v = value;
  for (let i = size - 1; i >= 0; i -= 1) {
    out[i] = Number(v & 0xffn);
    v >>= EIGHT_BITS;
  }
  return out;
}

function randomScalar(n: bigint): bigint {
  const bytes = new Uint8Array(BYTE_SIZE);
  while (true) {
    crypto.getRandomValues(bytes);
    const candidate = bytesToBigInt(bytes);
    if (candidate > 0n && candidate < n) {
      return candidate;
    }
  }
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  if (modulus <= 0n) {
    throw new Error('modulus must be positive');
  }
  let result = 1n;
  let b = mod(base, modulus);
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) {
      result = mod(result * b, modulus);
    }
    b = mod(b * b, modulus);
    e >>= 1n;
  }
  return result;
}

/**
 * Generate an ECDSA keypair for the chosen curve.
 */
export function generateKeyPair(curve: CurveName): ECDSAKeyPair {
  const c = getCurve(curve);
  const n = c.Point.Fn.ORDER;
  const d = randomScalar(n);
  const privateKey = bigIntToBytes(d, BYTE_SIZE);
  const publicKey = c.getPublicKey(privateKey);
  return { privateKey, publicKey, curve };
}

/**
 * Compute SHA-256 of a message, truncated to the curve's bit length.
 */
export async function hashMessage(
  message: Uint8Array,
  curve: CurveName,
): Promise<bigint> {
  const digest = await crypto.subtle.digest('SHA-256', message as unknown as BufferSource);
  const digestInt = bytesToBigInt(new Uint8Array(digest));
  const nBits = bitLength(curveOrder(curve));
  const digestBits = 256;
  if (digestBits > nBits) {
    return digestInt >> BigInt(digestBits - nBits);
  }
  return digestInt;
}

/**
 * Modular inverse using Fermat's little theorem (for prime modulus).
 * a^(-1) mod n = a^(n-2) mod n  (when n is prime)
 */
export function modInverse(a: bigint, n: bigint): bigint {
  const value = mod(a, n);
  if (value === 0n) {
    throw new Error('zero has no modular inverse');
  }
  return modPow(value, n - 2n, n);
}

/**
 * ECDSA sign with CALLER-PROVIDED nonce k.
 * This is the primitive — the dangerous one.
 * Exposed specifically so the demo can show nonce reuse.
 */
export async function signWithNonce(
  message: Uint8Array,
  keyPair: ECDSAKeyPair,
  k: bigint,
): Promise<ECDSASignature> {
  const c = getCurve(keyPair.curve);
  const n = c.Point.Fn.ORDER;
  const nonce = mod(k, n);
  if (nonce <= 0n) {
    throw new Error('nonce must be in [1, n-1]');
  }
  const e = await hashMessage(message, keyPair.curve);
  const rPoint = c.Point.BASE.multiply(nonce).toAffine();
  const r = mod(rPoint.x, n);
  if (r === 0n) {
    throw new Error('invalid nonce: r == 0');
  }
  const d = bytesToBigInt(keyPair.privateKey);
  const kinv = modInverse(nonce, n);
  const s = mod(kinv * mod(e + r * d, n), n);
  if (s === 0n) {
    throw new Error('invalid nonce: s == 0');
  }
  return { r, s, curve: keyPair.curve };
}

/**
 * ECDSA sign with random nonce (uses crypto.getRandomValues).
 * This is what naive implementations do — vulnerable if RNG is weak.
 */
export async function signRandom(
  message: Uint8Array,
  keyPair: ECDSAKeyPair,
): Promise<ECDSASignature> {
  const n = curveOrder(keyPair.curve);
  while (true) {
    const k = randomScalar(n);
    try {
      return await signWithNonce(message, keyPair, k);
    } catch {
      // Retry on astronomically rare invalid r/s outcomes.
    }
  }
}

/**
 * ECDSA verify.
 * Returns true iff signature is valid.
 */
export async function verify(
  message: Uint8Array,
  signature: ECDSASignature,
  publicKey: Uint8Array,
  curve: CurveName,
): Promise<boolean> {
  if (signature.curve !== curve) {
    return false;
  }
  const c = getCurve(curve);
  const n = c.Point.Fn.ORDER;
  const { r, s } = signature;
  if (r <= 0n || r >= n || s <= 0n || s >= n) {
    return false;
  }

  const e = await hashMessage(message, curve);
  const w = modInverse(s, n);
  const u1 = mod(e * w, n);
  const u2 = mod(r * w, n);

  const q = c.Point.fromBytes(publicKey);
  const point = c.Point.BASE.multiply(u1).add(q.multiply(u2));
  if (point.equals(c.Point.ZERO)) {
    return false;
  }
  const x = mod(point.toAffine().x, n);
  return x === r;
}

/**
 * Get the curve order n for a given curve.
 */
export function curveOrder(curve: CurveName): bigint {
  return getCurve(curve).Point.Fn.ORDER;
}

/**
 * Scalar multiplication: k · G on the chosen curve.
 * Returns the point (x, y).
 */
export function scalarMulG(k: bigint, curve: CurveName): { x: bigint; y: bigint } {
  const c = getCurve(curve);
  const n = c.Point.Fn.ORDER;
  const scalar = mod(k, n);
  if (scalar === 0n) {
    throw new Error('scalar cannot be zero');
  }
  const p = c.Point.BASE.multiply(scalar).toAffine();
  return { x: p.x, y: p.y };
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

export function textToBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function hex(value: bigint | Uint8Array): string {
  if (value instanceof Uint8Array) {
    return Array.from(value, (b) => b.toString(16).padStart(2, '0')).join('');
  }
  return value.toString(16);
}

export function privateKeyToBigInt(privateKey: Uint8Array): bigint {
  return bytesToBigInt(privateKey);
}
