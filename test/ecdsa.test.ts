/**
 * Real 256-bit ECDSA core: sign/verify round-trips, forgery rejection, and the
 * modular-arithmetic helpers the protocol is built on. Covers both curves the
 * demo advertises (secp256k1 and P-256).
 */
import { describe, it, expect } from 'vitest';
import {
  type CurveName,
  generateKeyPair,
  modInverse,
  signRandom,
  signWithNonce,
  curveOrder,
  textToBytes,
  verify,
} from '../src/ecdsa';

const CURVES: CurveName[] = ['secp256k1', 'p256'];

describe('modInverse (Fermat, prime modulus)', () => {
  it('computes correct small inverses', () => {
    expect(modInverse(3n, 11n)).toBe(4n); // 3*4 = 12 ≡ 1 mod 11
    expect(modInverse(7n, 13n)).toBe(2n); // 7*2 = 14 ≡ 1 mod 13
  });

  it('throws on zero', () => {
    expect(() => modInverse(0n, 13n)).toThrow();
  });
});

describe.each(CURVES)('ECDSA on %s', (curve) => {
  const msg = textToBytes('Authenticated by Paul Clark');

  it('sign → verify round-trips', async () => {
    const key = generateKeyPair(curve);
    const sig = await signRandom(msg, key);
    expect(await verify(msg, sig, key.publicKey, curve)).toBe(true);
  });

  it('rejects a tampered signature (s+1)', async () => {
    const key = generateKeyPair(curve);
    const sig = await signRandom(msg, key);
    const tampered = { ...sig, s: sig.s + 1n };
    expect(await verify(msg, tampered, key.publicKey, curve)).toBe(false);
  });

  it('rejects a signature verified against the wrong message', async () => {
    const key = generateKeyPair(curve);
    const sig = await signRandom(msg, key);
    expect(await verify(textToBytes('a different message'), sig, key.publicKey, curve)).toBe(false);
  });

  it('rejects a signature under the wrong public key', async () => {
    const key = generateKeyPair(curve);
    const other = generateKeyPair(curve);
    const sig = await signRandom(msg, key);
    expect(await verify(msg, sig, other.publicKey, curve)).toBe(false);
  });

  it('rejects out-of-range r/s', async () => {
    const key = generateKeyPair(curve);
    const n = curveOrder(curve);
    const sig = await signRandom(msg, key);
    expect(await verify(msg, { ...sig, s: 0n }, key.publicKey, curve)).toBe(false);
    expect(await verify(msg, { ...sig, r: n }, key.publicKey, curve)).toBe(false);
  });

  it('random signing uses fresh nonces (signatures differ)', async () => {
    const key = generateKeyPair(curve);
    const s1 = await signRandom(msg, key);
    const s2 = await signRandom(msg, key);
    expect(s1.r !== s2.r || s1.s !== s2.s).toBe(true);
  });

  it('reusing a nonce across two messages yields a shared r', async () => {
    const key = generateKeyPair(curve);
    const n = curveOrder(curve);
    const k = (n / 2n) + 1n;
    const a = await signWithNonce(textToBytes('one'), key, k);
    const b = await signWithNonce(textToBytes('two'), key, k);
    expect(a.r).toBe(b.r);
  });
});
