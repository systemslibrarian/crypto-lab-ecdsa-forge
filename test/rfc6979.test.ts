import { describe, it, expect } from 'vitest';
import { deterministicNonce, signDeterministic } from '../src/rfc6979';
import { generateKeyPair, textToBytes, verify } from '../src/ecdsa';

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error('invalid hex length');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

describe('RFC 6979 deterministic nonce', () => {
  it('is reproducible: same (key, message) yields identical signatures', async () => {
    const key = generateKeyPair('secp256k1');
    const message = textToBytes('same message');
    const sig1 = await signDeterministic(message, key);
    const sig2 = await signDeterministic(message, key);
    expect(sig1.r).toBe(sig2.r);
    expect(sig1.s).toBe(sig2.s);
  });

  it('produces a verifiable signature', async () => {
    const key = generateKeyPair('p256');
    const message = textToBytes('deterministic and valid');
    const sig = await signDeterministic(message, key);
    expect(await verify(message, sig, key.publicKey, key.curve)).toBe(true);
  });

  it('derives different nonces (and signatures) for different messages', async () => {
    const key = generateKeyPair('secp256k1');
    const m1 = textToBytes('message-1');
    const m2 = textToBytes('message-2');
    const k1 = await deterministicNonce(key.privateKey, m1, key.curve);
    const k2 = await deterministicNonce(key.privateKey, m2, key.curve);
    expect(k1).not.toBe(k2);
    const s1 = await signDeterministic(m1, key);
    const s2 = await signDeterministic(m2, key);
    expect(s1.r !== s2.r || s1.s !== s2.s).toBe(true);
  });

  // Known-answer test: RFC 6979 Appendix A.2.5 (P-256, SHA-256, message "sample").
  // This is the vector that pins the HMAC-DRBG construction to the spec — a bug
  // in bits2int/bits2octets or the generate loop would change k here.
  it('matches RFC 6979 Appendix A.2.5 known-answer vector (P-256 / "sample")', async () => {
    const privateKey = hexToBytes(
      'C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721',
    );
    const sample = textToBytes('sample');
    const expectedK = BigInt(
      '0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60',
    );
    const actualK = await deterministicNonce(privateKey, sample, 'p256');
    expect(actualK).toBe(expectedK);
  });
});
