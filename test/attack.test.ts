/**
 * The headline claim of the demo: given two ECDSA signatures that reused a
 * nonce, recover the private key and forge a new signature that verifies under
 * the victim's public key. These tests would fail if the recovery math were
 * faked, circular, or only "matched" a replay without equalling the real key.
 */
import { describe, it, expect } from 'vitest';
import {
  type CurveName,
  bytesEqual,
  generateKeyPair,
  signRandom,
  signWithNonce,
  curveOrder,
  textToBytes,
  verify,
} from '../src/ecdsa';
import {
  demonstrateFullCompromise,
  recoverKeyFromNonceReuse,
} from '../src/attack';

const CURVES: CurveName[] = ['secp256k1', 'p256'];

describe.each(CURVES)('nonce-reuse attack on %s', (curve) => {
  it('recovered private key equals the victim key exactly', async () => {
    const victim = generateKeyPair(curve);
    const n = curveOrder(curve);
    const k = (n / 3n) + 7n; // deliberately reused nonce
    const m1 = textToBytes('Transfer $10 to Bob');
    const m2 = textToBytes('Transfer $20 to Charlie');
    const sig1 = await signWithNonce(m1, victim, k);
    const sig2 = await signWithNonce(m2, victim, k);

    const recovered = await recoverKeyFromNonceReuse(sig1, m1, sig2, m2);
    expect(recovered).not.toBeNull();
    expect(recovered!.recoveredNonce).toBe(k % n);
    expect(bytesEqual(recovered!.recoveredKey, victim.privateKey)).toBe(true);
  });

  it('full compromise: forged signature verifies under the victim public key', async () => {
    const result = await demonstrateFullCompromise(curve);
    expect(bytesEqual(result.recoveredPrivateKey, result.victimKeyPair.privateKey)).toBe(true);
    expect(result.forgeryVerifies).toBe(true);

    // The forged signature is a genuine ECDSA signature over the malicious
    // message, checked independently here against the victim's key.
    const forged = await verify(
      textToBytes(result.maliciousMessage),
      result.forgedSignature,
      result.victimKeyPair.publicKey,
      curve,
    );
    expect(forged).toBe(true);
  });
});

describe('nonce-reuse attack — negative cases', () => {
  it('does NOT recover a key when nonces differ', async () => {
    const kp = generateKeyPair('secp256k1');
    const m1 = textToBytes('one');
    const m2 = textToBytes('two');
    const s1 = await signRandom(m1, kp);
    const s2 = await signRandom(m2, kp);
    const recovered = await recoverKeyFromNonceReuse(s1, m1, s2, m2);
    expect(recovered).toBeNull(); // distinct r ⇒ no shared nonce ⇒ no recovery
  });

  it('returns null across mismatched curves', async () => {
    const k1 = generateKeyPair('secp256k1');
    const p1 = generateKeyPair('p256');
    const m = textToBytes('cross');
    const sk1 = await signRandom(m, k1);
    const sp1 = await signRandom(m, p1);
    expect(await recoverKeyFromNonceReuse(sk1, m, sp1, m)).toBeNull();
  });
});
