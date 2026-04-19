import {
  type CurveName,
  type ECDSAKeyPair,
  type ECDSASignature,
  bytesEqual,
  bigIntToBytes,
  curveOrder,
  generateKeyPair,
  hashMessage,
  modInverse,
  signWithNonce,
  verify,
} from './ecdsa';

function mod(a: bigint, n: bigint): bigint {
  const x = a % n;
  return x >= 0n ? x : x + n;
}

function randomScalar(n: bigint): bigint {
  const buf = new Uint8Array(32);
  while (true) {
    crypto.getRandomValues(buf);
    let value = 0n;
    for (const b of buf) {
      value = (value << 8n) | BigInt(b);
    }
    if (value > 0n && value < n) return value;
  }
}

/**
 * Given two signatures produced with the SAME nonce k on DIFFERENT messages,
 * recover the private key.
 */
export async function recoverKeyFromNonceReuse(
  sig1: ECDSASignature,
  message1: Uint8Array,
  sig2: ECDSASignature,
  message2: Uint8Array,
): Promise<{
  recoveredKey: Uint8Array;
  recoveredNonce: bigint;
  matches: boolean;
} | null> {
  if (sig1.curve !== sig2.curve) return null;
  if (sig1.r !== sig2.r) return null;

  const n = curveOrder(sig1.curve);
  const e1 = await hashMessage(message1, sig1.curve);
  const e2 = await hashMessage(message2, sig2.curve);

  const sDelta = mod(sig1.s - sig2.s, n);
  if (sDelta === 0n) return null;

  const k = mod((e1 - e2) * modInverse(sDelta, n), n);
  if (k === 0n) return null;

  const d = mod((sig1.s * k - e1) * modInverse(sig1.r, n), n);
  if (d === 0n) return null;

  const recoveredKey = bigIntToBytes(d, 32);
  const recoveredKeyPair: ECDSAKeyPair = {
    privateKey: recoveredKey,
    publicKey: new Uint8Array(0),
    curve: sig1.curve,
  };

  const replaySig1 = await signWithNonce(message1, recoveredKeyPair, k);
  const replaySig2 = await signWithNonce(message2, recoveredKeyPair, k);
  const matches = replaySig1.r === sig1.r
    && replaySig1.s === sig1.s
    && replaySig2.r === sig2.r
    && replaySig2.s === sig2.s;

  return { recoveredKey, recoveredNonce: k, matches };
}

/**
 * Demonstrate full nonce-reuse compromise including forgery.
 */
export async function demonstrateFullCompromise(
  curve: CurveName,
): Promise<{
  victimKeyPair: ECDSAKeyPair;
  message1: string;
  message2: string;
  maliciousMessage: string;
  sig1: ECDSASignature;
  sig2: ECDSASignature;
  recoveredPrivateKey: Uint8Array;
  forgedSignature: ECDSASignature;
  forgeryVerifies: boolean;
}> {
  const victimKeyPair = generateKeyPair(curve);
  const message1 = 'Transfer $10 to Bob';
  const message2 = 'Transfer $20 to Charlie';
  const maliciousMessage = 'Transfer $1,000,000 to Eve';

  const n = curveOrder(curve);
  const reusedNonce = randomScalar(n);

  const msg1Bytes = new TextEncoder().encode(message1);
  const msg2Bytes = new TextEncoder().encode(message2);
  const maliciousBytes = new TextEncoder().encode(maliciousMessage);

  const sig1 = await signWithNonce(msg1Bytes, victimKeyPair, reusedNonce);
  const sig2 = await signWithNonce(msg2Bytes, victimKeyPair, reusedNonce);

  const recovered = await recoverKeyFromNonceReuse(sig1, msg1Bytes, sig2, msg2Bytes);
  if (!recovered || !recovered.matches || !bytesEqual(recovered.recoveredKey, victimKeyPair.privateKey)) {
    throw new Error('Nonce reuse attack failed: recovered key does not match victim key');
  }

  const attackerKeyPair: ECDSAKeyPair = {
    privateKey: recovered.recoveredKey,
    publicKey: victimKeyPair.publicKey,
    curve,
  };

  const forgedSignature = await signWithNonce(
    maliciousBytes,
    attackerKeyPair,
    randomScalar(n),
  );

  const forgeryVerifies = await verify(
    maliciousBytes,
    forgedSignature,
    victimKeyPair.publicKey,
    curve,
  );

  return {
    victimKeyPair,
    message1,
    message2,
    maliciousMessage,
    sig1,
    sig2,
    recoveredPrivateKey: recovered.recoveredKey,
    forgedSignature,
    forgeryVerifies,
  };
}
