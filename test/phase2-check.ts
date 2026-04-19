import {
  bytesEqual,
  generateKeyPair,
  signRandom,
  textToBytes,
} from '../src/ecdsa';
import {
  demonstrateFullCompromise,
  recoverKeyFromNonceReuse,
} from '../src/attack';

function expect(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

async function run(): Promise<void> {
  for (const curve of ['secp256k1', 'p256'] as const) {
    const result = await demonstrateFullCompromise(curve);
    expect(bytesEqual(result.recoveredPrivateKey, result.victimKeyPair.privateKey), `${curve} key recovery mismatch`);
    expect(result.forgeryVerifies, `${curve} forgery should verify`);
  }

  const kp = generateKeyPair('secp256k1');
  const m1 = textToBytes('one');
  const m2 = textToBytes('two');
  const s1 = await signRandom(m1, kp);
  const s2 = await signRandom(m2, kp);
  const recovered = await recoverKeyFromNonceReuse(s1, m1, s2, m2);
  expect(recovered === null, 'different nonces must not recover key');

  console.log('phase-2 checks passed');
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
