import {
  generateKeyPair,
  modInverse,
  signRandom,
  textToBytes,
  verify,
} from '../src/ecdsa';

function expect(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

async function run(): Promise<void> {
  const keyK1 = generateKeyPair('secp256k1');
  const keyP256 = generateKeyPair('p256');
  const msg = textToBytes('Authenticated by Paul Clark');

  const sigK1 = await signRandom(msg, keyK1);
  const sigP256 = await signRandom(msg, keyP256);

  expect(await verify(msg, sigK1, keyK1.publicKey, 'secp256k1'), 'secp256k1 round-trip failed');
  expect(await verify(msg, sigP256, keyP256.publicKey, 'p256'), 'p256 round-trip failed');

  const tampered = { ...sigK1, s: sigK1.s + 1n };
  expect(!(await verify(msg, tampered, keyK1.publicKey, 'secp256k1')), 'tampered signature should fail');

  expect(modInverse(3n, 11n) === 4n, 'modInverse(3,11) should equal 4');
  expect(modInverse(7n, 13n) === 2n, 'modInverse(7,13) should equal 2');

  const sig1 = await signRandom(msg, keyK1);
  const sig2 = await signRandom(msg, keyK1);
  expect(sig1.r !== sig2.r || sig1.s !== sig2.s, 'random signatures should differ');

  console.log('phase-1 checks passed');
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
