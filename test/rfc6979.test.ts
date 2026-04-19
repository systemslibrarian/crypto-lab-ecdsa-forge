import { deterministicNonce, signDeterministic } from '../src/rfc6979';
import { generateKeyPair, textToBytes } from '../src/ecdsa';

function expect(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error('invalid hex length');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

async function run(): Promise<void> {
  const key = generateKeyPair('secp256k1');
  const message = textToBytes('same message');

  const sig1 = await signDeterministic(message, key);
  const sig2 = await signDeterministic(message, key);
  expect(sig1.r === sig2.r && sig1.s === sig2.s, 'same message should have identical deterministic signature');

  const m1 = textToBytes('message-1');
  const m2 = textToBytes('message-2');
  const k1 = await deterministicNonce(key.privateKey, m1, key.curve);
  const k2 = await deterministicNonce(key.privateKey, m2, key.curve);
  const s1 = await signDeterministic(m1, key);
  const s2 = await signDeterministic(m2, key);
  expect(k1 !== k2, 'different messages must produce different deterministic nonces');
  expect(s1.r !== s2.r || s1.s !== s2.s, 'different messages should produce different signatures');

  const privateKey = hexToBytes('C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721');
  const sample = textToBytes('sample');
  const expectedK = BigInt('0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60');
  const actualK = await deterministicNonce(privateKey, sample, 'p256');
  expect(actualK === expectedK, 'RFC 6979 A.2.5 deterministic nonce mismatch');

  console.log('phase-3 checks passed');
  console.log(`RFC6979 A.2.5 expected k: ${expectedK.toString(16)}`);
  console.log(`RFC6979 A.2.5 actual k:   ${actualK.toString(16)}`);
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
