import {
  bytesEqual,
  generateKeyPair,
  signRandom,
  textToBytes,
  verify,
  signWithNonce,
  curveOrder,
} from '../src/ecdsa';
import { recoverKeyFromNonceReuse, demonstrateFullCompromise } from '../src/attack';
import { deterministicNonce, signDeterministic } from '../src/rfc6979';

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
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

function randomScalar(n: bigint): bigint {
  const bytes = new Uint8Array(32);
  while (true) {
    crypto.getRandomValues(bytes);
    let candidate = 0n;
    for (const b of bytes) candidate = (candidate << 8n) | BigInt(b);
    if (candidate > 0n && candidate < n) return candidate;
  }
}

async function run(): Promise<void> {
  const msg = textToBytes('verification message');
  const pair = generateKeyPair('secp256k1');

  const sig = await signRandom(msg, pair);
  const verifyOk = await verify(msg, sig, pair.publicKey, pair.curve);
  console.log(`1. npm run build zero TypeScript errors: defer to build command output`);
  console.log(`2. Generate keypair -> sign -> verify -> true: ${verifyOk ? 'PASS' : 'FAIL'}`);

  const tampered = { ...sig, s: sig.s + 1n };
  const tamperedOk = await verify(msg, tampered, pair.publicKey, pair.curve);
  console.log(`3. Sign + tamper -> verify false: ${!tamperedOk ? 'PASS' : 'FAIL'}`);

  const n = curveOrder(pair.curve);
  const nonce = randomScalar(n);
  const m1 = textToBytes('m1 reuse');
  const m2 = textToBytes('m2 reuse');
  const s1 = await signWithNonce(m1, pair, nonce);
  const s2 = await signWithNonce(m2, pair, nonce);
  const recovered = await recoverKeyFromNonceReuse(s1, m1, s2, m2);
  const recoveredMatch = recovered !== null && bytesEqual(recovered.recoveredKey, pair.privateKey);
  console.log(`4. recoverKeyFromNonceReuse exact key recovery: ${recoveredMatch ? 'PASS' : 'FAIL'}`);

  const compromise = await demonstrateFullCompromise('secp256k1');
  console.log(`5. Forged signature verifies after key recovery: ${compromise.forgeryVerifies ? 'PASS' : 'FAIL'}`);

  const dPair = generateKeyPair('p256');
  const dMsg = textToBytes('repeat me');
  const dSig1 = await signDeterministic(dMsg, dPair);
  const dSig2 = await signDeterministic(dMsg, dPair);
  const sameDet = dSig1.r === dSig2.r && dSig1.s === dSig2.s;
  console.log(`6. RFC6979 same (key,message) twice identical signatures: ${sameDet ? 'PASS' : 'FAIL'}`);

  const dm1 = textToBytes('deterministic one');
  const dm2 = textToBytes('deterministic two');
  const dk1 = await deterministicNonce(dPair.privateKey, dm1, dPair.curve);
  const dk2 = await deterministicNonce(dPair.privateKey, dm2, dPair.curve);
  const ds1 = await signDeterministic(dm1, dPair);
  const ds2 = await signDeterministic(dm2, dPair);
  const diffDet = dk1 !== dk2 && (ds1.r !== ds2.r || ds1.s !== ds2.s);
  console.log(`7. RFC6979 different messages -> different k and signatures: ${diffDet ? 'PASS' : 'FAIL'}`);

  const tvKey = hexToBytes('C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721');
  const expectedK = BigInt('0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60');
  const actualK = await deterministicNonce(tvKey, textToBytes('sample'), 'p256');
  console.log(`8. RFC6979 A.2.5 expected k match: ${actualK === expectedK ? 'PASS' : 'FAIL'} (${actualK.toString(16)})`);

  const bothCurves = ['secp256k1', 'p256'] as const;
  let curvesOk = true;
  for (const curve of bothCurves) {
    const result = await demonstrateFullCompromise(curve);
    curvesOk = curvesOk && result.forgeryVerifies && bytesEqual(result.recoveredPrivateKey, result.victimKeyPair.privateKey);
  }
  console.log(`10. Both secp256k1 and P-256 tested and working: ${curvesOk ? 'PASS' : 'FAIL'}`);

  if (!(verifyOk && !tamperedOk && recoveredMatch && compromise.forgeryVerifies && sameDet && diffDet && actualK === expectedK && curvesOk)) {
    throw new Error('Final verification failed');
  }

  console.log(`Recovered key sample: ${toHex(compromise.recoveredPrivateKey).slice(0, 16)}...`);
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
