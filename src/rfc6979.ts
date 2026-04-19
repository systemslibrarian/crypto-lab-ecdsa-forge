import {
  type CurveName,
  curveOrder,
  privateKeyToBigInt,
  signWithNonce,
  type ECDSAKeyPair,
  type ECDSASignature,
} from './ecdsa';

const HLEN = 32;
const RLEN = 32;

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, c) => sum + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let out = 0n;
  for (const b of bytes) {
    out = (out << 8n) | BigInt(b);
  }
  return out;
}

function intToBytes(value: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i -= 1) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function mod(a: bigint, n: bigint): bigint {
  const x = a % n;
  return x >= 0n ? x : x + n;
}

function bitLength(value: bigint): number {
  return value.toString(2).length;
}

function bits2int(input: Uint8Array, qlen: number): bigint {
  const v = bytesToBigInt(input);
  const blen = input.length * 8;
  if (blen > qlen) {
    return v >> BigInt(blen - qlen);
  }
  return v;
}

function bits2octets(input: Uint8Array, q: bigint): Uint8Array {
  const qlen = bitLength(q);
  const z1 = bits2int(input, qlen);
  const z2 = mod(z1, q);
  return intToBytes(z2, RLEN);
}

async function sha256(input: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', input as unknown as BufferSource);
  return new Uint8Array(digest);
}

async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key as unknown as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, data as unknown as BufferSource);
  return new Uint8Array(sig);
}

/**
 * Generate a deterministic nonce k per RFC 6979 Section 3.2.
 *
 * Uses HMAC-SHA-256 with the private key and message hash as inputs.
 * Same (d, m) always produces same k. Different messages -> different k.
 * No RNG required.
 */
export async function deterministicNonce(
  privateKey: Uint8Array,
  message: Uint8Array,
  curve: CurveName,
): Promise<bigint> {
  const q = curveOrder(curve);
  const qlen = bitLength(q);
  const h1 = await sha256(message);
  const x = intToBytes(privateKeyToBigInt(privateKey), RLEN);
  const h1octets = bits2octets(h1, q);

  let v: Uint8Array<ArrayBufferLike> = new Uint8Array(HLEN).fill(0x01);
  let k: Uint8Array<ArrayBufferLike> = new Uint8Array(HLEN).fill(0x00);

  k = await hmacSha256(k, concatBytes(v, new Uint8Array([0x00]), x, h1octets));
  v = await hmacSha256(k, v);
  k = await hmacSha256(k, concatBytes(v, new Uint8Array([0x01]), x, h1octets));
  v = await hmacSha256(k, v);

  while (true) {
    let t: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    while (t.length * 8 < qlen) {
      v = await hmacSha256(k, v);
      t = concatBytes(t, v);
    }

    const nonce = bits2int(t, qlen);
    if (nonce > 0n && nonce < q) {
      return nonce;
    }

    k = await hmacSha256(k, concatBytes(v, new Uint8Array([0x00])));
    v = await hmacSha256(k, v);
  }
}

/**
 * Sign with RFC 6979 deterministic nonce.
 * Reproducible: signing same (d, m) twice -> identical signatures.
 */
export async function signDeterministic(
  message: Uint8Array,
  keyPair: ECDSAKeyPair,
): Promise<ECDSASignature> {
  const k = await deterministicNonce(keyPair.privateKey, message, keyPair.curve);
  return signWithNonce(message, keyPair, k);
}
