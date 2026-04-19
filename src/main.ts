import './style.css';
import {
  curveOrder,
  generateKeyPair,
  hex,
  privateKeyToBigInt,
  signRandom,
  textToBytes,
  type CurveName,
  type ECDSAKeyPair,
  type ECDSASignature,
  verify,
} from './ecdsa';
import { demonstrateFullCompromise, recoverKeyFromNonceReuse } from './attack';
import { deterministicNonce, signDeterministic } from './rfc6979';

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) throw new Error('App root not found');

let activeCurve: CurveName = 'secp256k1';
let exhibit1KeyPair: ECDSAKeyPair | null = null;
let exhibit1LastSignature: ECDSASignature | null = null;
let compareKeyPair: ECDSAKeyPair | null = null;

const shortHex = (value: bigint | Uint8Array, size = 12): string => {
  const valueHex = hex(value);
  if (valueHex.length <= size * 2) return valueHex;
  return `${valueHex.slice(0, size)}...${valueHex.slice(-size)}`;
};

const html = `
  <main class="page">
    <header class="hero">
      <p class="eyebrow">crypto-lab-ecdsa-forge</p>
      <h1>The Signature That Runs the Internet</h1>
      <p class="subtitle">ECDSA signs TLS certificates, Bitcoin transactions, SSH keys, JWTs, and passkeys. One nonce reuse can destroy the private key in public.</p>
      <div class="hero-grid">
        <div class="hero-card danger">
          <h2>Hazard</h2>
          <p>Nonce reuse leaks the private key immediately.</p>
        </div>
        <div class="hero-card safe">
          <h2>Fix</h2>
          <p>RFC 6979 deterministic nonces remove RNG fragility.</p>
        </div>
      </div>
    </header>

    <section class="exhibit" id="exhibit-1">
      <div class="section-head">
        <h2>Exhibit 1: What Is ECDSA?</h2>
        <p>Interactive key generation, signing, and verification.</p>
      </div>
      <div class="panel-grid">
        <article class="panel">
          <label for="curve-select">Curve</label>
          <select id="curve-select">
            <option value="secp256k1">secp256k1 (Bitcoin, Ethereum)</option>
            <option value="p256">P-256 / secp256r1 (TLS, WebAuthn)</option>
          </select>
          <button id="btn-generate" class="btn">Generate Keypair</button>
          <p class="mono">Private key (hidden): <span id="private-hidden">████████████████</span></p>
          <p class="mono">Public key (compressed): <span id="public-key">not generated</span></p>
        </article>

        <article class="panel">
          <label for="msg-sign">Message</label>
          <textarea id="msg-sign" rows="3">Authenticated by Paul Clark</textarea>
          <div class="button-row">
            <button id="btn-sign-random" class="btn">Sign Random</button>
            <button id="btn-sign-det" class="btn safe">Sign Deterministic (RFC 6979)</button>
          </div>
          <p class="mono">Signature (r, s): <span id="sig-view">none</span></p>
          <p class="mono">Tag: 64 bytes / 520 bits total</p>
          <button id="btn-verify" class="btn ghost">Verify</button>
          <p id="verify-status" class="status" role="status" aria-live="polite">Awaiting signature</p>
        </article>
      </div>
    </section>

    <section class="exhibit" id="exhibit-2">
      <div class="section-head">
        <h2>Exhibit 2: The Nonce Reuse Attack (PS3-style)</h2>
        <p>Two signatures with the same nonce. One stolen private key.</p>
      </div>
      <div class="panel-grid two">
        <article class="panel danger">
          <p class="label">VICTIM</p>
          <h3>Alice</h3>
          <p>Private key: <span id="victim-key" class="censored">████████████████████████████████</span></p>
          <p>Public key: <span id="victim-pub" class="mono">pending...</span></p>
        </article>
        <article class="panel">
          <p class="label">ATTACKER</p>
          <h3>Eve</h3>
          <p>Observes public signatures and runs modular arithmetic recovery.</p>
          <button id="btn-attack" class="btn danger">Run Full Compromise</button>
        </article>
      </div>
      <div class="timeline" id="attack-timeline">
        <div class="step"><h4>Step 1</h4><p id="step1">Waiting...</p></div>
        <div class="step"><h4>Step 2</h4><p id="step2">Waiting...</p></div>
        <div class="step"><h4>Step 3</h4><p id="step3">Waiting...</p></div>
        <div class="step"><h4>Step 4</h4><p id="step4">Waiting...</p></div>
        <div class="step"><h4>Step 5</h4><p id="step5">Waiting...</p></div>
      </div>
      <aside class="history">
        <h3>Historical breakages</h3>
        <ul>
          <li>Sony PlayStation 3 (2010): repeated nonce in ECDSA firmware signatures.</li>
          <li>Android Bitcoin wallets (2013): weak RNG led to nonce reuse and theft.</li>
          <li>Debian OpenSSL entropy failure (2008): massive key recoverability.</li>
          <li>TouchTunes jukeboxes (2017): forged signatures enabled payment abuse.</li>
        </ul>
      </aside>
    </section>

    <section class="exhibit" id="exhibit-3">
      <div class="section-head">
        <h2>Exhibit 3: RFC 6979 Deterministic Nonces</h2>
        <p>Random nonces depend on entropy quality. RFC 6979 derives nonce from key + message hash using HMAC-SHA-256.</p>
      </div>
      <article class="panel">
        <label for="msg-compare">Message for comparison</label>
        <textarea id="msg-compare" rows="2">Nonce discipline is survival.</textarea>
        <div class="button-row">
          <button id="btn-random-sample" class="btn">Sign Random</button>
          <button id="btn-det-sample" class="btn safe">Sign RFC 6979</button>
          <button id="btn-reset-sample" class="btn ghost">Reset Samples</button>
        </div>
        <div class="compare-grid">
          <div class="panel-inner">
            <h3>Random nonce output</h3>
            <ul id="random-list" class="sig-list"></ul>
          </div>
          <div class="panel-inner safe-frame">
            <h3>RFC 6979 output</h3>
            <ul id="det-list" class="sig-list"></ul>
          </div>
        </div>
        <button id="btn-safe-attack" class="btn safe">Try nonce-reuse attack against RFC 6979</button>
        <p id="safe-attack-status" class="status" role="status" aria-live="polite">No test run yet.</p>
      </article>
    </section>

    <section class="exhibit" id="exhibit-4">
      <div class="section-head">
        <h2>Exhibit 4: ECDSA In The Wild</h2>
        <p>A daily signature backbone for identity, transport, and money.</p>
      </div>
      <div class="cards">
        <article class="panel"><h3>TLS Certificates (P-256)</h3><p>Every HTTPS certificate chain verifies ECDSA signatures.</p></article>
        <article class="panel"><h3>Bitcoin (secp256k1)</h3><p>Every spend authorization is an ECDSA signature over transaction data.</p></article>
        <article class="panel"><h3>Ethereum (secp256k1)</h3><p>Each transaction and contract operation is backed by signer authenticity.</p></article>
        <article class="panel"><h3>SSH and Secure Boot</h3><p>Enterprise access and firmware integrity checks rely on signature verification.</p></article>
        <article class="panel"><h3>JWT ES256</h3><p>OIDC and OAuth token verification commonly uses P-256 ECDSA.</p></article>
        <article class="panel"><h3>WebAuthn / Passkeys</h3><p>Biometric unlock signs a challenge from relying parties.</p></article>
      </div>
    </section>

    <section class="exhibit" id="exhibit-5">
      <div class="section-head">
        <h2>Exhibit 5: ECDSA vs Ed25519</h2>
        <p>Ed25519 was designed later to avoid common ECDSA footguns.</p>
      </div>
      <article class="panel table-wrap">
        <table>
          <thead>
            <tr><th>Property</th><th>ECDSA (secp256k1)</th><th>ECDSA (P-256)</th><th>Ed25519</th></tr>
          </thead>
          <tbody>
            <tr><td>Key size</td><td>256 bits</td><td>256 bits</td><td>256 bits</td></tr>
            <tr><td>Signature size</td><td>~70 DER / 64 raw</td><td>~70 DER / 64 raw</td><td>64 bytes</td></tr>
            <tr><td>Signing speed</td><td>Fast</td><td>Fast</td><td>Faster</td></tr>
            <tr><td>Deterministic by default</td><td>No (RFC 6979 needed)</td><td>No (RFC 6979 needed)</td><td>Yes</td></tr>
            <tr><td>Nonce reuse catastrophic</td><td class="warn">Yes</td><td class="warn">Yes</td><td>No by design</td></tr>
            <tr><td>Malleable signatures</td><td>Yes</td><td>Yes</td><td>No</td></tr>
            <tr><td>Best use today</td><td>Bitcoin / Ethereum interoperability</td><td>TLS, JWT, WebAuthn compatibility</td><td>New systems when possible</td></tr>
          </tbody>
        </table>
      </article>
      <article class="panel">
        <h3>Cross-lab links</h3>
        <ul>
          <li>crypto-lab-ed25519-forge</li>
          <li>crypto-lab-rsa-forge</li>
          <li>crypto-lab-dilithium-seal</li>
          <li>crypto-lab-pairing-gate</li>
        </ul>
      </article>
    </section>
  </main>
`;

app.innerHTML = html;

const getById = <T extends HTMLElement>(id: string): T => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing element: ${id}`);
  return el as T;
};

const curveSelect = getById<HTMLSelectElement>('curve-select');
const signMessageInput = getById<HTMLTextAreaElement>('msg-sign');
const compareMessageInput = getById<HTMLTextAreaElement>('msg-compare');
const privateHidden = getById<HTMLSpanElement>('private-hidden');
const publicKeyView = getById<HTMLSpanElement>('public-key');
const sigView = getById<HTMLSpanElement>('sig-view');
const verifyStatus = getById<HTMLParagraphElement>('verify-status');
const victimKey = getById<HTMLSpanElement>('victim-key');
const victimPub = getById<HTMLSpanElement>('victim-pub');
const step1 = getById<HTMLParagraphElement>('step1');
const step2 = getById<HTMLParagraphElement>('step2');
const step3 = getById<HTMLParagraphElement>('step3');
const step4 = getById<HTMLParagraphElement>('step4');
const step5 = getById<HTMLParagraphElement>('step5');
const randomList = getById<HTMLUListElement>('random-list');
const detList = getById<HTMLUListElement>('det-list');
const safeAttackStatus = getById<HTMLParagraphElement>('safe-attack-status');

const setStatus = (el: HTMLElement, message: string, cls: 'ok' | 'bad' | 'warn' = 'warn') => {
  el.textContent = message;
  el.className = `status ${cls}`;
};

const ensureCompareKey = (): ECDSAKeyPair => {
  if (!compareKeyPair || compareKeyPair.curve !== activeCurve) {
    compareKeyPair = generateKeyPair(activeCurve);
  }
  return compareKeyPair;
};

curveSelect.addEventListener('change', () => {
  activeCurve = curveSelect.value as CurveName;
  exhibit1KeyPair = null;
  exhibit1LastSignature = null;
  compareKeyPair = null;
  privateHidden.textContent = '████████████████';
  publicKeyView.textContent = 'not generated';
  sigView.textContent = 'none';
  setStatus(verifyStatus, `Curve switched to ${activeCurve}. Generate a fresh keypair.`, 'warn');
});

getById<HTMLButtonElement>('btn-generate').addEventListener('click', () => {
  exhibit1KeyPair = generateKeyPair(activeCurve);
  exhibit1LastSignature = null;
  publicKeyView.textContent = `${shortHex(exhibit1KeyPair.publicKey)} (${exhibit1KeyPair.publicKey.length} bytes)`;
  privateHidden.textContent = '████████████████████████████████';
  setStatus(verifyStatus, `Keypair generated on ${activeCurve}.`, 'ok');
});

getById<HTMLButtonElement>('btn-sign-random').addEventListener('click', async () => {
  if (!exhibit1KeyPair) {
    setStatus(verifyStatus, 'Generate a keypair first.', 'bad');
    return;
  }
  const message = textToBytes(signMessageInput.value);
  exhibit1LastSignature = await signRandom(message, exhibit1KeyPair);
  sigView.textContent = `(${shortHex(exhibit1LastSignature.r)}, ${shortHex(exhibit1LastSignature.s)})`;
  setStatus(verifyStatus, 'Signature generated with random nonce.', 'warn');
});

getById<HTMLButtonElement>('btn-sign-det').addEventListener('click', async () => {
  if (!exhibit1KeyPair) {
    setStatus(verifyStatus, 'Generate a keypair first.', 'bad');
    return;
  }
  const message = textToBytes(signMessageInput.value);
  exhibit1LastSignature = await signDeterministic(message, exhibit1KeyPair);
  sigView.textContent = `(${shortHex(exhibit1LastSignature.r)}, ${shortHex(exhibit1LastSignature.s)})`;
  setStatus(verifyStatus, 'Signature generated with RFC 6979 deterministic nonce.', 'ok');
});

getById<HTMLButtonElement>('btn-verify').addEventListener('click', async () => {
  if (!exhibit1KeyPair || !exhibit1LastSignature) {
    setStatus(verifyStatus, 'Sign something first.', 'bad');
    return;
  }
  const message = textToBytes(signMessageInput.value);
  const valid = await verify(message, exhibit1LastSignature, exhibit1KeyPair.publicKey, exhibit1KeyPair.curve);
  setStatus(verifyStatus, valid ? '✓ VALID signature' : '✗ INVALID signature', valid ? 'ok' : 'bad');
});

getById<HTMLButtonElement>('btn-attack').addEventListener('click', async () => {
  step1.className = 'status warn';
  step1.textContent = 'Executing attack...';
  const result = await demonstrateFullCompromise(activeCurve);
  victimPub.textContent = shortHex(result.victimKeyPair.publicKey, 18);

  step1.textContent = `Alice signs two messages with reused nonce: sig1(r=${shortHex(result.sig1.r)}, s1=${shortHex(result.sig1.s)}), sig2(r=${shortHex(result.sig2.r)}, s2=${shortHex(result.sig2.s)}).`;
  step2.textContent = `Eve spots identical r values, proving nonce reuse. r=${shortHex(result.sig1.r)}.`;

  const e1 = await crypto.subtle.digest('SHA-256', textToBytes(result.message1) as unknown as BufferSource);
  const e2 = await crypto.subtle.digest('SHA-256', textToBytes(result.message2) as unknown as BufferSource);
  const e1b = hex(new Uint8Array(e1));
  const e2b = hex(new Uint8Array(e2));

  const recovered = await recoverKeyFromNonceReuse(
    result.sig1,
    textToBytes(result.message1),
    result.sig2,
    textToBytes(result.message2),
  );
  if (!recovered) {
    throw new Error('Attack recovery returned null unexpectedly');
  }

  step3.textContent = `k = (e1-e2)*(s1-s2)^-1 mod n = ${shortHex(recovered.recoveredNonce, 16)}. e1=${e1b.slice(0, 14)}..., e2=${e2b.slice(0, 14)}...`;
  step4.textContent = `d = (s1*k-e1)*r^-1 mod n = ${shortHex(privateKeyToBigInt(recovered.recoveredKey), 16)}.`;
  step5.textContent = `Eve forges "${result.maliciousMessage}" and verification returns ${result.forgeryVerifies ? 'true' : 'false'}.`;

  victimKey.textContent = hex(result.recoveredPrivateKey);
  victimKey.classList.remove('censored');
  victimKey.classList.add('exposed');
});

getById<HTMLButtonElement>('btn-random-sample').addEventListener('click', async () => {
  const keyPair = ensureCompareKey();
  const message = textToBytes(compareMessageInput.value);
  const sig = await signRandom(message, keyPair);
  const item = document.createElement('li');
  item.textContent = `r=${shortHex(sig.r)}, s=${shortHex(sig.s)}`;
  randomList.prepend(item);
});

getById<HTMLButtonElement>('btn-det-sample').addEventListener('click', async () => {
  const keyPair = ensureCompareKey();
  const message = textToBytes(compareMessageInput.value);
  const k = await deterministicNonce(keyPair.privateKey, message, keyPair.curve);
  const sig = await signDeterministic(message, keyPair);
  const item = document.createElement('li');
  item.textContent = `k=${shortHex(k)}, r=${shortHex(sig.r)}, s=${shortHex(sig.s)}`;
  detList.prepend(item);
});

getById<HTMLButtonElement>('btn-reset-sample').addEventListener('click', () => {
  randomList.innerHTML = '';
  detList.innerHTML = '';
  safeAttackStatus.textContent = 'No test run yet.';
  safeAttackStatus.className = 'status warn';
});

getById<HTMLButtonElement>('btn-safe-attack').addEventListener('click', async () => {
  const keyPair = ensureCompareKey();
  const m1 = textToBytes(`${compareMessageInput.value} / 1`);
  const m2 = textToBytes(`${compareMessageInput.value} / 2`);
  const sig1 = await signDeterministic(m1, keyPair);
  const sig2 = await signDeterministic(m2, keyPair);
  const recovery = await recoverKeyFromNonceReuse(sig1, m1, sig2, m2);
  const n = curveOrder(keyPair.curve);

  if (sig1.r !== sig2.r && recovery === null) {
    setStatus(safeAttackStatus, `Attack blocked by construction: r1 != r2, no shared nonce, n=${shortHex(n, 14)}.`, 'ok');
    return;
  }

  setStatus(safeAttackStatus, 'Unexpected result: investigate deterministic nonce implementation.', 'bad');
});

if (!exhibit1KeyPair) {
  setStatus(verifyStatus, 'Generate a keypair to begin.', 'warn');
}

queueMicrotask(async () => {
  const keyPair = ensureCompareKey();
  const msg = textToBytes(compareMessageInput.value);
  const sig = await signDeterministic(msg, keyPair);
  const check = await signDeterministic(msg, keyPair);
  if (sig.r === check.r && sig.s === check.s) {
    const li = document.createElement('li');
    li.textContent = `Warmup deterministic signature: r=${shortHex(sig.r)}, s=${shortHex(sig.s)}`;
    detList.append(li);
  }
});
