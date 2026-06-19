import './style.css';
import {
  curveOrder,
  generateKeyPair,
  hashMessage,
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
import {
  TOY,
  allPoints,
  scalarMul,
  toyRecover,
  toySign,
  type ToyMaybePoint,
} from './toycurve';
import { X_MIN, addReal, curveY, type RealPoint } from './realcurve';
import { CITATIONS, GLOSSARY } from './content';

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

const fmtPoint = (P: ToyMaybePoint): string => (P === null ? '𝒪 (infinity)' : `(${P.x}, ${P.y})`);

// ---------------------------------------------------------------------------
// Visualization 1: continuous curve y² = x³ + 7 with chord-and-tangent addition
// ---------------------------------------------------------------------------
const VC = { w: 460, h: 320, pad: 16, xCurveMax: 4.2 };
const Q_FIXED: RealPoint = { x: -1, y: curveY(-1) as number };

function renderContinuousCurve(px: number, doubling: boolean): { svg: string; label: string } {
  const py = curveY(px);
  if (py === null) return { svg: '', label: 'P is left of the curve.' };
  const P: RealPoint = { x: px, y: py };
  const Q: RealPoint = doubling ? P : Q_FIXED;
  const res = addReal(P, Q);

  // Sample the curve once; reuse for drawing AND for auto-fitting the viewBox.
  const upperPts: RealPoint[] = [];
  const lowerPts: RealPoint[] = [];
  for (let x = X_MIN; x <= VC.xCurveMax; x += 0.04) {
    const y = curveY(x);
    if (y === null) continue;
    upperPts.push({ x, y });
    lowerPts.push({ x, y: -y });
  }

  // Auto-fit bounds so the result point (P+Q) is ALWAYS on screen.
  const fitPts: RealPoint[] = [...upperPts, ...lowerPts, P, Q, res.third, res.sum];
  let minX = Infinity;
  let maxX = -Infinity;
  let minY = Infinity;
  let maxY = -Infinity;
  for (const p of fitPts) {
    minX = Math.min(minX, p.x);
    maxX = Math.max(maxX, p.x);
    minY = Math.min(minY, p.y);
    maxY = Math.max(maxY, p.y);
  }
  const padX = (maxX - minX) * 0.07 + 0.3;
  const padY = (maxY - minY) * 0.07 + 0.3;
  minX -= padX;
  maxX += padX;
  minY -= padY;
  maxY += padY;

  const sx = (x: number): number => VC.pad + ((x - minX) / (maxX - minX)) * (VC.w - 2 * VC.pad);
  const sy = (y: number): number => VC.pad + ((maxY - y) / (maxY - minY)) * (VC.h - 2 * VC.pad);
  const poly = (pts: RealPoint[]): string =>
    pts.map((p) => `${sx(p.x).toFixed(1)},${sy(p.y).toFixed(1)}`).join(' ');

  const curvePath = `<polyline points="${poly(upperPts)}" class="vc-curve"/><polyline points="${poly(lowerPts)}" class="vc-curve"/>`;

  // The secant/tangent line spans the visible width.
  const lineY = (x: number): number => res.slope * (x - P.x) + P.y;
  const line = `<line x1="${sx(minX)}" y1="${sy(lineY(minX))}" x2="${sx(maxX)}" y2="${sy(lineY(maxX))}" class="vc-line"/>`;

  // Reflection drop from the third intersection to R = P+Q.
  const drop = `<line x1="${sx(res.third.x)}" y1="${sy(res.third.y)}" x2="${sx(res.sum.x)}" y2="${sy(res.sum.y)}" class="vc-drop"/>`;

  const dot = (p: RealPoint, cls: string) =>
    `<circle cx="${sx(p.x)}" cy="${sy(p.y)}" r="5" class="${cls}"/>`;
  const txt = (p: RealPoint, t: string, dx = 8, dy = -8) =>
    `<text x="${(sx(p.x) + dx).toFixed(1)}" y="${(sy(p.y) + dy).toFixed(1)}" class="vc-text">${t}</text>`;

  const axes = `
    <line x1="${sx(minX)}" y1="${sy(0)}" x2="${sx(maxX)}" y2="${sy(0)}" class="vc-axis"/>
    <line x1="${sx(0)}" y1="${sy(minY)}" x2="${sx(0)}" y2="${sy(maxY)}" class="vc-axis"/>`;

  const svg = `<svg viewBox="0 0 ${VC.w} ${VC.h}" class="viz-svg" role="img"
      aria-label="Curve y squared equals x cubed plus 7. ${doubling ? 'Doubling P.' : 'Adding P and Q.'} The line meets the curve at a third point; its reflection is the sum.">
    ${axes}${curvePath}${line}${drop}
    ${dot(P, 'vc-p')}${txt(P, 'P')}
    ${doubling ? '' : `${dot(Q, 'vc-p')}${txt(Q, 'Q', -18, -8)}`}
    <circle cx="${sx(res.third.x)}" cy="${sy(res.third.y)}" r="4" class="vc-third"/>
    ${dot(res.sum, 'vc-sum')}${txt(res.sum, doubling ? '2P' : 'P+Q', 8, 16)}
  </svg>`;

  const label = doubling
    ? `Doubling: 2P = (${res.sum.x.toFixed(2)}, ${res.sum.y.toFixed(2)}). The tangent at P meets the curve once more; reflect to get 2P.`
    : `P + Q = (${res.sum.x.toFixed(2)}, ${res.sum.y.toFixed(2)}). The line through P and Q meets the curve at a third point; reflect it across the x-axis.`;
  return { svg, label };
}

// ---------------------------------------------------------------------------
// Visualization 2: the same group as a finite field of 18 points (F_17)
// ---------------------------------------------------------------------------
const VD = { size: 340, pad: 22 };
const vdMap = (v: number): number => VD.pad + (v / (TOY.p - 1)) * (VD.size - 2 * VD.pad);

function renderDiscreteField(k: number): { svg: string; label: string } {
  const pts = allPoints();
  const target = scalarMul(k, TOY.G);

  const grid: string[] = [];
  for (let i = 0; i < TOY.p; i += 1) {
    grid.push(
      `<line x1="${vdMap(i)}" y1="${vdMap(0)}" x2="${vdMap(i)}" y2="${vdMap(TOY.p - 1)}" class="vd-grid"/>`,
      `<line x1="${vdMap(0)}" y1="${vdMap(i)}" x2="${vdMap(TOY.p - 1)}" y2="${vdMap(i)}" class="vd-grid"/>`,
    );
  }

  const dots = pts
    .map((p) => `<circle cx="${vdMap(p.x)}" cy="${vdMap(TOY.p - 1 - p.y)}" r="4" class="vd-dot"/>`)
    .join('');

  const gDot = `<circle cx="${vdMap(TOY.G.x)}" cy="${vdMap(TOY.p - 1 - TOY.G.y)}" r="6" class="vd-g"/>`;
  const tDot =
    target === null
      ? ''
      : `<circle cx="${vdMap(target.x)}" cy="${vdMap(TOY.p - 1 - target.y)}" r="8" class="vd-target"/>`;

  const svg = `<svg viewBox="0 0 ${VD.size} ${VD.size}" class="viz-svg" role="img"
      aria-label="The 18 points of y squared equals x cubed plus 2x plus 2 over F17. ${k} times G equals ${fmtPoint(target)}.">
    ${grid.join('')}${dots}${gDot}${tDot}
  </svg>`;
  const label = `${k}·G = ${fmtPoint(target)}. The dots are all 18 points. Multiplying G is easy; finding k from the highlighted point is the hard problem ECDSA relies on.`;
  return { svg, label };
}

// ---------------------------------------------------------------------------
// Interactive toy nonce-reuse attack — every number is hand-checkable
// ---------------------------------------------------------------------------
function renderToyAttack(
  d: number,
  k: number,
  e1: number,
  e2: number,
): { html: string; summary: string } {
  const n = TOY.n;
  const Q = scalarMul(d, TOY.G);

  if (e1 === e2) {
    const msg = 'Pick two different messages: the attack needs distinct hashes e₁ ≠ e₂.';
    return { html: `<p class="status bad">${msg}</p>`, summary: msg };
  }

  let s1: ReturnType<typeof toySign>;
  let s2: ReturnType<typeof toySign>;
  try {
    s1 = toySign(d, e1, k);
    s2 = toySign(d, e2, k);
  } catch (err) {
    const msg = `Degenerate nonce: ${(err as Error).message}. Try another k.`;
    return { html: `<p class="status bad">${msg}</p>`, summary: msg };
  }

  const rec = toyRecover({ r: s1.r, s: s1.s }, e1, { r: s2.r, s: s2.s }, e2);
  if (!rec) {
    const msg = 's₁ = s₂ here, so (s₁−s₂) has no inverse. Change a message hash and retry.';
    return { html: `<p class="status bad">${msg}</p>`, summary: msg };
  }
  const ok = rec.d === d && rec.k === k;
  const summary = ok
    ? `Attack succeeds: recovered private key d = ${rec.d}, matching the real key.`
    : `Unexpected mismatch: recovered d = ${rec.d}, real d = ${d}.`;

  const html = `
    <div class="toy-out">
      <p class="mono">Public key&nbsp; Q = ${d}·G = <strong>${fmtPoint(Q)}</strong> &nbsp;(published)</p>
      <div class="steps">
        <div class="step-card">
          <h4>Signature 1 &nbsp;<span class="dim">message hash e₁ = ${e1}</span></h4>
          <p class="mono">R = ${k}·G = ${fmtPoint(s1.R)} → r = R.x mod ${n} = <strong>${s1.r}</strong></p>
          <p class="mono">s₁ = k⁻¹·(e₁ + r·d) = ${s1.kInv}·(${e1} + ${s1.r}·${d}) mod ${n} = <strong>${s1.s}</strong></p>
        </div>
        <div class="step-card">
          <h4>Signature 2 &nbsp;<span class="dim">message hash e₂ = ${e2}</span></h4>
          <p class="mono">R = ${k}·G = ${fmtPoint(s2.R)} → r = <strong>${s2.r}</strong> &nbsp;<span class="tell">← same r! nonce reused</span></p>
          <p class="mono">s₂ = ${s2.kInv}·(${e2} + ${s2.r}·${d}) mod ${n} = <strong>${s2.s}</strong></p>
        </div>
      </div>
      <div class="recover-card">
        <h4>Eve recovers the secret from public values (r, s₁, s₂, e₁, e₂)</h4>
        <p class="mono">k = (e₁−e₂)·(s₁−s₂)⁻¹ = (${rec.eDelta})·(${rec.sDelta})⁻¹ mod ${n} = <strong>${rec.k}</strong></p>
        <p class="mono">d = (s₁·k − e₁)·r⁻¹ = (${s1.s}·${rec.k} − ${e1})·${rec.rInv} mod ${n} = <strong>${rec.d}</strong></p>
      </div>
      <p class="badge ${ok ? 'ok' : 'bad'}">${
        ok
          ? `✓ Recovered d = ${rec.d} equals the real private key d = ${d}. The secret is fully exposed.`
          : `Unexpected mismatch — recovered d = ${rec.d}, real d = ${d}.`
      }</p>
    </div>`;
  return { html, summary };
}

const html = `
  <nav class="topbar" aria-label="Lab navigation">
    <a class="brand" href="#main-content">
      <span class="brand-mark" aria-hidden="true">⛓</span>
      <span class="brand-text">ECDSA Forge</span>
    </a>
    <ul class="topnav" id="topnav">
      <li><a href="#exhibit-1">Basics</a></li>
      <li><a href="#exhibit-geometry">Geometry</a></li>
      <li><a href="#exhibit-attack">Nonce Attack</a></li>
      <li><a href="#exhibit-rfc">RFC 6979</a></li>
      <li><a href="#exhibit-wild">In the Wild</a></li>
      <li><a href="#exhibit-compare">vs Ed25519</a></li>
      <li><a href="#reference">Reference</a></li>
    </ul>
    <button id="theme-toggle" class="theme-toggle" type="button" aria-pressed="false">
      <span class="theme-icon" aria-hidden="true"></span>
      <span class="theme-label">Theme</span>
    </button>
  </nav>

  <main class="page" id="main-content" tabindex="-1">
    <div id="sr-live" class="sr-only" role="status" aria-live="polite"></div>
    <header class="hero">
      <p class="eyebrow">crypto-lab-ecdsa-forge</p>
      <h1>The Signature That Runs the Internet</h1>
      <p class="subtitle">ECDSA signs TLS certificates, Bitcoin transactions, SSH keys, JWTs, and passkeys. This lab shows exactly how it works — and how one reused nonce hands the private key to anyone watching.</p>
      <div class="hero-grid">
        <div class="hero-card danger">
          <h2>Hazard</h2>
          <p>Reuse the per-signature nonce and the private key falls out of public data by hand.</p>
        </div>
        <div class="hero-card safe">
          <h2>Fix</h2>
          <p>RFC 6979 derives the nonce from key + message, removing the RNG as a failure point.</p>
        </div>
      </div>
    </header>

    <section class="exhibit" id="exhibit-1" aria-labelledby="exhibit-1-title">
      <div class="section-head">
        <p class="exhibit-tag" aria-hidden="true">Exhibit 1</p>
        <h2 id="exhibit-1-title">What Is ECDSA?</h2>
        <p>Three moves on an elliptic curve: make a key, sign a hash, verify it.</p>
      </div>
      <ol class="how-grid">
        <li><span class="how-k">Keygen</span> Pick a secret scalar <span class="mono">d</span>; publish the point <span class="mono">Q = d·G</span>.</li>
        <li><span class="how-k">Sign</span> Choose a one-time nonce <span class="mono">k</span>; output <span class="mono">r = (k·G).x</span> and <span class="mono">s = k⁻¹(e + r·d)</span>.</li>
        <li><span class="how-k">Verify</span> Recompute the point from <span class="mono">(r, s)</span>, <span class="mono">e</span>, and <span class="mono">Q</span>; accept iff its x-coordinate equals <span class="mono">r</span>.</li>
      </ol>
      <div class="panel-grid">
        <article class="panel">
          <label for="curve-select">Curve</label>
          <select id="curve-select">
            <option value="secp256k1">secp256k1 (Bitcoin, Ethereum)</option>
            <option value="p256">P-256 / secp256r1 (TLS, WebAuthn)</option>
          </select>
          <button id="btn-generate" class="btn">Generate Keypair</button>
          <p class="mono">Private key <span class="sr-only">(kept hidden)</span><span aria-hidden="true">(hidden)</span>: <span id="private-hidden" aria-hidden="true">████████████████</span></p>
          <p class="mono">Public key Q (compressed): <span id="public-key">not generated</span></p>
        </article>

        <article class="panel">
          <label for="msg-sign">Message</label>
          <textarea id="msg-sign" rows="3">Authenticated by Paul Clark</textarea>
          <div class="button-row">
            <button id="btn-sign-random" class="btn">Sign Random</button>
            <button id="btn-sign-det" class="btn safe">Sign Deterministic (RFC 6979)</button>
          </div>
          <p class="mono">Signature (r, s): <span id="sig-view">none</span></p>
          <p class="mono">Raw size: r ∥ s = 64 bytes (512 bits) on a 256-bit curve.</p>
          <button id="btn-verify" class="btn ghost">Verify</button>
          <p id="verify-status" class="status" role="status" aria-live="polite">Awaiting signature</p>
        </article>
      </div>
    </section>

    <section class="exhibit" id="exhibit-geometry" aria-labelledby="exhibit-geometry-title">
      <div class="section-head">
        <p class="exhibit-tag" aria-hidden="true">Exhibit 2</p>
        <h2 id="exhibit-geometry-title">The Math You Can See</h2>
        <p>“Multiply a point by d” means add it to itself d times. Easy forward, infeasible to reverse — that gap (the ECDLP) is the whole security argument.</p>
      </div>
      <div class="panel-grid">
        <article class="panel">
          <h3>Adding points (over the reals)</h3>
          <p>To add P and Q, draw the line through them, find the third crossing, and reflect over the x-axis. Tangent line when P = Q (doubling).</p>
          <div class="viz" id="viz-continuous"></div>
          <label for="vc-slider">Move P along the curve</label>
          <input type="range" id="vc-slider" min="0.2" max="4" step="0.05" value="2" />
          <label class="inline-check"><input type="checkbox" id="vc-double" /> Double P (show P + P)</label>
          <p class="viz-label" id="vc-label"></p>
        </article>
        <article class="panel">
          <h3>The real thing: a finite field</h3>
          <p>Cryptography uses the same rules over a finite field, so the “curve” is a scatter of points. Here is a toy curve <span class="mono">y² = x³ + 2x + 2 (mod 17)</span> with 18 points and generator <span class="mono">G = (5, 1)</span>.</p>
          <div class="viz" id="viz-discrete"></div>
          <label for="vd-slider">Walk k·G &nbsp;<span class="dim">(scalar multiplication)</span></label>
          <input type="range" id="vd-slider" min="1" max="18" step="1" value="5" />
          <p class="viz-label" id="vd-label"></p>
          <p class="hint">Note: the two panels use different curves on purpose — the left needs a smooth real-number shape to draw, while this one needs a small <em>prime</em>-order group (19 points) so the toy attack's modular inverses always exist. The group law is identical.</p>
        </article>
      </div>
    </section>

    <section class="exhibit" id="exhibit-attack" aria-labelledby="exhibit-attack-title">
      <div class="section-head">
        <p class="exhibit-tag" aria-hidden="true">Exhibit 3</p>
        <h2 id="exhibit-attack-title">The Nonce-Reuse Attack</h2>
        <p>Why reusing the nonce is fatal — shown as algebra you can follow, then run on real 256-bit keys.</p>
      </div>

      <article class="panel math-panel">
        <h3>Why it works: two equations, two unknowns</h3>
        <pre class="math">Same nonce k, same key d, two messages:
  s₁ = k⁻¹(e₁ + r·d)   ⇒   s₁·k = e₁ + r·d
  s₂ = k⁻¹(e₂ + r·d)   ⇒   s₂·k = e₂ + r·d

Subtract:   (s₁ − s₂)·k = e₁ − e₂
            k = (e₁ − e₂)·(s₁ − s₂)⁻¹            (mod n)

Back-substitute:
            d = (s₁·k − e₁)·r⁻¹                  (mod n)</pre>
        <p>Reusing k forces <span class="mono">r</span> to be identical in both signatures — the public tell — and collapses two unknowns to a solvable linear system.</p>
      </article>

      <article class="panel">
        <h3>Try it yourself on the toy curve</h3>
        <p>Every value below is a small integer. Change the inputs and watch the secret <span class="mono">d</span> fall out of public data.</p>
        <div class="toy-controls">
          <label>Private key d = <output id="toy-d-out">7</output>
            <input type="range" id="toy-d" min="1" max="18" step="1" value="7" /></label>
          <label>Reused nonce k = <output id="toy-k-out">11</output>
            <input type="range" id="toy-k" min="1" max="18" step="1" value="11" /></label>
          <label>Message hash e₁ = <output id="toy-e1-out">5</output>
            <input type="range" id="toy-e1" min="0" max="18" step="1" value="5" /></label>
          <label>Message hash e₂ = <output id="toy-e2-out">9</output>
            <input type="range" id="toy-e2" min="0" max="18" step="1" value="9" /></label>
        </div>
        <div id="toy-attack-output"></div>
      </article>

      <article class="panel danger real-attack">
        <h3>Now on real 256-bit keys</h3>
        <div class="panel-grid two">
          <div class="mini danger">
            <p class="label">VICTIM</p>
            <h4>Alice</h4>
            <p>Private key: <span id="victim-key" class="censored" role="status" aria-live="polite"><span class="sr-only">hidden</span><span aria-hidden="true">████████████████████████████████</span></span></p>
            <p>Public key: <span id="victim-pub" class="mono">pending...</span></p>
          </div>
          <div class="mini">
            <p class="label">ATTACKER</p>
            <h4>Eve</h4>
            <p>Sees two signatures sharing r, then runs the same modular arithmetic.</p>
            <button id="btn-attack" class="btn danger">Run Full Compromise</button>
          </div>
        </div>
        <ol class="timeline" id="attack-timeline" aria-live="polite">
          <li class="step"><h4>Step 1 · Two signed messages</h4><p id="step1">Waiting...</p></li>
          <li class="step"><h4>Step 2 · Spot the reused nonce</h4><p id="step2">Waiting...</p></li>
          <li class="step"><h4>Step 3 · Recover the nonce k</h4><p id="step3">Waiting...</p></li>
          <li class="step"><h4>Step 4 · Recover the private key d</h4><p id="step4">Waiting...</p></li>
          <li class="step"><h4>Step 5 · Forge a new signature</h4><p id="step5">Waiting...</p></li>
        </ol>
        <details id="attack-detail">
          <summary>Show the full 256-bit values</summary>
          <pre class="math" id="attack-fullnums">Run the compromise to populate.</pre>
        </details>
      </article>

      <aside class="history" aria-label="Historical breakages">
        <h3>This has happened, repeatedly</h3>
        <ul>
          <li>Sony PlayStation 3 (2010): a constant nonce in firmware signing exposed the master key.</li>
          <li>Android Bitcoin wallets (2013): weak SecureRandom caused nonce reuse and on-chain theft.</li>
          <li>Debian OpenSSL (2008): broken entropy made keys and nonces guessable at scale.</li>
          <li>TouchTunes jukeboxes (2017): forged signatures enabled payment abuse.</li>
        </ul>
      </aside>
    </section>

    <section class="exhibit" id="exhibit-rfc" aria-labelledby="exhibit-rfc-title">
      <div class="section-head">
        <p class="exhibit-tag" aria-hidden="true">Exhibit 4</p>
        <h2 id="exhibit-rfc-title">RFC 6979 Deterministic Nonces</h2>
        <p>Random nonces are only as safe as the RNG behind them. RFC 6979 derives k from the private key and message hash via HMAC-SHA-256 — reproducible, and impossible to repeat across different messages.</p>
      </div>
      <article class="panel">
        <label for="msg-compare">Message for comparison</label>
        <textarea id="msg-compare" rows="2">Nonce discipline is survival.</textarea>
        <div class="button-row">
          <button id="btn-random-sample" class="btn">Sign Random</button>
          <button id="btn-det-sample" class="btn safe">Sign RFC 6979</button>
          <button id="btn-reset-sample" class="btn ghost">Reset Samples</button>
        </div>
        <p class="hint">Sign the same message twice with each method. Random nonces give different r every time; RFC 6979 gives the <em>same</em> r — deterministic, yet never reused across different messages.</p>
        <div class="compare-grid">
          <div class="panel-inner">
            <h3>Random nonce output</h3>
            <ul id="random-list" class="sig-list" aria-live="polite"></ul>
          </div>
          <div class="panel-inner safe-frame">
            <h3>RFC 6979 output</h3>
            <ul id="det-list" class="sig-list" aria-live="polite"></ul>
          </div>
        </div>
        <button id="btn-safe-attack" class="btn safe">Try the nonce-reuse attack against RFC 6979</button>
        <p id="safe-attack-status" class="status" role="status" aria-live="polite">No test run yet.</p>
      </article>
    </section>

    <section class="exhibit" id="exhibit-wild" aria-labelledby="exhibit-wild-title">
      <div class="section-head">
        <p class="exhibit-tag" aria-hidden="true">Exhibit 5</p>
        <h2 id="exhibit-wild-title">ECDSA In The Wild</h2>
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

    <section class="exhibit" id="exhibit-compare" aria-labelledby="exhibit-compare-title">
      <div class="section-head">
        <p class="exhibit-tag" aria-hidden="true">Exhibit 6</p>
        <h2 id="exhibit-compare-title">ECDSA vs Ed25519</h2>
        <p>Ed25519 was designed later to remove common ECDSA footguns — chiefly the nonce.</p>
      </div>
      <article class="panel table-wrap" tabindex="0" role="region" aria-label="ECDSA versus Ed25519 comparison table">
        <table>
          <caption class="sr-only">Comparison of ECDSA (secp256k1), ECDSA (P-256), and Ed25519 across key properties</caption>
          <thead>
            <tr><th scope="col">Property</th><th scope="col">ECDSA (secp256k1)</th><th scope="col">ECDSA (P-256)</th><th scope="col">Ed25519</th></tr>
          </thead>
          <tbody>
            <tr><th scope="row">Key size</th><td>256 bits</td><td>256 bits</td><td>256 bits</td></tr>
            <tr><th scope="row">Signature size</th><td>~70 DER / 64 raw</td><td>~70 DER / 64 raw</td><td>64 bytes</td></tr>
            <tr><th scope="row">Signing speed</th><td>Fast</td><td>Fast</td><td>Faster</td></tr>
            <tr><th scope="row">Deterministic by default</th><td>No (RFC 6979 needed)</td><td>No (RFC 6979 needed)</td><td>Yes</td></tr>
            <tr><th scope="row">Nonce reuse catastrophic</th><td class="warn">Yes</td><td class="warn">Yes</td><td>No by design</td></tr>
            <tr><th scope="row">Malleable signatures</th><td>Yes</td><td>Yes</td><td>No</td></tr>
            <tr><th scope="row">Best use today</th><td>Bitcoin / Ethereum interoperability</td><td>TLS, JWT, WebAuthn compatibility</td><td>New systems when possible</td></tr>
          </tbody>
        </table>
      </article>
    </section>

    <section class="exhibit" id="reference" aria-labelledby="reference-title">
      <div class="section-head">
        <p class="exhibit-tag" aria-hidden="true">Reference</p>
        <h2 id="reference-title">Glossary &amp; Sources</h2>
        <p>Every term used above, and the primary standards behind every claim.</p>
      </div>
      <dl class="glossary">
        ${GLOSSARY.map(
          (g) => `<div class="gl-item">
            <dt>${g.term}${g.symbol ? ` <span class="gl-sym mono">${g.symbol}</span>` : ''}</dt>
            <dd>${g.definition}</dd>
          </div>`,
        ).join('')}
      </dl>
      <article class="panel refs">
        <h3>Primary sources</h3>
        <ul class="ref-list">
          ${CITATIONS.map(
            (c) => `<li>
              <a href="${c.url}" target="_blank" rel="noopener noreferrer">${c.title}</a>
              <span class="ref-meta">${c.source} · ${c.year}</span>
              <span class="ref-note">${c.note}</span>
            </li>`,
          ).join('')}
        </ul>
      </article>
    </section>

    <footer class="page-footer">
      <p>Educational ECDSA lab — not for production signing. Curve arithmetic by <span class="mono">@noble/curves</span>; ECDSA, the attack, RFC 6979, and the toy curve are implemented from scratch in this repo.</p>
    </footer>
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
const attackFullNums = getById<HTMLPreElement>('attack-fullnums');
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

  step1.textContent = `Alice signs "${result.message1}" and "${result.message2}" reusing nonce k. sig1=(r=${shortHex(result.sig1.r)}, s1=${shortHex(result.sig1.s)}), sig2=(r=${shortHex(result.sig2.r)}, s2=${shortHex(result.sig2.s)}).`;
  step2.textContent = `Both signatures share the same r = ${shortHex(result.sig1.r)}. Identical r is the public proof of nonce reuse.`;

  const e1 = await hashMessage(textToBytes(result.message1), activeCurve);
  const e2 = await hashMessage(textToBytes(result.message2), activeCurve);

  const recovered = await recoverKeyFromNonceReuse(
    result.sig1,
    textToBytes(result.message1),
    result.sig2,
    textToBytes(result.message2),
  );
  if (!recovered) {
    throw new Error('Attack recovery returned null unexpectedly');
  }

  step3.textContent = `k = (e1−e2)·(s1−s2)⁻¹ mod n = ${shortHex(recovered.recoveredNonce, 16)}.`;
  step4.textContent = `d = (s1·k − e1)·r⁻¹ mod n = ${shortHex(privateKeyToBigInt(recovered.recoveredKey), 16)}. This equals Alice's real private key.`;
  step5.textContent = `Eve signs "${result.maliciousMessage}" with the stolen key; verification against Alice's public key returns ${result.forgeryVerifies ? 'TRUE — forgery accepted.' : 'false.'}`;

  const recoveredD = privateKeyToBigInt(recovered.recoveredKey);
  const victimD = privateKeyToBigInt(result.victimKeyPair.privateKey);
  attackFullNums.textContent = [
    `curve            : ${activeCurve}`,
    `n (order)        : ${curveOrder(activeCurve)}`,
    ``,
    `e1 = H("${result.message1}")  : ${e1}`,
    `e2 = H("${result.message2}")  : ${e2}`,
    `r  (shared)      : ${result.sig1.r}`,
    `s1               : ${result.sig1.s}`,
    `s2               : ${result.sig2.s}`,
    ``,
    `recovered k      : ${recovered.recoveredNonce}`,
    `recovered d      : ${recoveredD}`,
    `victim's real d  : ${victimD}`,
    `match            : ${recoveredD === victimD ? '✓ identical — private key fully recovered' : '✗ mismatch'}`,
  ].join('\n');

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
    setStatus(safeAttackStatus, `Attack blocked by construction: different messages ⇒ different nonces ⇒ r1 ≠ r2, so there is no shared nonce to exploit (n=${shortHex(n, 14)}).`, 'ok');
    return;
  }

  setStatus(safeAttackStatus, 'Unexpected result: investigate deterministic nonce implementation.', 'bad');
});

if (!exhibit1KeyPair) {
  setStatus(verifyStatus, 'Generate a keypair to begin.', 'warn');
}

// One shared, debounced live region so dragging a slider announces a single
// concise summary on pause — not a flood on every tick.
const srLive = getById<HTMLDivElement>('sr-live');
const debounce = <A extends unknown[]>(fn: (...args: A) => void, ms: number) => {
  let timer: ReturnType<typeof setTimeout> | undefined;
  return (...args: A) => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
};
const announce = debounce((message: string) => {
  srLive.textContent = message;
}, 450);

// --- Visualizations --------------------------------------------------------
const vizContinuous = getById<HTMLDivElement>('viz-continuous');
const vcSlider = getById<HTMLInputElement>('vc-slider');
const vcDouble = getById<HTMLInputElement>('vc-double');
const vcLabel = getById<HTMLParagraphElement>('vc-label');

const drawContinuous = () => {
  const { svg, label } = renderContinuousCurve(Number(vcSlider.value), vcDouble.checked);
  vizContinuous.innerHTML = svg;
  vcLabel.textContent = label;
  announce(label);
};
vcSlider.addEventListener('input', drawContinuous);
vcDouble.addEventListener('change', drawContinuous);
drawContinuous();

const vizDiscrete = getById<HTMLDivElement>('viz-discrete');
const vdSlider = getById<HTMLInputElement>('vd-slider');
const vdLabel = getById<HTMLParagraphElement>('vd-label');

const drawDiscrete = () => {
  const { svg, label } = renderDiscreteField(Number(vdSlider.value));
  vizDiscrete.innerHTML = svg;
  vdLabel.textContent = label;
  announce(label);
};
vdSlider.addEventListener('input', drawDiscrete);
drawDiscrete();

// --- Interactive toy attack ------------------------------------------------
const toyOutput = getById<HTMLDivElement>('toy-attack-output');
const toyD = getById<HTMLInputElement>('toy-d');
const toyK = getById<HTMLInputElement>('toy-k');
const toyE1 = getById<HTMLInputElement>('toy-e1');
const toyE2 = getById<HTMLInputElement>('toy-e2');
const toyDOut = getById<HTMLOutputElement>('toy-d-out');
const toyKOut = getById<HTMLOutputElement>('toy-k-out');
const toyE1Out = getById<HTMLOutputElement>('toy-e1-out');
const toyE2Out = getById<HTMLOutputElement>('toy-e2-out');

const drawToyAttack = () => {
  toyDOut.value = toyD.value;
  toyKOut.value = toyK.value;
  toyE1Out.value = toyE1.value;
  toyE2Out.value = toyE2.value;
  const { html: toyHtml, summary } = renderToyAttack(
    Number(toyD.value),
    Number(toyK.value),
    Number(toyE1.value),
    Number(toyE2.value),
  );
  toyOutput.innerHTML = toyHtml;
  announce(summary);
};
[toyD, toyK, toyE1, toyE2].forEach((el) => el.addEventListener('input', drawToyAttack));
drawToyAttack();

// --- RFC 6979 warmup demonstration -----------------------------------------
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

// --- Theme toggle (persisted, system-aware) --------------------------------
const themeToggle = getById<HTMLButtonElement>('theme-toggle');
const themeLabel = themeToggle.querySelector<HTMLSpanElement>('.theme-label');

const applyTheme = (theme: 'light' | 'dark') => {
  document.documentElement.setAttribute('data-theme', theme);
  const goesTo = theme === 'dark' ? 'light' : 'dark';
  themeToggle.setAttribute('aria-pressed', theme === 'light' ? 'true' : 'false');
  themeToggle.setAttribute('aria-label', `Switch to ${goesTo} theme (current: ${theme})`);
  themeToggle.setAttribute('title', `Switch to ${goesTo} theme`);
  if (themeLabel) themeLabel.textContent = theme === 'dark' ? 'Dark' : 'Light';
};

const currentTheme = (): 'light' | 'dark' =>
  document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';

applyTheme(currentTheme());

themeToggle.addEventListener('click', () => {
  const next = currentTheme() === 'dark' ? 'light' : 'dark';
  try {
    localStorage.setItem('theme', next);
  } catch {
    // storage may be unavailable (private mode); theme still applies for the session
  }
  applyTheme(next);
});

// --- Active-section highlighting in the top navigation ---------------------
const navLinks = Array.from(document.querySelectorAll<HTMLAnchorElement>('#topnav a'));
const sectionById = new Map(
  navLinks
    .map((link) => {
      const id = link.getAttribute('href')?.slice(1) ?? '';
      const section = document.getElementById(id);
      return section ? ([section, link] as const) : null;
    })
    .filter((entry): entry is readonly [HTMLElement, HTMLAnchorElement] => entry !== null),
);

if (sectionById.size > 0 && 'IntersectionObserver' in window) {
  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        const link = sectionById.get(entry.target as HTMLElement);
        if (!link) continue;
        if (entry.isIntersecting) {
          navLinks.forEach((l) => l.removeAttribute('aria-current'));
          link.setAttribute('aria-current', 'true');
        }
      }
    },
    { rootMargin: '-45% 0px -50% 0px' },
  );
  for (const section of sectionById.keys()) observer.observe(section);
}
