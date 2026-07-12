# crypto-lab-ecdsa-forge

## What It Is

Browser-based ECDSA (Elliptic Curve Digital Signature Algorithm) demo with full protocol implementation on secp256k1 (Bitcoin, Ethereum) and P-256 (NIST, TLS). Uses @noble/curves for audited field arithmetic; all ECDSA protocol logic is implemented from scratch in this repository. Demonstrates the critical nonce reuse vulnerability that compromised the Sony PS3, Android Bitcoin wallets, and numerous other systems by performing real private key recovery from two signatures sharing a nonce. Shows RFC 6979 deterministic nonces as mitigation, verified against RFC 6979 Appendix A.2.5.

## When to Use It

- Understand why TLS certificates, Bitcoin transactions, and SSH/JWT verification rely on ECDSA.
- Teach PS3 nonce reuse and Android wallet RNG failures with real math, not simulation.
- Learn RFC 6979 deterministic nonce derivation and reproducible ECDSA signing behavior.
- Compare legacy ECDSA pitfalls to safer modern signature defaults like Ed25519.
- Not for production signing libraries; use @noble/curves or platform-native APIs in production.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-ecdsa-forge](https://systemslibrarian.github.io/crypto-lab-ecdsa-forge/)**

The demo visualizes ECDSA on both a hand-checkable toy curve and real 256-bit keys: point addition (chord-and-tangent) and the `k·G` walk that makes the discrete-log gap tangible, a transparent two-equations / two-unknowns nonce-reuse attack that recovers a private key live with an explicit recovered-equals-victim proof, and RFC 6979 deterministic nonces shown as the mitigation. Every term is defined and every claim is cited to FIPS 186-5, SEC 1/2, RFC 6979, and the PS3 disclosure.

## What Can Go Wrong

- This demo uses @noble/curves for scalar multiplication and curve arithmetic. Production systems also need comprehensive side-channel controls and hardened key management.
- The nonce reuse attack here is real. If two signatures share nonce k, private key recovery follows directly from modular arithmetic.
- Browser JavaScript timing is noisy and can leak execution patterns; timing and fault attacks are out of scope but relevant in real signing oracles.
- ECDSA signatures are malleable: both (r, s) and (r, n-s) can verify unless low-S normalization is enforced by protocol rules.

## Real-World Usage

ECDSA is standardized in NIST FIPS 186-5 and SEC 2. It underpins TLS 1.2/1.3 certificates, Bitcoin, Ethereum, SSH ECDSA keys, secure boot chains, JWT ES256 tokens, and WebAuthn/passkeys. Global verification volume is massive (roughly 10^9+ checks daily). RFC 6979 (Pornin, 2013) deterministic nonces are now standard in mature ECDSA deployments to eliminate nonce entropy failures.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-ecdsa-forge
cd crypto-lab-ecdsa-forge
npm install
npm run dev
```

## Related Demos

- [crypto-lab-ed25519-forge](https://systemslibrarian.github.io/crypto-lab-ed25519-forge/) — the safer modern default, with deterministic nonces by construction.
- [crypto-lab-nonce-lattice](https://systemslibrarian.github.io/crypto-lab-nonce-lattice/) — recovers ECDSA keys from biased nonces via the hidden number problem and LLL.
- [crypto-lab-rsa-forge](https://systemslibrarian.github.io/crypto-lab-rsa-forge/) — the other classic signature family (RSA, PSS, PKCS#1) and its pitfalls.
- [crypto-lab-bitcoin-wallet](https://systemslibrarian.github.io/crypto-lab-bitcoin-wallet/) — secp256k1 keys in the BIP-32/39 wallet ecosystem ECDSA signs for.
- [crypto-lab-jwt-forge](https://systemslibrarian.github.io/crypto-lab-jwt-forge/) — JWT/JWS attacks including ES256 and key-confusion failures.

## Development

- Install: `npm install`
- Build: `npm run build`
- Unit tests (Vitest): `npm test`
  - `test/ecdsa.test.ts` — real 256-bit sign/verify round-trips, forgery rejection, and the modular-arithmetic helpers, on both secp256k1 and P-256.
  - `test/attack.test.ts` — nonce-reuse key recovery equals the victim key exactly, the forged signature verifies under the victim public key, and recovery correctly refuses when nonces differ.
  - `test/rfc6979.test.ts` — deterministic-nonce reproducibility plus the RFC 6979 Appendix A.2.5 known-answer vector.
  - `test/toycurve.test.ts` — hand-checkable toy-curve group structure, ECDSA, and exhaustive nonce-reuse recovery across all `(d, k, e1, e2)`.
- Accessibility gate (axe-core, WCAG A/AA): `npm run test:a11y` (builds are gated on this in CI).

## Teaching Features

- **Curve geometry, visualized** — point addition over the reals (chord-and-tangent, plus doubling) and the same group as a finite field of points, with the `k·G` walk that makes the discrete-log gap tangible.
- **Transparent nonce-reuse attack** — the two-equations / two-unknowns derivation, an interactive toy curve (`y² = x³ + 2x + 2 mod 17`, prime order 19) where every value is a hand-checkable small integer, and the same attack run live on real 256-bit keys with full values and an explicit recovered-equals-victim proof.
- **Glossary & primary sources** — every term defined, every claim cited to FIPS 186-5, SEC 1/2, RFC 6979, and the PS3 disclosure.
- **Accessible & responsive** — skip link, ARIA landmarks/live regions, keyboard-navigable, light/dark theme, reduced-motion support, and a mobile layout down to small screens.

## License

Educational demo repository.

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
