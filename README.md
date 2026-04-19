# crypto-lab-ecdsa-forge

Browser-based ECDSA lab on secp256k1 and P-256 with a live nonce-reuse key theft demo and RFC 6979 deterministic nonce mitigation.

## What It Is
Browser-based ECDSA (Elliptic Curve Digital Signature Algorithm) demo with full protocol implementation on secp256k1 (Bitcoin, Ethereum) and P-256 (NIST, TLS). Uses @noble/curves for audited field arithmetic; all ECDSA protocol logic is implemented from scratch in this repository. Demonstrates the critical nonce reuse vulnerability that compromised the Sony PS3, Android Bitcoin wallets, and numerous other systems by performing real private key recovery from two signatures sharing a nonce. Shows RFC 6979 deterministic nonces as mitigation, verified against RFC 6979 Appendix A.2.5.

## When to Use It
- Understand why TLS certificates, Bitcoin transactions, and SSH/JWT verification rely on ECDSA.
- Teach PS3 nonce reuse and Android wallet RNG failures with real math, not simulation.
- Learn RFC 6979 deterministic nonce derivation and reproducible ECDSA signing behavior.
- Compare legacy ECDSA pitfalls to safer modern signature defaults like Ed25519.
- Not for production signing libraries; use @noble/curves or platform-native APIs in production.

## Live Demo
https://systemslibrarian.github.io/crypto-lab-ecdsa-forge/

## What Can Go Wrong
- This demo uses @noble/curves for scalar multiplication and curve arithmetic. Production systems also need comprehensive side-channel controls and hardened key management.
- The nonce reuse attack here is real. If two signatures share nonce k, private key recovery follows directly from modular arithmetic.
- Browser JavaScript timing is noisy and can leak execution patterns; timing and fault attacks are out of scope but relevant in real signing oracles.
- ECDSA signatures are malleable: both (r, s) and (r, n-s) can verify unless low-S normalization is enforced by protocol rules.

## Real-World Usage
ECDSA is standardized in NIST FIPS 186-5 and SEC 2. It underpins TLS 1.2/1.3 certificates, Bitcoin, Ethereum, SSH ECDSA keys, secure boot chains, JWT ES256 tokens, and WebAuthn/passkeys. Global verification volume is massive (roughly 10^9+ checks daily). RFC 6979 (Pornin, 2013) deterministic nonces are now standard in mature ECDSA deployments to eliminate nonce entropy failures.

## Development
- Install: `npm install`
- Build: `npm run build`
- Run checks:
  - `npx tsx test/phase1-check.ts`
  - `npx tsx test/phase2-check.ts`
  - `npx tsx test/rfc6979.test.ts`

## License
Educational demo repository.
