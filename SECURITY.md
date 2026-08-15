# Security policy — sk_pqc

`sk_pqc` is the sovereign shared Rust PQC core for the SK ecosystem. This document states
its threat model, its cryptographic provenance (what is reused vs. what is original), the
supported versions, and how to report a vulnerability.

> ⚠️ **Experimental, pre-1.0, NOT independently security-audited.** No third-party
> security audit, fuzzing, or formal review has been performed on this crate. The
> primitives bind vetted upstreams (RustCrypto `ml-kem`, `x25519-dalek`, `aes-gcm`,
> `hkdf`, `sha2`, `hmac`, `subtle`); the original code is the combiner wiring and the
> wire/label layout. A passing test suite proves interop and determinism, **not** the
> absence of side-channels or protocol flaws. **Review it yourself before production
> use.**

---

## Honest claims (read first)

`sk_pqc` is a **hybrid** scheme. Its key-distribution surfaces stay confidential as long
as **either** the classical X25519 leg **or** the ML-KEM-768 leg is unbroken. It is
**not** "quantum-proof", "quantum-safe", or "unbreakable" and makes no such claim — those
three words are mechanically forbidden in any externally-visible note (`report::FORBIDDEN_WORDS`).

- ML-KEM-768 is standardized as **NIST FIPS 203**. The companion signature standard
  **FIPS 204** (ML-DSA) is referenced but **not** implemented in this crate.
- AES-256-GCM is symmetric, only Grover-relevant, and already quantum-acceptable; the hard
  problem this crate solves is **key distribution**, not bulk encryption.
- A ratchet over a *classical* KEM is still harvest-now-decrypt-later (HNDL) exposed. The
  self-report says so regardless of ratchet level.

---

## Cryptographic provenance — no hand-rolled crypto

The security of this crate **binds** vetted implementations. We never implement lattice,
elliptic-curve, AEAD, MAC, or hash math ourselves. Only the *combiner wiring*, the wire
layout, and the KDF labels are original SK code.

| Primitive | Crate (provenance) | Role |
| --- | --- | --- |
| ML-KEM-768 (FIPS 203) | RustCrypto `ml-kem` 0.2.1 | post-quantum KEM leg |
| X25519 | `x25519-dalek` 2 (dalek-cryptography) | classical KEM/DH leg |
| HKDF-SHA256 (RFC 5869) | `hkdf` 0.12 + `sha2` 0.10 (RustCrypto) | combiner + key schedule |
| AES-256-GCM | `aes-gcm` 0.10 (RustCrypto) | authenticated body sealing |
| HMAC-SHA256 | `hmac` 0.12 + `sha2` (RustCrypto) | deniable queue authenticator |
| Constant-time compare | `subtle` 2 (dalek-cryptography) | MAC/tag verification |
| CSPRNG | `rand` 0.8 `OsRng` | all key/nonce/id generation |

The crate contains no `unsafe` of its own and performs no I/O. Malformed input returns a
typed error (`KemError`, `RatchetError`, `PqDmError`, `PqRouteError`, `AnonQueueError`,
`GroupRatchetError`, `DmSessionError`) — never a panic, never an error oracle that
distinguishes "wrong key" from "tampered ciphertext".

---

## Threat model

**Assets.** Message/DM/group-chat plaintext; routing metadata; the unlinkability of queue
addresses; the integrity of the negotiated crypto suite.

**Primary adversary — Harvest-Now-Decrypt-Later (HNDL).** A network adversary that records
all ciphertext today and decrypts later with a cryptographically-relevant quantum computer
(CRQC). **Mitigation:** every confidentiality surface seals to the **hybrid** KEM; a
recorded transcript stays confidential unless **both** the X25519 **and** the ML-KEM-768
leg are broken. ML-KEM-768 (FIPS 203) defeats the quantum leg; X25519 defeats a flaw in
ML-KEM. This is the explicit design driver for `kem`, `pqdm`, `pqroute`, `group_ratchet`,
and the `ratchet`/`dm_session` epoch rekey.

**Active in-transit tamper.** Bit-flips, ciphertext substitution, AAD/header rewriting.
**Mitigation:** AES-256-GCM authenticates every sealed body; the `(epoch, index)` pair
(`ratchet`/`dm_session`) and the negotiated suite id (`pqdm`) and the plaintext route
header (`pqroute`) are bound into the AEAD AAD, so a moved frame, a stripped PQ option, or
a rewritten next-hop fails to open (`PqDmError::Open` / `PqRouteError::Open`). ML-KEM uses
implicit rejection: a tampered KEM ciphertext yields a pseudo-random secret that simply
fails the AEAD — not an error oracle.

**Silent downgrade (MITM strips the hybrid prekey).** **Mitigation:** the negotiated suite
id is bound into the `pqdm` downgrade-lock AAD (canonical JSON, identical bytes across
implementations). A peer that forces a classical downgrade changes the suite the sender
seals under, so the downgrade cannot be *silent*: the recipient's open fails or the
recorded suite no longer reads hybrid, and the `report` self-report surfaces a `classical`
line rather than an invented hybrid one.

**Honesty / over-claim risk (a first-class threat here).** A report that over-states the
crypto posture is itself a security failure. **Mitigation:** `report` resolves status
*only* from the `suites` registry (unknown ⇒ `classical` ⇒ never quantum-resistant),
screens every note against `FORBIDDEN_WORDS`, and `assert_honest` is a runtime backstop.

**Compromise of an epoch / member key.** **Mitigation:** independent per-epoch secrets give
post-compromise security (PCS) — a leaked epoch secret reveals only that epoch — and
rekey-on-membership-change gives forward secrecy (FS); a removed member cannot derive
future epoch keys (`group_ratchet`, `dm_session`).

### Out of scope / known limitations

- **Endpoint compromise.** If an endpoint is owned, plaintext and keys are exposed; no
  transport crypto helps.
- **Metadata at small anonymity sets.** `anon_queue` unlinkable ids reduce *relay-side*
  metadata leakage, but on a small sovereign network (e.g. 3 nodes) timing/volume
  correlation and candidate paucity can still deanonymize. It raises the bar for a passive
  relay; it is not an anonymity cloak.
- **Identity / authentication / PKI, key management, key rotation policy, and transport**
  are the consumers' responsibility, not this crate's.
- **Side channels** beyond the constant-time guarantees of the underlying RustCrypto/dalek
  crates and `subtle` are out of scope.
- **`anon_queue` deniable MAC** provides authenticity + deniability, **never**
  non-repudiation.

---

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | ✅ active (pre-1.0; the wire contract is stabilizing toward 1.0) |
| < 0.1 | ❌ |

Until 1.0, security fixes land on the latest 0.1.x. Wire-affecting changes are major bumps
per SOP.md section 5 / the sk-standards VERSION_STANDARD and are parity-verified against the Python
and Dart implementations before release.

---

## Reporting a vulnerability

Report privately — **do not** open a public issue for a security report.

- Use GitHub **private vulnerability reporting** on `github.com/smilinTux/sk-pqc-rs`
  (Security ▸ Report a vulnerability), or
- Contact the smilinTux maintainers through the org's listed private security channel.

Please include: affected version/commit, the module and construction involved, a minimal
reproduction (ideally a failing test vector), and — if it is an interop/wire issue —
whether the Python (`sk-pqc-py`) or Dart (`sk_pqc`) implementation is also affected, since
a wire-level fix must be coordinated across all three.

**Acknowledgement SLA: within 72 hours.** After acknowledgement you can expect a severity
assessment, a remediation plan, and a target fix or mitigation within 90 days, with the
disclosure date coordinated with you. A finding in a **bound upstream** (RustCrypto
`ml-kem`, `x25519-dalek`, `aes-gcm`, `hkdf`, `hmac`, `subtle`) will be forwarded upstream
and tracked here. Reporters are credited unless they ask otherwise.

### Safe harbour

We will not pursue or support legal action against anyone who, in good faith, finds and
reports a vulnerability under this policy: research only against your **own** keys, data
and installations; no access to or exfiltration of other people's data; no denial of
service, spam, or social engineering of maintainers or users; and no public disclosure
before a coordinated date. Good-faith research conducted this way is authorised, and we
will work with you rather than against you. If you are unsure whether an action is in
scope, ask first via the private channel above.

### What we especially want to hear about

- A combiner deviation: XOR instead of concat-then-KDF, the wrong concat order, or a
  missing domain separation label.
- Wire-format or length confusion that could cause cross-implementation secret divergence.
- A path where malformed input **panics** instead of returning a typed `*Error`.
- A **classical** surface reported as `quantum_resistant: true`, or any silent downgrade
  that the `report` module fails to surface.
- A forbidden word reaching an emitted note despite `report::is_honest_note`.
- Any place a claim in these docs overstates assurance, including the tier statement.

---

## CRYPTOGRAPHY_STANDARD compliance statement

Standard: [sk-standards `standards/CRYPTOGRAPHY_STANDARD.md`](https://github.com/smilinTux/sk-standards/blob/main/standards/CRYPTOGRAPHY_STANDARD.md).

`sk-pqc` (Rust) conforms to the SK CRYPTOGRAPHY_STANDARD honest-claim and binding rules:

- Uses **"post-quantum" / "quantum-resistant"**, never "quantum-proof", "quantum-safe" or
  "unbreakable". **This is enforced in code**, not only in review: `report::FORBIDDEN_WORDS`
  plus `report::is_honest_note` reject any emitted note containing one, and
  `SurfaceReport::assert_honest` is the debug-time backstop.
- **Every claim is scoped to a named surface** and cites its standard: **FIPS 203**
  (ML-KEM-768); FIPS 204 is referenced only to scope signatures **out**; RFC 5869 (HKDF),
  RFC 7748 (X25519), SP 800-38D (AES-GCM), NIST CSWP 39 (crypto-agility).
- **Hybrid is stated correctly:** confidential if **either** leg holds. Concat-then-KDF
  (`HKDF-SHA256(X25519_ss || MLKEM768_ss)`, X25519 first), **never XOR, never pure-PQ**,
  and the classical leg is never replaced.
- **AES-256-GCM is never described as quantum-broken.** It is symmetric and Grover-only,
  and is already quantum-acceptable; the hard problem addressed here is key distribution.
- **No classical suite is ever marked quantum-resistant.** `assert_honest` panics if one
  is, and a ratchet over a classical KEM is still reported as HNDL-exposed regardless of
  ratchet level.
- **Binds vetted crates; hand-rolls no primitives.** Only the combiner wiring and the
  wire/label layout are original.
- **Maturity tier declared: T2 (Hybrid KEM), T1 met, T3 out of scope.** See
  [SOP.md](SOP.md) section 9 for per-axis evidence.

**Two honest limits on the mechanical gate**, so it is not over-read: it screens the
three absolute-guarantee words, **not** the standard's wider list (which also forbids
"CNSA 2.0 compliant", "FIPS 206" and "Falcon" in claims); and it screens the strings the
library **emits**, not documentation prose, which must be able to name a forbidden word
in order to prohibit it. Those remain a human review gate (SOP.md appendix A).
