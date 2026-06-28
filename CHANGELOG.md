# Changelog

All notable changes to `sk_pqc` (crate [`sk-pqc`](https://crates.io/crates/sk-pqc))
are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Because the wire format is a
cross-language interop contract, **any wire-affecting change is a major (breaking)
release** — see [SOP.md](SOP.md) §7.

## [Unreleased]

### Added
- **Optional `dart` feature** — flutter_rust_bridge (frb) bindings (`src/frb_api.rs`)
  so the Dart `sk_pqc` package can be backed by this same pure-Rust core over FFI (the
  Dart twin of the `python`/PyO3 binding). Exposes `hybrid_keypair` / `hybrid_encap` /
  `hybrid_decap` / `derive_dm_message_key` (+ `suite_id` / `wire_sizes`). Gated and
  **off by default**: `cargo build` / `cargo test` stay pure-Rust and the 99 in-tree
  tests are unchanged. Committed generated glue (`src/frb_generated.rs` + the sibling
  `sk-pqc-dart/lib/src/rust/`), a `flutter_rust_bridge.yaml` codegen config, and a Dart
  parity harness (`sk-pqc-dart/test/rust_frb_parity_test.dart`) proving byte-for-byte
  agreement with the pure-Dart impl (shared KAT + hybrid-KEM cross-decapsulation both
  directions). Native binding; web/wasm is future work. No wire change.

## [0.1.0] — 2026-06-27

Initial release — **published to crates.io** as
[`sk-pqc`](https://crates.io/crates/sk-pqc) (`cargo add sk-pqc`, import `use sk_pqc;`).
Companion packages: PyPI [`sk-pqc`](https://pypi.org/project/sk-pqc/) and pub.dev
[`sk_pqc`](https://pub.dev/packages/sk_pqc) — all import as `sk_pqc`, byte-for-byte
interoperable.

First crates.io cut of the **full SK confidentiality toolkit** in Rust — a clean-room
port of the Python `skcomms` / `skchat` / `sksecurity` PQC modules, parity-verified
against Python-computed vectors.

### Added

- **`kem`** — hybrid KEM combiner `x25519-mlkem768`: X25519 (`x25519-dalek`) composed
  with ML-KEM-768 (RustCrypto `ml-kem`, FIPS 203) via concat-then-KDF
  `HKDF-SHA256(X25519_ss ‖ MLKEM768_ss)` → 32-byte shared secret. `hybrid_keypair` /
  `hybrid_encap` / `hybrid_decap` and the fixed wire-length constants (1216-B public
  key, 2432-B secret key, 1120-B ciphertext, 32-B shared secret).
- **`ratchet`** — 1:1 DM epoch-ratchet key schedule: deterministic, index-addressable
  per-message key derivation, hybrid epoch-secret wrap/unwrap, rekey bound (50 msgs OR
  7 days), `DmRatchet` driver.
- **`dm_session`** — stateful DM session driver: epoch lifecycle / auto-rekey, KAM
  piggyback, `pqdr1:` sealed-frame token codec, snapshot/restore.
- **`group_ratchet`** — group epoch-ratchet with per-member hybrid-KEM-wrapped epoch
  secret (`wrap_epoch_secret` / `unwrap_epoch_secret`) and symmetric per-message key
  derivation (`EpochRatchet`) — the HNDL fix for group chat.
- **`pqdm`** — hybrid PQXDH-style message sealing (`seal` / `open_sealed`) with the
  negotiated-suite downgrade-lock AAD and `negotiate_suite`.
- **`pqroute`** — the `pqroute1` metadata-routing envelope: relay-readable
  AAD-authenticated outer header + hybrid-sealed inner metadata/content
  (`seal_routed` / `open_routed` / `read_route_header` / `replace_route_header`).
- **`anon_queue`** — anonymous, no-identity addressing: independent recipient/sender
  queue ids, the `aqid:` address codec, and a deniable HMAC authenticator
  (`auth_tag` / `verify_tag`).
- **`suites`** — the crypto-suite registry (crypto-agility seam): single source of
  truth mapping each `suite_id` to kind/status/primitives/FIPS refs and the one
  `is_quantum_resistant` predicate.
- **`report`** — the honest PQC self-report: builds per-surface posture, screens every
  note against the forbidden marketing words (`quantum-proof` / `quantum-safe` /
  `unbreakable`), and never marks a classical suite quantum-resistant.
- Project doc set per the **sk-standards** DOC_SOP: README, SOP, SECURITY,
  ARCHITECTURE, CONTRIBUTING, CODE_OF_CONDUCT, this CHANGELOG, and an Apache-2.0
  LICENSE.

### Security / honest-claims

- This is a **hybrid** scheme: confidential as long as **either** the classical X25519
  leg **or** the ML-KEM-768 leg holds. It is **not** "quantum-proof," "quantum-safe,"
  or "unbreakable," and the `report` module mechanically rejects those words.
- ML-KEM-768 is standardized as **FIPS 203**. The companion signature standard
  (FIPS 204 / ML-DSA) is referenced but **not** implemented here — this crate is
  KEM + sealing + addressing, not signatures.
- No hand-rolled lattice/curve/AEAD/MAC math: all primitives bind vetted RustCrypto /
  dalek crates; only the combiner wiring and wire/label layout are original.

### Known limitations

- **Experimental · pre-1.0 · NOT independently security-audited.** No third-party
  audit, fuzzing, or formal review yet.
- PyO3 / FFI bindings are intentionally **not** included in this crate (a later
  coordination task).

[Unreleased]: https://github.com/smilinTux/sk-pqc-rs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/smilinTux/sk-pqc-rs/releases/tag/v0.1.0
