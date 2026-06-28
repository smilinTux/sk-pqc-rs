//! proptest property tests (shrinking) — the stable counterpart to libFuzzer's
//! minimization. Run: `cargo test -p sk-pqc-fuzz-harness` (or in this dir).
//!
//! Invariants asserted as properties over arbitrary inputs:
//!   * hybrid_decap never panics; correct-length => Ok (implicit reject),
//!     wrong-length => Err.
//!   * decode_aqid / open_routed / open_sealed / from_wire never panic.
//!   * derive_dm_message_key: len==32 => Ok(32 bytes) & deterministic;
//!     len!=32 => Err; never panics.

use proptest::prelude::*;
use sk_pqc::{anon_queue, kem, pqdm, pqroute, ratchet, report, suites};

proptest! {
    #![proptest_config(ProptestConfig { cases: 4096, ..ProptestConfig::default() })]

    #[test]
    fn hybrid_decap_never_panics(ct in proptest::collection::vec(any::<u8>(), 0..2400)) {
        let kp = kem::hybrid_keypair();
        let res = kem::hybrid_decap(&ct, &kp.private_key);
        if ct.len() == kem::CIPHERTEXT_LEN {
            prop_assert!(res.is_ok(), "correct-length ct must implicit-reject to Ok");
        } else {
            prop_assert!(res.is_err(), "wrong-length ct must Err");
        }
    }

    #[test]
    fn hybrid_decap_fuzzed_privkey_never_panics(
        ct in proptest::collection::vec(any::<u8>(), 0..1200),
        pk in proptest::collection::vec(any::<u8>(), 0..2500),
    ) {
        let _ = kem::hybrid_decap(&ct, &pk);
    }

    #[test]
    fn decode_aqid_never_panics(s in ".{0,128}") {
        let _ = anon_queue::decode_aqid(&s);
    }

    #[test]
    fn open_routed_never_panics(blob in proptest::collection::vec(any::<u8>(), 0..1400)) {
        let kp = kem::hybrid_keypair();
        let _ = pqroute::open_routed(&blob, &kp.private_key);
    }

    #[test]
    fn open_sealed_never_panics(
        blob in proptest::collection::vec(any::<u8>(), 0..1400),
        suite in prop_oneof![Just("x25519-mlkem768"), Just("x25519-pgp-wrap-v1"), Just("zzz")],
    ) {
        let kp = kem::hybrid_keypair();
        let _ = pqdm::open_sealed(&blob, &kp.private_key, "a", "b", suite);
    }

    #[test]
    fn from_wire_never_panics(s in ".{0,64}") {
        let _ = report::RatchetLevel::from_wire(&s);
        let _ = suites::SuiteStatus::from_wire(&s);
    }

    #[test]
    fn derive_dm_message_key_bounds(
        secret in proptest::collection::vec(any::<u8>(), 0..200),
        epoch in any::<u64>(),
        index in any::<u64>(),
    ) {
        let res = ratchet::derive_dm_message_key(&secret, epoch, index);
        if secret.len() == ratchet::EPOCH_SECRET_LEN {
            let k = res.expect("32-byte secret must yield Ok");
            prop_assert_eq!(k.len(), ratchet::MESSAGE_KEY_LEN);
            let again = ratchet::derive_dm_message_key(&secret, epoch, index).unwrap();
            prop_assert_eq!(k, again, "must be deterministic");
        } else {
            prop_assert!(res.is_err(), "non-32 secret must Err");
        }
    }
}
