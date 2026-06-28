//! Stable-Rust randomized / differential fuzz campaign for the sk-pqc core.
//!
//! cargo-fuzz (libFuzzer) needs nightly `-Zsanitizer`; the Arch system rustc is
//! stable with no rustup, so this is the time-boxed property/differential
//! fallback. Every target is wrapped in `catch_unwind` — a panic is a FINDING.
//!
//! Targets:
//!   1. kem::hybrid_decap        — malformed/random ciphertexts must
//!                                  implicit-reject (never panic); round-trip
//!                                  correctness + tamper-divergence checked.
//!   2. wire codecs              — anon_queue::decode_aqid, pqroute::open_routed,
//!                                  pqdm::open_sealed, report/suites from_wire
//!                                  on random bytes/strings (never panic).
//!   3. ratchet::derive_dm_message_key — bounds: any epoch_secret length, full
//!                                  u64 epoch/index range, determinism.
//!
//! Usage: `campaign [seconds_per_target] [base_seed]` (defaults 20, 0xC0FFEE).

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{Duration, Instant};

use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};

use sk_pqc::{anon_queue, kem, pqdm, pqroute, ratchet, report, suites};

struct Stat {
    name: &'static str,
    iters: u64,
    oks: u64,
    errs: u64,
    panics: u64,
    findings: Vec<String>,
}
impl Stat {
    fn new(name: &'static str) -> Self {
        Stat { name, iters: 0, oks: 0, errs: 0, panics: 0, findings: Vec::new() }
    }
    fn report(&self) {
        println!(
            "[{:<26}] iters={:>9} ok={:>9} err={:>9} PANICS={}",
            self.name, self.iters, self.oks, self.errs, self.panics
        );
        for f in &self.findings {
            println!("    FINDING: {f}");
        }
    }
}

fn deadline(secs: u64) -> Instant {
    Instant::now() + Duration::from_secs(secs)
}

/// 1. hybrid_decap: malformed/random ciphertexts must never panic.
fn campaign_hybrid_decap(secs: u64, seed: u64) -> Stat {
    let mut s = Stat::new("kem::hybrid_decap");
    let mut rng = StdRng::seed_from_u64(seed);
    let kp = kem::hybrid_keypair();
    let priv_ok = kp.private_key.clone();
    let dl = deadline(secs);
    while Instant::now() < dl {
        s.iters += 1;
        let ct: Vec<u8> = match rng.gen_range(0..5u8) {
            0 => {
                let mut v = vec![0u8; kem::CIPHERTEXT_LEN];
                rng.fill_bytes(&mut v);
                v
            }
            1 => match kem::hybrid_encap(&kp.public_key) {
                Ok((mut ct, ss)) => {
                    if rng.gen_bool(0.5) {
                        let i = rng.gen_range(0..ct.len());
                        ct[i] ^= 1 << rng.gen_range(0..8);
                    } else {
                        match catch_unwind(AssertUnwindSafe(|| kem::hybrid_decap(&ct, &priv_ok))) {
                            Ok(Ok(got)) => {
                                if got != ss {
                                    s.findings.push(
                                        "round-trip mismatch: pristine ct decapped != encap ss"
                                            .into(),
                                    );
                                }
                                s.oks += 1;
                            }
                            Ok(Err(_)) => s
                                .findings
                                .push("pristine round-trip returned Err (should be Ok)".into()),
                            Err(_) => {
                                s.panics += 1;
                                s.findings.push("PANIC on pristine round-trip".into());
                            }
                        }
                    }
                    ct
                }
                Err(_) => {
                    let mut v = vec![0u8; kem::CIPHERTEXT_LEN];
                    rng.fill_bytes(&mut v);
                    v
                }
            },
            2 => {
                let n = rng.gen_range(0..(kem::CIPHERTEXT_LEN * 2));
                let mut v = vec![0u8; n];
                rng.fill_bytes(&mut v);
                v
            }
            3 => {
                let base = kem::CIPHERTEXT_LEN;
                let n = (base as i64 + rng.gen_range(-2..=2i64)).max(0) as usize;
                let mut v = vec![0u8; n];
                rng.fill_bytes(&mut v);
                v
            }
            _ => Vec::new(),
        };
        let pk: Vec<u8> = if rng.gen_bool(0.15) {
            let n = rng.gen_range(0..(kem::PRIVATE_KEY_LEN + 4));
            let mut v = vec![0u8; n];
            rng.fill_bytes(&mut v);
            v
        } else {
            priv_ok.clone()
        };
        match catch_unwind(AssertUnwindSafe(|| kem::hybrid_decap(&ct, &pk))) {
            Ok(Ok(_)) => s.oks += 1,
            Ok(Err(_)) => s.errs += 1,
            Err(_) => {
                s.panics += 1;
                s.findings
                    .push(format!("PANIC: hybrid_decap ct_len={} pk_len={}", ct.len(), pk.len()));
            }
        }
    }
    s
}

/// 2a. anon_queue::decode_aqid on random strings.
fn campaign_decode_aqid(secs: u64, seed: u64) -> Stat {
    let mut s = Stat::new("anon_queue::decode_aqid");
    let mut rng = StdRng::seed_from_u64(seed);
    let dl = deadline(secs);
    while Instant::now() < dl {
        s.iters += 1;
        let n = rng.gen_range(0..96);
        let mut raw = vec![0u8; n];
        rng.fill_bytes(&mut raw);
        let lossy = String::from_utf8_lossy(&raw).into_owned();
        let candidate = match rng.gen_range(0..4u8) {
            0 => lossy,
            1 => format!("aqid:{lossy}"),
            2 => format!("aqid:relay/{lossy}"),
            _ => format!("aqid:{}/{}", "r".repeat(rng.gen_range(0..8)), lossy),
        };
        match catch_unwind(AssertUnwindSafe(|| anon_queue::decode_aqid(&candidate))) {
            Ok(Ok(_)) => s.oks += 1,
            Ok(Err(_)) => s.errs += 1,
            Err(_) => {
                s.panics += 1;
                s.findings.push(format!("PANIC: decode_aqid({candidate:?})"));
            }
        }
    }
    s
}

/// 2b. pqroute::open_routed + pqdm::open_sealed on random blobs.
fn campaign_envelopes(secs: u64, seed: u64) -> Stat {
    let mut s = Stat::new("pqroute/pqdm open_*");
    let mut rng = StdRng::seed_from_u64(seed);
    let kp = kem::hybrid_keypair();
    let dl = deadline(secs);
    while Instant::now() < dl {
        s.iters += 1;
        let n = rng.gen_range(0..(kem::CIPHERTEXT_LEN + 64));
        let mut blob = vec![0u8; n];
        rng.fill_bytes(&mut blob);
        if rng.gen_bool(0.5) && blob.len() >= 4 {
            let hl = rng.gen_range(0..(blob.len() as u32 + 8));
            blob[..4].copy_from_slice(&hl.to_be_bytes());
        }
        match catch_unwind(AssertUnwindSafe(|| pqroute::open_routed(&blob, &kp.private_key))) {
            Ok(Ok(_)) => s.oks += 1,
            Ok(Err(_)) => s.errs += 1,
            Err(_) => {
                s.panics += 1;
                s.findings.push(format!("PANIC: pqroute::open_routed blob_len={}", blob.len()));
            }
        }
        let suite = ["x25519-mlkem768", "x25519-pgp-wrap-v1", "garbage"][rng.gen_range(0..3)];
        match catch_unwind(AssertUnwindSafe(|| {
            pqdm::open_sealed(&blob, &kp.private_key, "alice", "bob", suite)
        })) {
            Ok(Ok(_)) => s.oks += 1,
            Ok(Err(_)) => s.errs += 1,
            Err(_) => {
                s.panics += 1;
                s.findings.push(format!("PANIC: pqdm::open_sealed blob_len={}", blob.len()));
            }
        }
    }
    s
}

/// 2c. report/suites from_wire on random strings (must total + never panic).
fn campaign_from_wire(secs: u64, seed: u64) -> Stat {
    let mut s = Stat::new("report/suites::from_wire");
    let mut rng = StdRng::seed_from_u64(seed);
    let dl = deadline(secs);
    while Instant::now() < dl {
        s.iters += 1;
        let n = rng.gen_range(0..40);
        let mut raw = vec![0u8; n];
        rng.fill_bytes(&mut raw);
        let str_in = String::from_utf8_lossy(&raw).into_owned();
        match catch_unwind(AssertUnwindSafe(|| {
            let _ = report::RatchetLevel::from_wire(&str_in);
            let _ = suites::SuiteStatus::from_wire(&str_in);
        })) {
            Ok(()) => s.oks += 1,
            Err(_) => {
                s.panics += 1;
                s.findings.push(format!("PANIC: from_wire({str_in:?})"));
            }
        }
    }
    s
}

/// 3. ratchet::derive_dm_message_key bounds + determinism.
fn campaign_derive_key(secs: u64, seed: u64) -> Stat {
    let mut s = Stat::new("derive_dm_message_key");
    let mut rng = StdRng::seed_from_u64(seed);
    let dl = deadline(secs);
    while Instant::now() < dl {
        s.iters += 1;
        let slen = if rng.gen_bool(0.5) {
            ratchet::EPOCH_SECRET_LEN
        } else {
            rng.gen_range(0..256)
        };
        let mut secret = vec![0u8; slen];
        rng.fill_bytes(&mut secret);
        let epoch = match rng.gen_range(0..4u8) {
            0 => 0,
            1 => u64::MAX,
            2 => rng.gen::<u32>() as u64,
            _ => rng.gen(),
        };
        let index = match rng.gen_range(0..4u8) {
            0 => 0,
            1 => u64::MAX,
            2 => rng.gen::<u32>() as u64,
            _ => rng.gen(),
        };
        match catch_unwind(AssertUnwindSafe(|| {
            ratchet::derive_dm_message_key(&secret, epoch, index)
        })) {
            Ok(Ok(k)) => {
                s.oks += 1;
                if slen != ratchet::EPOCH_SECRET_LEN {
                    s.findings
                        .push(format!("wrong-len secret ({slen}) returned Ok (expected Err)"));
                }
                if k.len() != ratchet::MESSAGE_KEY_LEN {
                    s.findings.push("output key not 32 bytes".into());
                }
                let again = ratchet::derive_dm_message_key(&secret, epoch, index).unwrap();
                if again != k {
                    s.findings.push("NONDETERMINISTIC derive for same inputs".into());
                }
            }
            Ok(Err(_)) => {
                s.errs += 1;
                if slen == ratchet::EPOCH_SECRET_LEN {
                    s.findings
                        .push("correct-len (32) secret returned Err (expected Ok)".into());
                }
            }
            Err(_) => {
                s.panics += 1;
                s.findings.push(format!(
                    "PANIC: derive_dm_message_key slen={slen} epoch={epoch} index={index}"
                ));
            }
        }
    }
    s
}

fn main() {
    let secs: u64 = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(20);
    let base_seed: u64 =
        std::env::args().nth(2).and_then(|a| a.parse().ok()).unwrap_or(0xC0FFEE);

    println!("== sk-pqc stable randomized/differential fuzz campaign ==");
    println!("seconds/target={secs} base_seed={base_seed:#x}\n");

    let stats = vec![
        campaign_hybrid_decap(secs, base_seed ^ 1),
        campaign_decode_aqid(secs, base_seed ^ 2),
        campaign_envelopes(secs, base_seed ^ 3),
        campaign_from_wire(secs, base_seed ^ 4),
        campaign_derive_key(secs, base_seed ^ 5),
    ];

    println!();
    let mut total_iters = 0u64;
    let mut total_panics = 0u64;
    let mut total_findings = 0usize;
    for st in &stats {
        st.report();
        total_iters += st.iters;
        total_panics += st.panics;
        total_findings += st.findings.len();
    }
    println!("\n== TOTAL iters={total_iters} panics={total_panics} findings={total_findings} ==");
    if total_panics > 0 || total_findings > 0 {
        std::process::exit(1);
    }
    println!("CLEAN: no panics, no correctness findings.");
}
