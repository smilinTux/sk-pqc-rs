#!/usr/bin/env python3
"""Cross-implementation PARITY: Rust-via-PyO3 (`sk_pqc_rs`) == Python (`sk_pqc`).

Proves the Rust core can back the Python services byte-for-byte:

  1. `derive_dm_message_key` — deterministic, so we assert *byte-for-byte equality*
     between the two implementations across the known KAT vectors (and against the
     pinned hex literals shared with the Rust in-tree tests / Dart KAT).

  2. Hybrid X25519+ML-KEM-768 (FIPS 203) KEM — encap/decap carry fresh randomness,
     so we prove parity by *cross-decapsulation*: a ciphertext produced by one
     implementation MUST decapsulate to the identical 32-byte secret on the other,
     in BOTH directions. That is the real interop contract (shared wire format +
     identical HKDF combiner). Hybrid = secure if EITHER leg holds; not quantum-proof.

Run:  ~/.skenv/bin/python tests/parity_python.py
"""
import sys

import sk_pqc          # pure-Python (liboqs + pyca)
import sk_pqc_rs       # Rust core via PyO3 (ml-kem + x25519-dalek, no OpenSSL)

# Known-answer vectors shared with the Rust in-tree tests (epoch_secret = bytes(range(32))).
ES = bytes(range(32))
KAT_RANGE = {
    (7, 3): "abca41b038c1565004c201741f896ae0c122fd8f6716ba4b85c850e5d163e6bc",
    (7, 4): "ee18766d0fb4c31b03bb544a300232008fee43197d177d584bbed77ebd497834",
    (0, 0): "976feb338842bce61bde060cc8559d66472e1c1c9edcfba3ae70cabb39e3f39a",
    (1, 0): "5cf5ac603c0e9dd2165bf583930e5a2b5549e3b98fd1057de3fead1184610422",
}
# Second pinned vector from the Rust unit tests (epoch_secret = bytes([0x42]*32)).
KAT_42 = (bytes([0x42] * 32), 7, 3,
          "74095f508856520198d56192d8cfd3247f05f5c10f3b33b165e6f64ea1daaddf")

failures = []


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        failures.append(name)


def main():
    print("== derive_dm_message_key parity (Rust-PyO3 vs Python vs pinned KAT) ==")
    for (epoch, index), expected in KAT_RANGE.items():
        rs = sk_pqc_rs.derive_dm_message_key(ES, epoch, index)
        py = sk_pqc.derive_dm_message_key(ES, epoch, index)
        check(f"derive(range32, e={epoch}, i={index}): rust==python", rs == py)
        check(f"derive(range32, e={epoch}, i={index}): rust==KAT hex", rs.hex() == expected)

    es42, e42, i42, hex42 = KAT_42
    rs = sk_pqc_rs.derive_dm_message_key(es42, e42, i42)
    py = sk_pqc.derive_dm_message_key(es42, e42, i42)
    check("derive(0x42*32, e=7, i=3): rust==python", rs == py)
    check("derive(0x42*32, e=7, i=3): rust==KAT hex", rs.hex() == hex42)

    # Bad-length epoch secret must raise on the Rust side too.
    try:
        sk_pqc_rs.derive_dm_message_key(b"\x00" * 16, 0, 0)
        check("derive(short secret) raises", False)
    except ValueError:
        check("derive(short secret) raises ValueError", True)

    print("== hybrid KEM cross-decapsulation (FIPS 203 ML-KEM-768 + X25519) ==")
    # Direction A: Python keypair + Python encap  ->  Rust decap.
    kp = sk_pqc.hybrid_keypair()
    check("python keypair wire lengths", len(kp.public_key) == sk_pqc_rs.PUBLIC_KEY_LEN
          and len(kp.private_key) == sk_pqc_rs.PRIVATE_KEY_LEN)
    ct, ss_py = sk_pqc.hybrid_encap(kp.public_key)
    ss_rs = sk_pqc_rs.hybrid_decap(ct, kp.private_key)
    check("python-encap -> rust-decap secret matches", ss_rs == ss_py)

    # Direction B: Rust keypair + Rust encap  ->  Python decap.
    pub_rs, priv_rs = sk_pqc_rs.hybrid_keypair()
    check("rust keypair wire lengths", len(pub_rs) == sk_pqc.PUBLIC_KEY_LEN
          and len(priv_rs) == sk_pqc.PRIVATE_KEY_LEN)
    ct_rs, ss_rs2 = sk_pqc_rs.hybrid_encap(pub_rs)
    ss_py2 = sk_pqc.hybrid_decap(ct_rs, priv_rs)
    check("rust-encap -> python-decap secret matches", ss_py2 == ss_rs2)

    # Direction C: Python keypair + Rust encap -> Python decap (combiner symmetry).
    ct_rs2, ss_rs3 = sk_pqc_rs.hybrid_encap(kp.public_key)
    ss_py3 = sk_pqc.hybrid_decap(ct_rs2, kp.private_key)
    check("python-keypair + rust-encap -> python-decap matches", ss_py3 == ss_rs3)

    # Wrong-length key surfaces as ValueError on the Rust binding.
    try:
        sk_pqc_rs.hybrid_encap(b"\x00" * 10)
        check("hybrid_encap(short key) raises", False)
    except ValueError:
        check("hybrid_encap(short key) raises ValueError", True)

    print()
    if failures:
        print(f"PARITY FAILED: {len(failures)} check(s): {failures}")
        sys.exit(1)
    print("PARITY OK: Rust-via-PyO3 == Python sk_pqc byte-for-byte.")


if __name__ == "__main__":
    main()
