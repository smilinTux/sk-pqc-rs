//! Optional PyO3 bindings — gated behind the `python` feature.
//!
//! Exposes the deterministic key-schedule and the hybrid KEM so the Python SK
//! services can be backed by this pure-Rust core (no OpenSSL, no liboqs — the
//! ML-KEM-768 leg is RustCrypto `ml-kem` (**FIPS 203**), the X25519 leg is
//! `x25519-dalek`). The wheel is built abi3 (`extension-module`) so it spans
//! CPython 3.8+ and never links libpython.
//!
//! Importable as `sk_pqc_rs` — deliberately distinct from the pure-Python
//! `sk_pqc` package so both can be imported side-by-side for parity checks.
//!
//! These are thin wrappers: every byte of crypto wiring lives in [`crate::kem`]
//! and [`crate::ratchet`]; here we only marshal `bytes` <-> `&[u8]` and map the
//! crate error types onto `ValueError`. **Hybrid**, not "quantum-proof": the
//! derived secret holds as long as **either** the X25519 leg **or** the
//! ML-KEM-768 leg holds.

// The `?` operator on the already-`PyErr` results below desugars to an
// identity `PyErr -> PyErr` `From` conversion that clippy flags as useless;
// it is intrinsic to the `map_err(..)?` binding pattern, so allow it here.
#![allow(clippy::useless_conversion)]

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::kem;
use crate::ratchet;

/// `hybrid_keypair() -> (public_key: bytes, private_key: bytes)`.
///
/// Fresh hybrid keypair: 1216-byte public (`X25519_pub ‖ MLKEM768_ek`) and
/// 2432-byte private (`X25519_seed ‖ MLKEM768_dk`). Byte-compatible with
/// `sk_pqc.hybrid_keypair()`.
#[pyfunction]
fn hybrid_keypair(py: Python<'_>) -> (Py<PyBytes>, Py<PyBytes>) {
    let kp = kem::hybrid_keypair();
    (
        PyBytes::new_bound(py, &kp.public_key).unbind(),
        PyBytes::new_bound(py, &kp.private_key).unbind(),
    )
}

/// `hybrid_encap(peer_public_key: bytes) -> (ciphertext: bytes, shared_secret: bytes)`.
///
/// Encapsulate to a 1216-byte peer hybrid public key. Returns the 1120-byte
/// ciphertext (`X25519_eph_pub ‖ MLKEM768_ct`) and the 32-byte shared secret.
/// Raises `ValueError` on a wrong-length key. Wire-compatible with
/// `sk_pqc.hybrid_encap()` — a ciphertext from either side decaps on the other.
#[pyfunction]
fn hybrid_encap(py: Python<'_>, peer_public_key: &[u8]) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let (ct, ss) =
        kem::hybrid_encap(peer_public_key).map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok((
        PyBytes::new_bound(py, &ct).unbind(),
        PyBytes::new_bound(py, &ss).unbind(),
    ))
}

/// `hybrid_decap(ciphertext: bytes, private_key: bytes) -> bytes`.
///
/// Decapsulate a 1120-byte ciphertext with a 2432-byte hybrid private key →
/// 32-byte shared secret. Raises `ValueError` only on a wrong *length*; ML-KEM
/// implicit rejection means a tampered ciphertext yields a pseudo-random secret
/// (no error, no oracle). Byte-compatible with `sk_pqc.hybrid_decap()`.
#[pyfunction]
fn hybrid_decap(py: Python<'_>, ciphertext: &[u8], private_key: &[u8]) -> PyResult<Py<PyBytes>> {
    let ss = kem::hybrid_decap(ciphertext, private_key)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(PyBytes::new_bound(py, &ss).unbind())
}

/// `derive_dm_message_key(epoch_secret: bytes, epoch: int, index: int) -> bytes`.
///
/// Deterministic, index-addressable 32-byte DM message key. Raises `ValueError`
/// if `epoch_secret` is not 32 bytes. Byte-for-byte identical to
/// `sk_pqc.derive_dm_message_key()` (shared HKDF labels / KAT).
#[pyfunction]
fn derive_dm_message_key(
    py: Python<'_>,
    epoch_secret: &[u8],
    epoch: u64,
    index: u64,
) -> PyResult<Py<PyBytes>> {
    let key = ratchet::derive_dm_message_key(epoch_secret, epoch, index)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(PyBytes::new_bound(py, &key).unbind())
}

/// The `sk_pqc_rs` Python module.
#[pymodule]
fn sk_pqc_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__doc__", "Rust-backed hybrid X25519+ML-KEM-768 (FIPS 203) PQC core — PyO3 bindings for sk-pqc-rs. Hybrid (either-leg), not quantum-proof.")?;
    m.add("SUITE_ID", kem::SUITE_ID)?;
    m.add("PUBLIC_KEY_LEN", kem::PUBLIC_KEY_LEN)?;
    m.add("PRIVATE_KEY_LEN", kem::PRIVATE_KEY_LEN)?;
    m.add("CIPHERTEXT_LEN", kem::CIPHERTEXT_LEN)?;
    m.add("SHARED_SECRET_LEN", kem::SHARED_SECRET_LEN)?;
    m.add_function(wrap_pyfunction!(hybrid_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(hybrid_encap, m)?)?;
    m.add_function(wrap_pyfunction!(hybrid_decap, m)?)?;
    m.add_function(wrap_pyfunction!(derive_dm_message_key, m)?)?;
    Ok(())
}
