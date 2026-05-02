use crate::TargetSpec;
use std::sync::atomic::{AtomicU64, Ordering};

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use num_bigint::BigUint;
use num_traits::Zero;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

static SINK: AtomicU64 = AtomicU64::new(0);

fn touch(v: u64) {
    SINK.fetch_add(v, Ordering::Relaxed);
}

pub fn register_all() -> Vec<(&'static str, TargetSpec)> {
    let mut v: Vec<(&'static str, TargetSpec)> = Vec::new();

    // ---------- Known constant-time ----------

    v.push((
        "subtle_ConstantTimeEq_32",
        TargetSpec {
            secret_len: 32,
            public_len: 32,
            inner: 2000,
            func: Box::new(|pub_, sec| {
                let r = pub_.ct_eq(sec);
                touch(r.unwrap_u8() as u64);
            }),
        },
    ));

    v.push((
        "curve25519_dalek_scalar_mul",
        TargetSpec {
            secret_len: 32,
            public_len: 32,
            inner: 1,
            func: Box::new(|_pub, sec| {
                let mut k = [0u8; 32];
                k.copy_from_slice(sec);
                // Wide-reduce to ensure canonical scalar (no rejection asymmetry).
                let s = Scalar::from_bytes_mod_order(k);
                let p = &s * ED25519_BASEPOINT_TABLE;
                touch(p.compress().to_bytes()[0] as u64);
            }),
        },
    ));

    v.push((
        "aes_block_encrypt",
        TargetSpec {
            secret_len: 16,
            public_len: 16,
            inner: 200,
            func: Box::new(|pub_, sec| {
                let key = aes::cipher::generic_array::GenericArray::from_slice(sec);
                let cipher = Aes128::new(key);
                let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(pub_);
                cipher.encrypt_block(&mut block);
                touch(block[0] as u64);
            }),
        },
    ));

    v.push((
        "sha2_256_secret",
        TargetSpec {
            secret_len: 32,
            public_len: 32,
            inner: 200,
            func: Box::new(|_pub, sec| {
                let h = Sha256::digest(sec);
                touch(h[0] as u64);
            }),
        },
    ));

    // ---------- Known variable-time ----------

    v.push((
        "naive_eq_32",
        TargetSpec {
            secret_len: 32,
            public_len: 32,
            inner: 2000,
            func: Box::new(|pub_, sec| {
                let mut eq = true;
                for i in 0..pub_.len().min(sec.len()) {
                    if pub_[i] != sec[i] {
                        eq = false;
                        break;
                    }
                }
                if eq {
                    touch(1);
                }
            }),
        },
    ));

    v.push((
        "naive_pkeq_eq",
        TargetSpec {
            secret_len: 32,
            public_len: 32,
            inner: 2000,
            func: Box::new(|pub_, sec| {
                if pub_ == sec {
                    touch(1);
                }
            }),
        },
    ));

    v.push((
        "table_lookup_secret_index",
        TargetSpec {
            secret_len: 8,
            public_len: 32,
            inner: 2000,
            func: Box::new(|_pub, sec| {
                let mut table = [0u64; 256];
                for i in 0..256 {
                    table[i] = (i as u64).wrapping_mul(0x9e3779b97f4a7c15);
                }
                touch(table[sec[0] as usize]);
            }),
        },
    ));

    v.push((
        "num_bigint_mod_secret",
        TargetSpec {
            secret_len: 32,
            public_len: 32,
            inner: 5,
            func: Box::new(|pub_, sec| {
                let x = BigUint::from_bytes_be(sec);
                let m = BigUint::from_bytes_be(pub_);
                if m.is_zero() {
                    return;
                }
                let r = x % m;
                let bytes = r.to_bytes_be();
                if let Some(b) = bytes.first() {
                    touch(*b as u64);
                }
            }),
        },
    ));

    // ---------- Borderline / production ----------

    v.push((
        "ring_constant_time_verify",
        TargetSpec {
            secret_len: 32,
            public_len: 32,
            inner: 2000,
            func: Box::new(|pub_, sec| {
                let _ = ring::constant_time::verify_slices_are_equal(pub_, sec);
                touch(0);
            }),
        },
    ));

    v
}
