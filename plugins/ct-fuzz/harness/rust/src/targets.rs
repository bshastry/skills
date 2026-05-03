use crate::{MeasureFn, PrepFn, TargetFn, TargetSpec};
use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use num_bigint::BigUint;
use num_traits::Zero;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use ring::signature::Ed25519KeyPair;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

static SINK: AtomicU64 = AtomicU64::new(0);

fn touch(v: u64) {
    SINK.fetch_add(v, Ordering::Relaxed);
}

fn whole(name: &'static str, secret_len: usize, public_len: usize, inner: usize, f: TargetFn) -> (&'static str, TargetSpec) {
    (name, TargetSpec::whole(secret_len, public_len, inner, f))
}

fn split(name: &'static str, secret_len: usize, public_len: usize, inner: usize, prep: PrepFn, measure: MeasureFn) -> (&'static str, TargetSpec) {
    (name, TargetSpec::split(secret_len, public_len, inner, prep, measure))
}

pub fn register_all() -> Vec<(&'static str, TargetSpec)> {
    let mut v: Vec<(&'static str, TargetSpec)> = Vec::new();

    // ---------- Known constant-time ----------

    v.push(whole("subtle_ConstantTimeEq_32", 32, 32, 2000, Box::new(|pub_, sec| {
        let r = pub_.ct_eq(sec);
        touch(r.unwrap_u8() as u64);
    })));

    v.push(whole("curve25519_dalek_scalar_mul", 32, 32, 1, Box::new(|_pub, sec| {
        let mut k = [0u8; 32];
        k.copy_from_slice(sec);
        let s = Scalar::from_bytes_mod_order(k);
        let p = &s * ED25519_BASEPOINT_TABLE;
        touch(p.compress().to_bytes()[0] as u64);
    })));

    v.push(whole("aes_block_encrypt", 16, 16, 200, Box::new(|pub_, sec| {
        let key = aes::cipher::generic_array::GenericArray::from_slice(sec);
        let cipher = Aes128::new(key);
        let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(pub_);
        cipher.encrypt_block(&mut block);
        touch(block[0] as u64);
    })));

    v.push(whole("sha2_256_secret", 32, 32, 200, Box::new(|_pub, sec| {
        let h = Sha256::digest(sec);
        touch(h[0] as u64);
    })));

    // ---------- Known variable-time ----------

    v.push(whole("naive_eq_32", 32, 32, 2000, Box::new(|pub_, sec| {
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
    })));

    v.push(whole("naive_pkeq_eq", 32, 32, 2000, Box::new(|pub_, sec| {
        if pub_ == sec {
            touch(1);
        }
    })));

    v.push(whole("table_lookup_secret_index", 8, 32, 2000, Box::new(|_pub, sec| {
        let mut table = [0u64; 256];
        for i in 0..256 {
            table[i] = (i as u64).wrapping_mul(0x9e3779b97f4a7c15);
        }
        touch(table[sec[0] as usize]);
    })));

    v.push(whole("num_bigint_mod_secret", 32, 32, 5, Box::new(|pub_, sec| {
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
    })));

    // ---------- Borderline / production ----------

    v.push(whole("ring_constant_time_verify", 32, 32, 2000, Box::new(|pub_, sec| {
        let _ = ring::constant_time::verify_slices_are_equal(pub_, sec);
        touch(0);
    })));

    // ---------- Production: ring AEAD/Ed25519, vary the key, WHOLE pipeline ----------

    v.push(whole("ring_aes128gcm_seal_vary_key", 16, 0, 5, Box::new(|_pub, sec| {
        let unbound = match UnboundKey::new(&AES_128_GCM, sec) {
            Ok(k) => k,
            Err(_) => return,
        };
        let key = LessSafeKey::new(unbound);
        let nonce = Nonce::assume_unique_for_key([0u8; 12]);
        let mut buf = [0xAAu8; 64];
        if key.seal_in_place_separate_tag(nonce, Aad::empty(), &mut buf).is_ok() {
            touch(buf[0] as u64);
        }
    })));

    v.push(whole("ring_aes128gcm_open_invalid_vary_key", 16, 0, 5, Box::new(|_pub, sec| {
        let unbound = match UnboundKey::new(&AES_128_GCM, sec) {
            Ok(k) => k,
            Err(_) => return,
        };
        let key = LessSafeKey::new(unbound);
        let nonce = Nonce::assume_unique_for_key([0u8; 12]);
        let mut buf = [0xAAu8; 80];
        let _ = key.open_in_place(nonce, Aad::empty(), &mut buf);
        touch(buf[0] as u64);
    })));

    v.push(whole("ring_ed25519_sign_vary_key", 32, 0, 1, Box::new(|_pub, sec| {
        let kp = match Ed25519KeyPair::from_seed_unchecked(sec) {
            Ok(k) => k,
            Err(_) => return,
        };
        let msg = [0xAAu8; 64];
        let sig = kp.sign(&msg);
        touch(sig.as_ref()[0] as u64);
    })));

    // ---------- Production: SPLIT mode (prep untimed, measure timed) ----------
    // Compare to whole-pipeline targets above to attribute the dudect signal.

    // ring AES-128-GCM seal — split. Key construction in prep, only seal timed.
    {
        let cipher: RefCell<Option<LessSafeKey>> = RefCell::new(None);
        let prep: PrepFn = Box::new(move |sec: &[u8]| {
            let unbound = match UnboundKey::new(&AES_128_GCM, sec) {
                Ok(k) => k,
                Err(_) => return,
            };
            *cipher.borrow_mut() = Some(LessSafeKey::new(unbound));
        });
        // We need cipher again for measure — but it was moved into prep.
        // Use a separate Rc<RefCell<>> to share between prep and measure.
        let _ = prep; // discard — use the shared variant below
    }

    {
        use std::rc::Rc;
        let cipher: Rc<RefCell<Option<LessSafeKey>>> = Rc::new(RefCell::new(None));
        let cipher_p = cipher.clone();
        let prep: PrepFn = Box::new(move |sec: &[u8]| {
            let unbound = match UnboundKey::new(&AES_128_GCM, sec) {
                Ok(k) => k,
                Err(_) => return,
            };
            *cipher_p.borrow_mut() = Some(LessSafeKey::new(unbound));
        });
        let cipher_m = cipher.clone();
        let measure: MeasureFn = Box::new(move |_pub: &[u8]| {
            let c = cipher_m.borrow();
            let key = match c.as_ref() {
                Some(k) => k,
                None => return,
            };
            let nonce = Nonce::assume_unique_for_key([0u8; 12]);
            let mut buf = [0xAAu8; 64];
            if key.seal_in_place_separate_tag(nonce, Aad::empty(), &mut buf).is_ok() {
                touch(buf[0] as u64);
            }
        });
        v.push(split("ring_aes128gcm_seal_vary_key_split", 16, 0, 5, prep, measure));
    }

    // ring AES-128-GCM open invalid — split.
    {
        use std::rc::Rc;
        let cipher: Rc<RefCell<Option<LessSafeKey>>> = Rc::new(RefCell::new(None));
        let cipher_p = cipher.clone();
        let prep: PrepFn = Box::new(move |sec: &[u8]| {
            let unbound = match UnboundKey::new(&AES_128_GCM, sec) {
                Ok(k) => k,
                Err(_) => return,
            };
            *cipher_p.borrow_mut() = Some(LessSafeKey::new(unbound));
        });
        let cipher_m = cipher.clone();
        let measure: MeasureFn = Box::new(move |_pub: &[u8]| {
            let c = cipher_m.borrow();
            let key = match c.as_ref() {
                Some(k) => k,
                None => return,
            };
            let nonce = Nonce::assume_unique_for_key([0u8; 12]);
            let mut buf = [0xAAu8; 80];
            let _ = key.open_in_place(nonce, Aad::empty(), &mut buf);
            touch(buf[0] as u64);
        });
        v.push(split("ring_aes128gcm_open_invalid_vary_key_split", 16, 0, 5, prep, measure));
    }

    // ring Ed25519 sign — split. KeyPair construction (seed expansion via SHA-512)
    // happens in prep; only the actual sign call is timed.
    {
        use std::rc::Rc;
        let kp: Rc<RefCell<Option<Ed25519KeyPair>>> = Rc::new(RefCell::new(None));
        let kp_p = kp.clone();
        let prep: PrepFn = Box::new(move |sec: &[u8]| {
            *kp_p.borrow_mut() = Ed25519KeyPair::from_seed_unchecked(sec).ok();
        });
        let kp_m = kp.clone();
        let measure: MeasureFn = Box::new(move |_pub: &[u8]| {
            let k = kp_m.borrow();
            if let Some(kp) = k.as_ref() {
                let msg = [0xAAu8; 64];
                let sig = kp.sign(&msg);
                touch(sig.as_ref()[0] as u64);
            }
        });
        v.push(split("ring_ed25519_sign_vary_key_split", 32, 0, 1, prep, measure));
    }

    v
}
