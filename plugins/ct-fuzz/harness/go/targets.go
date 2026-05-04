// Registered Go targets.
//
// Each target is f(public, secret []byte) and uses the inputs in some way.
// The harness times one call. Public input is fresh-random each call;
// secret is fixed (class A) or random (class B) each call.

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"math/big"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/curve25519"
)

// sink prevents the optimizer from eliding work whose result is unused.
var sink uint64

func registerAll() {
	// ---------- Known constant-time (precision targets) ----------

	// crypto/subtle.ConstantTimeCompare on 32-byte buffers.
	register("subtle_ConstantTimeCompare_32", 32, 32, 2000, func(pub, sec []byte) {
		sink += uint64(subtle.ConstantTimeCompare(pub, sec))
	})

	// crypto/subtle.ConstantTimeCopy: cmov-style. dst is closure-captured to
	// keep the allocator out of the timed region.
	{
		dst := make([]byte, 32)
		register("subtle_ConstantTimeCopy_32", 32, 32, 1000, func(pub, sec []byte) {
			subtle.ConstantTimeCopy(int(sec[0]&1), dst, pub)
			sink += uint64(dst[0])
		})
	}

	// curve25519 X25519 scalar mult: documented constant-time.
	register("curve25519_X25519", 32, 32, 1, func(pub, sec []byte) {
		out, err := curve25519.X25519(sec, pub[:32])
		if err == nil {
			sink += uint64(out[0])
		}
	})

	// edwards25519 scalar mult on basepoint: constant-time.
	// Use SetUniformBytes (64-byte input, mod-L reduction) so both classes
	// always reach the scalar-mult — no rejection-sampling asymmetry.
	register("edwards25519_ScalarBaseMult", 64, 32, 1, func(pub, sec []byte) {
		scalar, err := edwards25519.NewScalar().SetUniformBytes(sec)
		if err != nil {
			return
		}
		p := edwards25519.NewIdentityPoint().ScalarBaseMult(scalar)
		bs := p.Bytes()
		sink += uint64(bs[0])
	})

	// ---------- Known variable-time (recall targets) ----------

	// bytes.Equal: early-exit byte comparison.
	register("bytes_Equal_32", 32, 32, 2000, func(pub, sec []byte) {
		if bytes.Equal(pub, sec) {
			sink++
		}
	})

	// Naive byte loop with early exit on first mismatch.
	register("naive_eq_32", 32, 32, 2000, func(pub, sec []byte) {
		eq := true
		for i := 0; i < len(pub) && i < len(sec); i++ {
			if pub[i] != sec[i] {
				eq = false
				break
			}
		}
		if eq {
			sink++
		}
	})

	// Table lookup indexed by secret byte (cache timing risk).
	register("table_lookup_secret_index", 8, 32, 2000, func(pub, sec []byte) {
		var table [256]uint64
		for i := range table {
			table[i] = uint64(i) * 0x9e3779b97f4a7c15
		}
		// Index a 256-entry table by the first secret byte.
		sink += table[sec[0]]
		_ = pub
	})

	// math/big.Int.Mod: division is variable-time.
	register("bigint_mod_secret", 32, 32, 5, func(pub, sec []byte) {
		x := new(big.Int).SetBytes(sec)
		m := new(big.Int).SetBytes(pub)
		if m.Sign() == 0 {
			return
		}
		r := new(big.Int).Mod(x, m)
		if len(r.Bits()) > 0 {
			sink += uint64(r.Bits()[0])
		}
	})

	// ---------- Borderline / production targets ----------

	// crypto/elliptic P-256 ScalarBaseMult. Modern Go uses the constant-time
	// nistec implementation; older Go versions did not.
	register("elliptic_P256_ScalarBaseMult", 32, 0, 1, func(pub, sec []byte) {
		_ = pub
		x, y := elliptic.P256().ScalarBaseMult(sec)
		if x != nil {
			sink += uint64(x.Bits()[0])
			_ = y
		}
	})

	// RSA decryption — two variants. With rng=nil Go SKIPS blinding (variable-
	// time, known leaky). With rng=cryptoRandReader Go applies blinding (CT-ish).
	rsaKey := loadRSAKey()
	rsaRand := cryptoRandReader{}
	// Class A: ciphertext = 0xAA-fill (pub buf). Class B: random ciphertext.
	// The "secret" buffer is the ciphertext — sec varies per class, pub stays fixed.
	register("rsa_decrypt_unblinded", 256, 128, 1, func(pub, sec []byte) {
		_ = pub
		_, _ = rsa.DecryptPKCS1v15(nil, rsaKey, sec)
	})
	register("rsa_decrypt_blinded", 256, 128, 1, func(pub, sec []byte) {
		_ = pub
		_, _ = rsa.DecryptPKCS1v15(rsaRand, rsaKey, sec)
	})

	// SHA-256 of secret: HMAC-style; should be constant-time in input length.
	register("sha256_secret", 32, 32, 200, func(pub, sec []byte) {
		_ = pub
		h := sha256.Sum256(sec)
		sink += uint64(h[0])
	})

	// ---------- Production targets: vary the KEY, fixed plaintext/message ----------
	// These are the public APIs production Go code calls for AEAD and signatures.
	// Threat model: attacker submits chosen plaintexts/messages (held fixed
	// across our test) and observes wall-clock latency; we ask whether timing
	// depends on the secret key.

	// AES-128-GCM seal — varying 16-byte AES key.
	{
		nonce := make([]byte, 12) // fixed all-zeros
		pt := bytes.Repeat([]byte{0xAA}, 64)
		dst := make([]byte, 0, 80) // 64 bytes pt + 16 bytes tag
		register("aes128gcm_seal_vary_key", 16, 0, 5, func(pub, sec []byte) {
			_ = pub
			block, err := aes.NewCipher(sec)
			if err != nil {
				return
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				return
			}
			ct := gcm.Seal(dst[:0], nonce, pt, nil)
			sink += uint64(ct[0])
		})
	}

	// AES-128-GCM open with bogus tag — varying key. Always fails authentication.
	// Tests whether the failure-path timing leaks the key (Bleichenbacher-class).
	{
		nonce := make([]byte, 12)
		bogusCt := bytes.Repeat([]byte{0xAA}, 80) // 64-byte payload + 16-byte tag
		dst := make([]byte, 0, 64)
		register("aes128gcm_open_invalid_vary_key", 16, 0, 5, func(pub, sec []byte) {
			_ = pub
			block, err := aes.NewCipher(sec)
			if err != nil {
				return
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				return
			}
			out, err := gcm.Open(dst[:0], nonce, bogusCt, nil)
			if err == nil && len(out) > 0 {
				sink += uint64(out[0])
			}
		})
	}

	// Ed25519 sign — varying 32-byte private seed. Sign expands the seed via
	// SHA-512 internally and runs scalar mult on the basepoint. Both should be CT.
	{
		msg := bytes.Repeat([]byte{0xAA}, 64)
		register("ed25519_sign_vary_key", 32, 0, 1, func(pub, sec []byte) {
			_ = pub
			priv := ed25519.NewKeyFromSeed(sec)
			sig := ed25519.Sign(priv, msg)
			sink += uint64(sig[0])
		})
	}

	// ECDSA P-256 sign — varying 32-byte private scalar. Modern Go (1.18+) uses
	// crypto/internal/nistec for constant-time scalar mult. Pre-1.18 was variable-
	// time and exploitable. SignASN1 requires PublicKey.X/Y so we derive via
	// ScalarBaseMult — this means each call performs two scalar mults (key
	// derivation + sign), modeling the key-import-then-sign pipeline.
	{
		hash := bytes.Repeat([]byte{0xAA}, 32)
		register("ecdsa_p256_sign_vary_key", 32, 0, 1, func(pub, sec []byte) {
			_ = pub
			// Clamp to ensure D in [1, N-1].
			var d [32]byte
			copy(d[:], sec)
			d[0] &= 0x7F
			if d == ([32]byte{}) {
				d[31] = 1
			}
			x, y := elliptic.P256().ScalarBaseMult(d[:])
			priv := &ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y},
				D:         new(big.Int).SetBytes(d[:]),
			}
			sig, err := ecdsa.SignASN1(rand.Reader, priv, hash)
			if err == nil && len(sig) > 0 {
				sink += uint64(sig[0])
			}
		})
	}

	// ---------- Production targets: SPLIT (prep untimed, measure timed) ----------
	// The same operations as above, but with the per-call cipher/key construction
	// moved OUT of the timed window. Compare to the whole-pipeline variants to
	// see whether the dudect signal lives in the cipher core or in the scaffolding.

	// AES-128-GCM seal, prep/measure split: only the gcm.Seal call is timed.
	{
		nonce := make([]byte, 12)
		pt := bytes.Repeat([]byte{0xAA}, 64)
		dst := make([]byte, 0, 80)
		var gcmState cipher.AEAD
		prep := func(sec []byte) {
			block, err := aes.NewCipher(sec)
			if err != nil {
				return
			}
			gcmState, _ = cipher.NewGCM(block)
		}
		measure := func(pub []byte) {
			_ = pub
			if gcmState == nil {
				return
			}
			ct := gcmState.Seal(dst[:0], nonce, pt, nil)
			sink += uint64(ct[0])
		}
		registerSplit("aes128gcm_seal_vary_key_split", 16, 0, 5, prep, measure)
	}

	// AES-128-GCM open with bogus tag, split. Only gcm.Open is timed.
	{
		nonce := make([]byte, 12)
		bogusCt := bytes.Repeat([]byte{0xAA}, 80)
		dst := make([]byte, 0, 64)
		var gcmState cipher.AEAD
		prep := func(sec []byte) {
			block, err := aes.NewCipher(sec)
			if err != nil {
				return
			}
			gcmState, _ = cipher.NewGCM(block)
		}
		measure := func(pub []byte) {
			_ = pub
			if gcmState == nil {
				return
			}
			out, err := gcmState.Open(dst[:0], nonce, bogusCt, nil)
			if err == nil && len(out) > 0 {
				sink += uint64(out[0])
			}
		}
		registerSplit("aes128gcm_open_invalid_vary_key_split", 16, 0, 5, prep, measure)
	}

	// Ed25519 sign, split. Key seed expansion (SHA-512) is in prep; only the
	// scalar-mult-and-output sign step is timed.
	{
		msg := bytes.Repeat([]byte{0xAA}, 64)
		var privKey ed25519.PrivateKey
		prep := func(sec []byte) {
			privKey = ed25519.NewKeyFromSeed(sec)
		}
		measure := func(pub []byte) {
			_ = pub
			sig := ed25519.Sign(privKey, msg)
			sink += uint64(sig[0])
		}
		registerSplit("ed25519_sign_vary_key_split", 32, 0, 1, prep, measure)
	}

	// ECDSA P-256 sign, split. Key derivation (ScalarBaseMult to get
	// PublicKey.X/Y, big.Int.SetBytes) is in prep; only ecdsa.SignASN1 is timed.
	{
		hash := bytes.Repeat([]byte{0xAA}, 32)
		var privKey *ecdsa.PrivateKey
		prep := func(sec []byte) {
			var d [32]byte
			copy(d[:], sec)
			d[0] &= 0x7F
			if d == ([32]byte{}) {
				d[31] = 1
			}
			x, y := elliptic.P256().ScalarBaseMult(d[:])
			privKey = &ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y},
				D:         new(big.Int).SetBytes(d[:]),
			}
		}
		measure := func(pub []byte) {
			_ = pub
			sig, err := ecdsa.SignASN1(rand.Reader, privKey, hash)
			if err == nil && len(sig) > 0 {
				sink += uint64(sig[0])
			}
		}
		registerSplit("ecdsa_p256_sign_vary_key_split", 32, 0, 1, prep, measure)
	}

	// golang.org/x/crypto/curve25519.X25519 — split version. Vary the scalar.
	// X25519(scalar, point) — fixed peer point, vary the scalar. Production
	// X25519 used by TLS 1.3 ECDHE.
	{
		peer := bytes.Repeat([]byte{0x09}, 32) // basepoint-like fixed peer
		var scalar [32]byte
		prep := func(sec []byte) {
			copy(scalar[:], sec)
		}
		measure := func(pub []byte) {
			_ = pub
			out, err := curve25519.X25519(scalar[:], peer)
			if err == nil && len(out) > 0 {
				sink += uint64(out[0])
			}
		}
		registerSplit("curve25519_X25519_split", 32, 0, 1, prep, measure)
	}

	// Go stdlib ML-KEM-768 Decapsulate — varying the private key. Production
	// post-quantum KEM. Threat model: attacker submits a fixed ciphertext to
	// victim, victim Decapsulates with their private key; timing leak reveals
	// key bits.
	{
		// Pre-build a valid encapsulation+ciphertext from a reference key so
		// our ciphertext input is well-formed (otherwise decap exercises
		// the implicit-rejection path which is also CT but a different test).
		refKey, _ := mlkem.GenerateKey768()
		_, ciphertext := refKey.EncapsulationKey().Encapsulate()
		_ = ciphertext
		var dk *mlkem.DecapsulationKey768
		// 64-byte secret = ML-KEM seed (d || z, 32+32 bytes).
		prep := func(sec []byte) {
			var seed [64]byte
			copy(seed[:], sec)
			k, err := mlkem.NewDecapsulationKey768(seed[:])
			if err == nil {
				dk = k
			}
		}
		measure := func(pub []byte) {
			_ = pub
			if dk == nil {
				return
			}
			ss, err := dk.Decapsulate(ciphertext)
			if err == nil && len(ss) > 0 {
				sink += uint64(ss[0])
			}
		}
		registerSplit("mlkem768_decapsulate_vary_key_split", 64, 0, 1, prep, measure)
	}

	// ---------- v5: SUB-REGION annotation. Time exactly one phase. ----------

	// AES-128-GCM key schedule only: aes.NewCipher(sec).
	{
		var stashed [16]byte
		prep := func(sec []byte) { copy(stashed[:], sec) }
		measure := func(pub []byte) {
			_ = pub
			block, err := aes.NewCipher(stashed[:])
			if err == nil {
				_ = block
				sink++
			}
		}
		registerSplit("aes128gcm_keysched_only", 16, 0, 50, prep, measure)
	}

	// AES-128-GCM NewGCM only: cipher.NewGCM(block) given a pre-built cipher.Block.
	{
		var blockState cipher.Block
		prep := func(sec []byte) {
			b, err := aes.NewCipher(sec)
			if err == nil {
				blockState = b
			}
		}
		measure := func(pub []byte) {
			_ = pub
			gcm, err := cipher.NewGCM(blockState)
			if err == nil {
				_ = gcm
				sink++
			}
		}
		registerSplit("aes128gcm_newgcm_only", 16, 0, 50, prep, measure)
	}
}

// loadRSAKey returns a fresh 2048-bit RSA key generated at startup.
func loadRSAKey() *rsa.PrivateKey {
	k, _ := rsa.GenerateKey(cryptoRandReader{}, 2048)
	return k
}

type cryptoRandReader struct{}

func (cryptoRandReader) Read(p []byte) (int, error) { return realRandRead(p) }
