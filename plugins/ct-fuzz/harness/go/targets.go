// Registered Go targets.
//
// Each target is f(public, secret []byte) and uses the inputs in some way.
// The harness times one call. Public input is fresh-random each call;
// secret is fixed (class A) or random (class B) each call.

package main

import (
	"bytes"
	"crypto/elliptic"
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
}

// loadRSAKey returns a fresh 2048-bit RSA key generated at startup.
func loadRSAKey() *rsa.PrivateKey {
	k, _ := rsa.GenerateKey(cryptoRandReader{}, 2048)
	return k
}

type cryptoRandReader struct{}

func (cryptoRandReader) Read(p []byte) (int, error) { return realRandRead(p) }
