package vulnerable

// ML-DSA (FIPS 204) decompose: given a coefficient r in Z_q, split it into
// (r1, r0) such that r = r1 * 2*gamma2 + r0 with |r0| <= gamma2.
//
// The reference implementations in several projects (including early NIST
// submissions and pqcrypto/circl) perform this with native integer division.
// Because the coefficient is derived from the signing key, this is a textbook
// data-dependent timing leak that lets an attacker recover the secret after
// observing enough signatures.
//
// See:
//   - "KyberSlash: Exploiting secret-dependent division timings in Kyber",
//     2023.
//   - Bernstein, Lange, "Curves, Cycles and Side-Channels", 2024.

const (
	mldsaQ      = 8380417            // ML-DSA modulus
	mldsaG87    = (mldsaQ - 1) / 32  // gamma2 for ML-DSA-87
	mldsaG44    = (mldsaQ - 1) / 88  // gamma2 for ML-DSA-44 / 65
	mldsaBeta44 = mldsaG44 - 175      // beta for ML-DSA-44
)

// DecomposeVulnerable is the textbook (vulnerable) ML-DSA decompose. Both
// the divide and the modulo on the secret coefficient leak via timing.
func DecomposeVulnerable(r, gamma2 int32) (r1, r0 int32) {
	twoGamma2 := 2 * gamma2
	// VULNERABLE: integer divide on secret coefficient r.
	r1 = r / twoGamma2
	// VULNERABLE: integer modulo on secret coefficient r.
	r0 = r % twoGamma2
	if r0 > gamma2 {
		r0 -= twoGamma2
		r1++
	}
	return r1, r0
}

// UseHintVulnerable mixes a divide on a key-derived value with branches that
// depend on the hint bit. Both the IDIV and the conditional jump leak.
func UseHintVulnerable(r, hint, gamma2 int32) int32 {
	r1, r0 := DecomposeVulnerable(r, gamma2)
	m := (mldsaQ - 1) / (2 * gamma2)
	// VULNERABLE: branch on hint, which is derived from the signature.
	if hint == 0 {
		return r1
	}
	// VULNERABLE: branch on r0 sign, plus a modulo on key material.
	if r0 > 0 {
		return (r1 + 1) % (m + 1)
	}
	return (r1 - 1 + m + 1) % (m + 1)
}
