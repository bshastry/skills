// Package vulnerable contains known-bad crypto patterns used to validate
// the ct_analyzer Go support. DO NOT use in production.
//
// kyberslash_division.go reproduces the KyberSlash family of vulnerabilities
// (https://kyberslash.cr.yp.to/), in which post-quantum lattice-based
// cryptosystems perform integer division on secret-derived values.
//
// Important Go-specific subtlety: when the divisor is a *compile-time
// constant*, Go's SSA optimizer rewrites `x / k` into a multiply-by-magic-
// number sequence (IMULQ + SARQ) that runs in constant time. This means a
// naive Go port of a vulnerable C reference implementation may
// *accidentally* be constant-time, while the original C version IS
// vulnerable.
//
// Real KyberSlash exploitation in Go requires the divisor to be loaded from
// a runtime value (e.g. a parameter or struct field). The two functions
// below cover both paths so the analyzer can be tested against the realistic
// scenario where a maintainer adapted the public modulus into a struct.
package vulnerable

// KyberParams holds runtime-loaded KEM parameters. In production this is
// initialised once from a key blob; from the compiler's point of view, both
// fields are unknown at compile time.
type KyberParams struct {
	Q  int32 // public modulus, e.g. 3329
	D  int32 // compression bit-width
}

// CompressKyberSlash is the textbook (vulnerable) ML-KEM compression
// formula c = round(((1 << d) * x) / q). The divisor and shift amount come
// from a runtime struct, so the compiler must emit a hardware divide.
//
// Detected: IDIVL (amd64), SDIVW/REMW (arm64), DIVW/REMW (riscv64).
func CompressKyberSlash(coef int32, p *KyberParams) int32 {
	num := (int32(1) << uint(p.D)) * coef
	// VULNERABLE: KyberSlash-style integer divide by a runtime modulus.
	q := num / p.Q
	r := num % p.Q
	if r >= p.Q/2 {
		q++
	}
	return q & ((1 << uint(p.D)) - 1)
}

// DecompressKyberSlashAlt uses unsigned division. The runtime-loaded params
// prevent Go's SSA from rewriting the divide into a multiply-by-magic.
func DecompressKyberSlashAlt(c uint32, p *KyberParams) uint32 {
	d := uint(p.D)
	q := uint32(p.Q)
	// VULNERABLE: unsigned divide by runtime modulus on secret-derived input.
	return (c*q + (1<<(d-1))) / (1 << d)
}
