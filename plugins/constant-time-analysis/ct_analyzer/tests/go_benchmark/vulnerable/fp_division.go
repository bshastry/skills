package vulnerable

// Floating-point division has variable latency on every modern CPU
// (DIVSD on amd64, FDIVD on arm64/riscv64). It should never appear on
// a code path that touches secret data. Some elliptic-curve scalar
// reduction implementations inadvertently use float64 for performance,
// which has been the source of multiple CVEs.

// ReduceWithFloat is a textbook (vulnerable) modular reduction that uses
// the floating-point divide instruction. Both DIVSD and the subsequent
// FCVT have data-dependent latency.
func ReduceWithFloat(x, modulus uint64) uint64 {
	// VULNERABLE: DIVSD / FDIV on secret operand x.
	q := uint64(float64(x) / float64(modulus))
	return x - q*modulus
}
