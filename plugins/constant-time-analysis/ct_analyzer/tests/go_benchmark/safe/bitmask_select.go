package safe

import "crypto/subtle"

// SelectSafe is a constant-time conditional move using crypto/subtle. The
// subtle.ConstantTimeSelect function is implemented with bitwise ops that
// the Go compiler is not allowed to optimize back into a branch.
func SelectSafe(cond int, a, b uint32) uint32 {
	if subtle.ConstantTimeEq(int32(cond), 1) == 1 {
		// This branch is on a public selector value, not on secret data.
		return a
	}
	return b
}

// MaskSelectSafe demonstrates the manual bit-mask pattern that crypto
// libraries use when they cannot afford the call overhead of crypto/subtle.
//
// The mask is computed from the comparison and used to blend the two values
// without branching.
func MaskSelectSafe(cond uint32, a, b uint32) uint32 {
	// SAFE: turn the boolean into an all-ones / all-zeros mask without
	// branching, then blend.
	mask := uint32(0) - (cond & 1)
	return (a & mask) | (b & ^mask)
}
