package vulnerable

// Variable-time MAC / signature / token comparison. This is the most common
// real-world side-channel bug. Lucky Thirteen (2013), the Vaudenay padding
// oracle (2002), and dozens of authentication CVEs all exploit early-exit
// equality checks. Go provides crypto/subtle for this exact reason.

// EqualVulnerable returns true if a and b are byte-identical, using a loop
// that exits on the first mismatch. The number of iterations executed leaks
// the index of the first differing byte, which lets a remote attacker
// brute-force a MAC byte-by-byte.
//
// VULNERABLE: early-exit comparison on secret-equal data.
func EqualVulnerable(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// VerifyMACVulnerable is a realistic HMAC verification anti-pattern.
func VerifyMACVulnerable(expected, got []byte) bool {
	// VULNERABLE: bytes.Equal early-exits.
	if len(expected) != len(got) {
		return false
	}
	for i := 0; i < len(expected); i++ {
		if expected[i] != got[i] {
			return false
		}
	}
	return true
}
