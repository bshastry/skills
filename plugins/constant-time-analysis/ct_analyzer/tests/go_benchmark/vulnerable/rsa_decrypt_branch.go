package vulnerable

// Bleichenbacher / Manger style padding oracle. Branching on the value of
// the padding byte leaks whether the decryption is well-formed; the timing
// of "return early on bad pad" vs "verify the rest of the message" is what
// powered every PKCS#1 v1.5 padding oracle from 1998 onward.

// CheckPKCS1PadVulnerable inspects a decrypted RSA block. A real
// constant-time implementation must look at every byte and combine the
// failure conditions with bitwise OR (see crypto/rsa.decryptPKCS1v15 for
// the Go stdlib's hardened version). This version returns early.
//
// VULNERABLE: branches reveal where in the padding the failure occurred.
func CheckPKCS1PadVulnerable(em []byte) (msg []byte, ok bool) {
	if len(em) < 11 {
		return nil, false
	}
	// VULNERABLE: branch reveals the first byte mismatch.
	if em[0] != 0x00 || em[1] != 0x02 {
		return nil, false
	}
	// VULNERABLE: loop with secret-dependent termination.
	i := 2
	for i < len(em) && em[i] != 0x00 {
		i++
	}
	if i == len(em) {
		return nil, false
	}
	return em[i+1:], true
}
