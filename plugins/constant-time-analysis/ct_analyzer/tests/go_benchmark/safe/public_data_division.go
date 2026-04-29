package safe

// Division on public, non-secret data. The analyzer is a structural tool
// without data-flow analysis, so it WILL flag these as ERRORs. They are
// expected false positives for the user to triage. We keep them in the
// benchmark to track the false-positive rate over time.

// BlocksRequired computes how many cipher blocks fit in messageLen bytes.
// messageLen is a public input (length of the ciphertext, not its content),
// so dividing by the public block size is safe.
func BlocksRequired(messageLen int, blockSize int) int {
	// EXPECTED FALSE POSITIVE: divide on public lengths is fine.
	return (messageLen + blockSize - 1) / blockSize
}
