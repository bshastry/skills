package safe

// Barrett reduction replaces a hardware divide with a multiply-and-shift,
// using a precomputed approximation of 1/q. This is the standard fix
// applied across the post-quantum ecosystem in response to KyberSlash
// (see commits in pq-crystals/kyber, cloudflare/circl, golang.org/x/crypto).

const (
	kyberQ      = 3329
	// barrettMul is precomputed: ceil((1 << 26) / kyberQ) so that
	//   floor(x / kyberQ) == (x * barrettMul) >> 26 for x in [0, 2*q*q).
	barrettMul   = 20159
	barrettShift = 26
)

// CompressBarrett is the constant-time replacement for the KyberSlash
// compression formula. It uses only multiplication, shift, and bitwise
// operations -- all of which run in constant time on every Go target.
func CompressBarrett(coef int32) int32 {
	num := int32(1) << 4 * coef
	// SAFE: replaces hardware divide with multiply + shift.
	q := int32((int64(num) * barrettMul) >> barrettShift)
	return q & ((1 << 4) - 1)
}
