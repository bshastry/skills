package vulnerable

// Variable-time scalar multiplication. Real ECDH and ECDSA implementations
// must perform the same set of point operations regardless of which bits of
// the scalar are 1 -- otherwise the timing of each iteration leaks the
// scalar. This is the basis of the original Kocher 1996 timing attack and
// of every textbook square-and-multiply timing leak.

// PointDouble and PointAdd are stubs; we only care about the control flow.
type Point struct{ X, Y, Z uint64 }

func PointDouble(p Point) Point { return Point{p.X * 2, p.Y * 2, p.Z * 2} }
func PointAdd(a, b Point) Point { return Point{a.X + b.X, a.Y + b.Y, a.Z + b.Z} }

// ScalarMulVulnerable is the textbook (vulnerable) double-and-add ladder.
// The branch on the secret bit means the attacker observes "did this round
// take time T (bit 0) or T + addCost (bit 1)?" and recovers the scalar.
//
// VULNERABLE: secret-dependent control flow -> conditional branches on key bits.
func ScalarMulVulnerable(scalar uint64, base Point) Point {
	r := Point{0, 0, 1}
	for i := 63; i >= 0; i-- {
		r = PointDouble(r)
		// VULNERABLE: branch on bit of secret scalar.
		if (scalar>>uint(i))&1 == 1 {
			r = PointAdd(r, base)
		}
	}
	return r
}
