package safe

// Montgomery ladder for scalar multiplication. Both branches of the if/else
// would be present in the textbook version; here we use a constant-time
// swap so the same operations execute on every iteration.

type Point struct{ X, Y, Z uint64 }

func pointDouble(p Point) Point { return Point{p.X * 2, p.Y * 2, p.Z * 2} }
func pointAdd(a, b Point) Point { return Point{a.X + b.X, a.Y + b.Y, a.Z + b.Z} }

// cswap is constant-time: it computes a mask from the bit and uses XOR
// blending so both halves of the swap are always executed.
func cswap(bit uint64, a, b *Point) {
	mask := uint64(0) - (bit & 1)
	a.X, b.X = a.X^((a.X^b.X)&mask), b.X^((a.X^b.X)&mask)
	a.Y, b.Y = a.Y^((a.Y^b.Y)&mask), b.Y^((a.Y^b.Y)&mask)
	a.Z, b.Z = a.Z^((a.Z^b.Z)&mask), b.Z^((a.Z^b.Z)&mask)
}

// ScalarMulSafe performs the same set of operations every iteration; the
// bit only steers a constant-time swap, not the control flow.
func ScalarMulSafe(scalar uint64, base Point) Point {
	r0 := Point{0, 0, 1}
	r1 := base
	for i := 63; i >= 0; i-- {
		bit := (scalar >> uint(i)) & 1
		cswap(bit, &r0, &r1)
		r0, r1 = pointAdd(r0, r1), pointDouble(r1)
		cswap(bit, &r0, &r1)
	}
	return r0
}
