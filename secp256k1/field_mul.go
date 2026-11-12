// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

// 256x256-bit multiplication and squaring, row by row: each row computes
// four independent 64x64-bit products and adds their low and high halves
// in two carry chains. The field versions keep the 512-bit product in
// registers and reduce it immediately (reduceWords). Straight-line code
// with no data-dependent branches or indices. Checked against math/big in
// arith_test.go (TestWideProductsAgainstBig and the field tests).

import "math/bits"

// mulWords returns the 512-bit product x·y as eight little-endian words.
func mulWords(x, y *limbs) (t0, t1, t2, t3, t4, t5, t6, t7 uint64) {
	x0, x1, x2, x3 := x[0], x[1], x[2], x[3]
	y0, y1, y2, y3 := y[0], y[1], y[2], y[3]
	var c, l0, l1, l2, l3, h0, h1, h2, h3 uint64

	h0, t0 = bits.Mul64(x0, y0)
	h1, l1 = bits.Mul64(x0, y1)
	h2, l2 = bits.Mul64(x0, y2)
	h3, l3 = bits.Mul64(x0, y3)
	t1, c = bits.Add64(l1, h0, 0)
	t2, c = bits.Add64(l2, h1, c)
	t3, c = bits.Add64(l3, h2, c)
	t4 = h3 + c

	h0, l0 = bits.Mul64(x1, y0)
	h1, l1 = bits.Mul64(x1, y1)
	h2, l2 = bits.Mul64(x1, y2)
	h3, l3 = bits.Mul64(x1, y3)
	t1, c = bits.Add64(t1, l0, 0)
	t2, c = bits.Add64(t2, l1, c)
	t3, c = bits.Add64(t3, l2, c)
	t4, c = bits.Add64(t4, l3, c)
	t5 = c
	t2, c = bits.Add64(t2, h0, 0)
	t3, c = bits.Add64(t3, h1, c)
	t4, c = bits.Add64(t4, h2, c)
	t5 += h3 + c

	h0, l0 = bits.Mul64(x2, y0)
	h1, l1 = bits.Mul64(x2, y1)
	h2, l2 = bits.Mul64(x2, y2)
	h3, l3 = bits.Mul64(x2, y3)
	t2, c = bits.Add64(t2, l0, 0)
	t3, c = bits.Add64(t3, l1, c)
	t4, c = bits.Add64(t4, l2, c)
	t5, c = bits.Add64(t5, l3, c)
	t6 = c
	t3, c = bits.Add64(t3, h0, 0)
	t4, c = bits.Add64(t4, h1, c)
	t5, c = bits.Add64(t5, h2, c)
	t6 += h3 + c

	h0, l0 = bits.Mul64(x3, y0)
	h1, l1 = bits.Mul64(x3, y1)
	h2, l2 = bits.Mul64(x3, y2)
	h3, l3 = bits.Mul64(x3, y3)
	t3, c = bits.Add64(t3, l0, 0)
	t4, c = bits.Add64(t4, l1, c)
	t5, c = bits.Add64(t5, l2, c)
	t6, c = bits.Add64(t6, l3, c)
	t7 = c
	t4, c = bits.Add64(t4, h0, 0)
	t5, c = bits.Add64(t5, h1, c)
	t6, c = bits.Add64(t6, h2, c)
	t7 += h3 + c
	return
}

// sqrWords returns the 512-bit square x^2: the six cross products are
// computed once and doubled, then the four squares are added.
func sqrWords(x *limbs) (t0, t1, t2, t3, t4, t5, t6, t7 uint64) {
	x0, x1, x2, x3 := x[0], x[1], x[2], x[3]
	var c uint64

	// Cross products x_i·x_j (i < j) into words 1..6.
	h01, l01 := bits.Mul64(x0, x1)
	h02, l02 := bits.Mul64(x0, x2)
	h03, l03 := bits.Mul64(x0, x3)
	h12, l12 := bits.Mul64(x1, x2)
	h13, l13 := bits.Mul64(x1, x3)
	h23, l23 := bits.Mul64(x2, x3)

	// Row of x0: l01, l02+h01, l03+h02, h03.
	t1 = l01
	t2, c = bits.Add64(l02, h01, 0)
	t3, c = bits.Add64(l03, h02, c)
	t4 = h03 + c
	// Row of x1: l12 at word 3, l13 at word 4; highs at 4 and 5.
	t3, c = bits.Add64(t3, l12, 0)
	t4, c = bits.Add64(t4, l13, c)
	t5 = c
	t4, c = bits.Add64(t4, h12, 0)
	t5, c = bits.Add64(t5, h13, c)
	t6 = c
	// x2·x3 at word 5.
	t5, c = bits.Add64(t5, l23, 0)
	t6, c = bits.Add64(t6, h23, c)
	t7 = c

	// Double the cross products.
	t7 = t7<<1 | t6>>63
	t6 = t6<<1 | t5>>63
	t5 = t5<<1 | t4>>63
	t4 = t4<<1 | t3>>63
	t3 = t3<<1 | t2>>63
	t2 = t2<<1 | t1>>63
	t1 <<= 1

	// Add the squares x_i^2 at words 2i, 2i+1.
	h0, l0 := bits.Mul64(x0, x0)
	h1, l1 := bits.Mul64(x1, x1)
	h2, l2 := bits.Mul64(x2, x2)
	h3, l3 := bits.Mul64(x3, x3)
	t0 = l0
	t1, c = bits.Add64(t1, h0, 0)
	t2, c = bits.Add64(t2, l1, c)
	t3, c = bits.Add64(t3, h1, c)
	t4, c = bits.Add64(t4, l2, c)
	t5, c = bits.Add64(t5, h2, c)
	t6, c = bits.Add64(t6, l3, c)
	t7, _ = bits.Add64(t7, h3, c)
	return
}

// mul256 stores the 512-bit product x·y in t (used by the scalar code and
// by tests).
func mul256(t *[8]uint64, x, y *limbs) {
	t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7] = mulWords(x, y)
}

// sqr256 stores the 512-bit square x^2 in t.
func sqr256(t *[8]uint64, x *limbs) {
	t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7] = sqrWords(x)
}
