// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

// Fully unrolled 256x256-bit multiplication and squaring (Comba schedule:
// one column of partial products at a time, three-word accumulator).
// Straight-line code with no data-dependent branches or indices. Checked
// against math/big in arith_test.go (TestWideProductsAgainstBig).

import "math/bits"

// mul256 computes the full 512-bit product t = x·y, unrolled
// column-wise (Comba) with a three-word accumulator (c0, c1, c2).
func mul256(t *[8]uint64, x, y *limbs) {
	var c0, c1, c2, hi, lo, cc uint64
	hi, lo = bits.Mul64(x[0], y[0])
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	t[0] = c0
	c0, c1, c2 = c1, c2, 0
	hi, lo = bits.Mul64(x[0], y[1])
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	hi, lo = bits.Mul64(x[1], y[0])
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	t[1] = c0
	c0, c1, c2 = c1, c2, 0
	hi, lo = bits.Mul64(x[0], y[2])
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	hi, lo = bits.Mul64(x[1], y[1])
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	hi, lo = bits.Mul64(x[2], y[0])
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	t[2] = c0
	c0, c1, c2 = c1, c2, 0
	hi, lo = bits.Mul64(x[0], y[3])
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	hi, lo = bits.Mul64(x[1], y[2])
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	hi, lo = bits.Mul64(x[2], y[1])
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	hi, lo = bits.Mul64(x[3], y[0])
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	t[3] = c0
	c0, c1, c2 = c1, c2, 0
	hi, lo = bits.Mul64(x[1], y[3])
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	hi, lo = bits.Mul64(x[2], y[2])
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	hi, lo = bits.Mul64(x[3], y[1])
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	t[4] = c0
	c0, c1, c2 = c1, c2, 0
	hi, lo = bits.Mul64(x[2], y[3])
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	hi, lo = bits.Mul64(x[3], y[2])
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	t[5] = c0
	c0, c1, c2 = c1, c2, 0
	hi, lo = bits.Mul64(x[3], y[3])
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	t[6] = c0
	c0, c1, c2 = c1, c2, 0
	t[7] = c0
}

// sqr256 computes t = x^2 (512-bit), unrolled column-wise (Comba);
// cross products x[i]·x[j] (i<j) are computed once and doubled.
func sqr256(t *[8]uint64, x *limbs) {
	var c0, c1, c2, hi, lo, cc uint64
	hi, lo = bits.Mul64(x[0], x[0])
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	t[0] = c0
	c0, c1, c2 = c1, c2, 0
	hi, lo = bits.Mul64(x[0], x[1])
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	t[1] = c0
	c0, c1, c2 = c1, c2, 0
	hi, lo = bits.Mul64(x[0], x[2])
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	hi, lo = bits.Mul64(x[1], x[1])
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	t[2] = c0
	c0, c1, c2 = c1, c2, 0
	hi, lo = bits.Mul64(x[0], x[3])
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	hi, lo = bits.Mul64(x[1], x[2])
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	t[3] = c0
	c0, c1, c2 = c1, c2, 0
	hi, lo = bits.Mul64(x[1], x[3])
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	hi, lo = bits.Mul64(x[2], x[2])
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	t[4] = c0
	c0, c1, c2 = c1, c2, 0
	hi, lo = bits.Mul64(x[2], x[3])
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	t[5] = c0
	c0, c1, c2 = c1, c2, 0
	hi, lo = bits.Mul64(x[3], x[3])
	c0, cc = bits.Add64(c0, lo, 0)
	c1, cc = bits.Add64(c1, hi, cc)
	c2 += cc
	t[6] = c0
	c0, c1, c2 = c1, c2, 0
	t[7] = c0
}
