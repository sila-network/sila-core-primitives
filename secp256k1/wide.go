// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

// 320-bit two's-complement helpers for the divstep inversions
// (inv_ct.go, constant time; vartime_inv.go, public inputs only). Every
// function here is straight-line and branch-free.

import "math/bits"

// wide is a 320-bit two's-complement integer, little-endian words.
type wide [5]uint64

func wideFromLimbs(x *limbs) wide { return wide{x[0], x[1], x[2], x[3], 0} }

func wideAdd(a, b *wide) wide {
	var r wide
	var c uint64
	r[0], c = bits.Add64(a[0], b[0], 0)
	r[1], c = bits.Add64(a[1], b[1], c)
	r[2], c = bits.Add64(a[2], b[2], c)
	r[3], c = bits.Add64(a[3], b[3], c)
	r[4], _ = bits.Add64(a[4], b[4], c)
	return r
}

func wideSub(a, b *wide) wide {
	var r wide
	var c uint64
	r[0], c = bits.Sub64(a[0], b[0], 0)
	r[1], c = bits.Sub64(a[1], b[1], c)
	r[2], c = bits.Sub64(a[2], b[2], c)
	r[3], c = bits.Sub64(a[3], b[3], c)
	r[4], _ = bits.Sub64(a[4], b[4], c)
	return r
}

// wideMulWord returns a·k mod 2^320 for an unsigned word k.
func wideMulWord(a *wide, k uint64) wide {
	h0, l0 := bits.Mul64(a[0], k)
	h1, l1 := bits.Mul64(a[1], k)
	h2, l2 := bits.Mul64(a[2], k)
	h3, l3 := bits.Mul64(a[3], k)
	var r wide
	var c uint64
	r[0] = l0
	r[1], c = bits.Add64(l1, h0, 0)
	r[2], c = bits.Add64(l2, h1, c)
	r[3], c = bits.Add64(l3, h2, c)
	r[4] = a[4]*k + h3 + c
	return r
}

// wideMulAdd returns a + k·m mod 2^320 for m < 2^256 and an unsigned k.
func wideMulAdd(a *wide, m *limbs, k uint64) wide {
	h0, l0 := bits.Mul64(m[0], k)
	h1, l1 := bits.Mul64(m[1], k)
	h2, l2 := bits.Mul64(m[2], k)
	h3, l3 := bits.Mul64(m[3], k)
	var r wide
	var c uint64
	r[0], c = bits.Add64(a[0], l0, 0)
	r[1], c = bits.Add64(a[1], l1, c)
	r[2], c = bits.Add64(a[2], l2, c)
	r[3], c = bits.Add64(a[3], l3, c)
	r[4] = a[4] + h3 + c
	r[1], c = bits.Add64(r[1], h0, 0)
	r[2], c = bits.Add64(r[2], h1, c)
	r[3], c = bits.Add64(r[3], h2, c)
	r[4] += c
	return r
}

// wideShr62 returns a / 2^62 (arithmetic shift; exact when the low 62 bits
// are zero).
func wideShr62(a *wide) wide {
	return wide{
		a[0]>>62 | a[1]<<2,
		a[1]>>62 | a[2]<<2,
		a[2]>>62 | a[3]<<2,
		a[3]>>62 | a[4]<<2,
		uint64(int64(a[4]) >> 62),
	}
}

// inv62 returns m^-1 mod 2^62 for odd m (Newton iteration).
func inv62(m0 uint64) uint64 {
	inv := uint64(1)
	for i := 0; i < 6; i++ {
		inv *= 2 - m0*inv
	}
	return inv & (1<<62 - 1)
}

var (
	fieldPInv62  = inv62(fieldP.m[0])
	scalarNInv62 = inv62(scalarN.m[0])
	// scalarR3 is R^3 mod n (R = 2^256): Montgomery-multiplying the plain
	// inverse of a Montgomery value aR by R^3 gives a^-1·R.
	scalarR3 = func() limbs {
		var r3 limbs
		scalarN.mul(&r3, &scalarN.r2, &scalarN.r2) // R^4/R = R^3
		return r3
	}()
)
