// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

import "math/bits"

// Scalar arithmetic modulo the group order
// n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
// (SEC 2 v2.0, §2.4.1). scalar values are always fully reduced and held in
// Montgomery form. All operations are constant time with respect to the
// scalar values, so they are safe for private keys and nonces.

type scalar struct{ v limbs }

var scalarN = newModulus(limbs{
	0xBFD25E8CD0364141, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF,
})

var (
	scalarInvExp = exponentBytes(scalarN.m, -2, 0) // n-2 (Fermat inversion)
	// halfN is (n-1)/2 in canonical (non-Montgomery) form: s is "low" iff s <= halfN.
	halfN = func() limbs {
		h := limbsFromBytes(ptr(exponentBytes(scalarN.m, -1, 1)))
		return h
	}()
)

func ptr(b [32]byte) *[32]byte { return &b }

// setBytesCanonical sets z from 32 big-endian bytes. It returns 1 if the
// value is < n, else 0 (z is then zero). Use it where non-canonical input
// must be rejected (private keys, signature components).
func (z *scalar) setBytesCanonical(b *[32]byte) uint64 {
	x := limbsFromBytes(b)
	ok := lessThan(&x, &scalarN.m)
	var zero limbs
	selectLimbs(&x, &x, &zero, ok)
	scalarN.toMont(&z.v, &x)
	return ok
}

// setBytesReduced sets z = int(b) mod n. Any 256-bit value is < 2n, so a
// single conditional subtraction reduces it. Used for message digests.
func (z *scalar) setBytesReduced(b *[32]byte) {
	x := limbsFromBytes(b)
	scalarN.reduceOnce(&x, &x, 0)
	scalarN.toMont(&z.v, &x)
}

// bytes returns the canonical 32-byte big-endian encoding.
func (z *scalar) bytes() [32]byte {
	var x limbs
	scalarN.fromMont(&x, &z.v)
	var out [32]byte
	limbsToBytes(&out, &x)
	return out
}

// canonical returns the value as plain (non-Montgomery) limbs.
func (z *scalar) canonical() limbs {
	var x limbs
	scalarN.fromMont(&x, &z.v)
	return x
}

func (z *scalar) isZero() uint64         { return isZeroLimbs(&z.v) }
func (z *scalar) equal(x *scalar) uint64 { return equalLimbs(&z.v, &x.v) }

// isHigh returns 1 if z > (n-1)/2, else 0, in constant time.
func (z *scalar) isHigh() uint64 {
	x := z.canonical()
	return lessThan(&halfN, &x)
}

func (z *scalar) add(x, y *scalar) *scalar { scalarN.add(&z.v, &x.v, &y.v); return z }
func (z *scalar) sub(x, y *scalar) *scalar { scalarN.sub(&z.v, &x.v, &y.v); return z }
func (z *scalar) neg(x *scalar) *scalar    { scalarN.neg(&z.v, &x.v); return z }

// mul sets z = x·y (Montgomery product mod n).
func (z *scalar) mul(x, y *scalar) *scalar {
	scalarMul(&z.v, &x.v, &y.v, &scalarN.m)
	return z
}

// square sets z = x^2 (Montgomery form).
func (z *scalar) square(x *scalar) *scalar {
	scalarSqr(&z.v, &x.v, &scalarN.m)
	return z
}

// Limbs of n and -n^-1 mod 2^64, as constants for the unrolled reduction.
const (
	scalarN0   = 0xBFD25E8CD0364141
	scalarN1   = 0xBAAEDCE6AF48A03B
	scalarN2   = 0xFFFFFFFFFFFFFFFE
	scalarN3   = 0xFFFFFFFFFFFFFFFF
	scalarNInv = 0x4B0DFF665588B13F
)

// montReduceN sets z = t·2^-256 mod n for t < n·2^256 (Montgomery
// reduction, one word per step, unrolled; constant time).
func montReduceN(z *limbs, t0, t1, t2, t3, t4, t5, t6, t7 uint64) {
	var c, c2, carry, h0, h1, h2, h3, l0, l1, l2, l3 uint64
	// Step i adds q·n·2^(64i) so that word i becomes zero; carry holds
	// the overflow beyond word i+4.
	q := t0 * scalarNInv
	h0, l0 = bits.Mul64(q, scalarN0)
	h1, l1 = bits.Mul64(q, scalarN1)
	h2, l2 = bits.Mul64(q, scalarN2)
	h3, l3 = bits.Mul64(q, scalarN3)
	_, c = bits.Add64(t0, l0, 0)
	t1, c = bits.Add64(t1, l1, c)
	t2, c = bits.Add64(t2, l2, c)
	t3, c = bits.Add64(t3, l3, c)
	t4, c2 = bits.Add64(t4, 0, c)
	t1, c = bits.Add64(t1, h0, 0)
	t2, c = bits.Add64(t2, h1, c)
	t3, c = bits.Add64(t3, h2, c)
	t4, c = bits.Add64(t4, h3, c)
	carry = c + c2

	q = t1 * scalarNInv
	h0, l0 = bits.Mul64(q, scalarN0)
	h1, l1 = bits.Mul64(q, scalarN1)
	h2, l2 = bits.Mul64(q, scalarN2)
	h3, l3 = bits.Mul64(q, scalarN3)
	_, c = bits.Add64(t1, l0, 0)
	t2, c = bits.Add64(t2, l1, c)
	t3, c = bits.Add64(t3, l2, c)
	t4, c = bits.Add64(t4, l3, c)
	t5, c2 = bits.Add64(t5, carry, c)
	t2, c = bits.Add64(t2, h0, 0)
	t3, c = bits.Add64(t3, h1, c)
	t4, c = bits.Add64(t4, h2, c)
	t5, c = bits.Add64(t5, h3, c)
	carry = c + c2

	q = t2 * scalarNInv
	h0, l0 = bits.Mul64(q, scalarN0)
	h1, l1 = bits.Mul64(q, scalarN1)
	h2, l2 = bits.Mul64(q, scalarN2)
	h3, l3 = bits.Mul64(q, scalarN3)
	_, c = bits.Add64(t2, l0, 0)
	t3, c = bits.Add64(t3, l1, c)
	t4, c = bits.Add64(t4, l2, c)
	t5, c = bits.Add64(t5, l3, c)
	t6, c2 = bits.Add64(t6, carry, c)
	t3, c = bits.Add64(t3, h0, 0)
	t4, c = bits.Add64(t4, h1, c)
	t5, c = bits.Add64(t5, h2, c)
	t6, c = bits.Add64(t6, h3, c)
	carry = c + c2

	q = t3 * scalarNInv
	h0, l0 = bits.Mul64(q, scalarN0)
	h1, l1 = bits.Mul64(q, scalarN1)
	h2, l2 = bits.Mul64(q, scalarN2)
	h3, l3 = bits.Mul64(q, scalarN3)
	_, c = bits.Add64(t3, l0, 0)
	t4, c = bits.Add64(t4, l1, c)
	t5, c = bits.Add64(t5, l2, c)
	t6, c = bits.Add64(t6, l3, c)
	t7, c2 = bits.Add64(t7, carry, c)
	t4, c = bits.Add64(t4, h0, 0)
	t5, c = bits.Add64(t5, h1, c)
	t6, c = bits.Add64(t6, h2, c)
	t7, c = bits.Add64(t7, h3, c)
	carry = c + c2

	// The result carry·2^256 + t[4..7] is below 2n.
	r := limbs{t4, t5, t6, t7}
	scalarN.reduceOnce(z, &r, carry)
}

// inv sets z = x^-1 mod n; the inverse of 0 is 0. Constant time: the
// divstep inversion of inv_ct.go (fixed 620 divsteps) on the Montgomery
// value a·R gives (a·R)^-1, and a Montgomery product with R^3 turns it
// into a^-1·R.
func (z *scalar) inv(x *scalar) *scalar {
	y := modInverseCT(&x.v, &scalarN.m, scalarNInv62)
	scalarMul(&z.v, &y, &scalarR3, &scalarN.m)
	clear(y[:])
	return z
}

// invFermat sets z = x^-1 mod n as x^(n-2) (the inverse of 0 is 0). It is
// the reference the divstep inversion is tested against. The exponent
// n - 2 is public: its top 127 bits are all ones (an addition chain builds
// x^(2^127 - 1) with 126 squarings and 10 products), and the low 129 bits
// are processed with a width-5 sliding window over odd powers. All
// branches depend only on the bits of n - 2.
func (z *scalar) invFermat(x *scalar) *scalar {
	var x2, x3, x6, x7, x14, x28, x56, x112, x126, acc scalar
	x2.square(x).mul(&x2, x)
	x3.square(&x2).mul(&x3, x)
	x6.sqrN(&x3, 3).mul(&x6, &x3)
	x7.square(&x6).mul(&x7, x)
	x14.sqrN(&x7, 7).mul(&x14, &x7)
	x28.sqrN(&x14, 14).mul(&x28, &x14)
	x56.sqrN(&x28, 28).mul(&x56, &x28)
	x112.sqrN(&x56, 56).mul(&x112, &x56)
	x126.sqrN(&x112, 14).mul(&x126, &x14)
	acc.square(&x126).mul(&acc, x) // x^(2^127 - 1)

	// odd[i] = x^(2i+1).
	var odd [16]scalar
	var xsq scalar
	odd[0] = *x
	xsq.square(x)
	for i := 1; i < 16; i++ {
		odd[i].mul(&odd[i-1], &xsq)
	}
	for _, step := range scalarInvTail {
		acc.sqrN(&acc, int(step.shift))
		if step.digit != 0 {
			acc.mul(&acc, &odd[step.digit>>1])
		}
	}
	*z = acc
	return z
}

// sqrN sets z = x^(2^k) for k >= 1.
func (z *scalar) sqrN(x *scalar, k int) *scalar {
	z.square(x)
	for i := 1; i < k; i++ {
		z.square(z)
	}
	return z
}

// scalarInvTail is the sliding-window schedule for the low 129 bits of
// n - 2: shift the accumulator left by shift bits, then multiply by
// x^digit (digit odd, < 32) when digit != 0. Derived from the public
// constant n at start-up.
var scalarInvTail = func() []struct{ shift, digit uint8 } {
	e := limbsFromBytes(&scalarInvExp)
	bit := func(i int) uint8 { return uint8(e[i/64]>>(uint(i)%64)) & 1 }
	for i := 255; i >= 129; i-- {
		if bit(i) != 1 {
			panic("sila/secp256k1: unexpected order constant")
		}
	}
	var steps []struct{ shift, digit uint8 }
	i := 128
	for i >= 0 {
		if bit(i) == 0 {
			steps = append(steps, struct{ shift, digit uint8 }{1, 0})
			i--
			continue
		}
		// Window of up to 5 bits ending in a one.
		j := i - 4
		if j < 0 {
			j = 0
		}
		for bit(j) == 0 {
			j++
		}
		var d uint8
		for k := i; k >= j; k-- {
			d = d<<1 | bit(k)
		}
		steps = append(steps, struct{ shift, digit uint8 }{uint8(i - j + 1), d})
		i = j - 1
	}
	return steps
}()

// selectFrom sets z = a if cond == 1, else b.
func (z *scalar) selectFrom(a, b *scalar, cond uint64) *scalar {
	selectLimbs(&z.v, &a.v, &b.v, cond)
	return z
}

// zero overwrites the scalar.
func (z *scalar) zero() { z.v = limbs{} }

// window returns the 4-bit window i (0 = least significant) of the
// canonical value x. The caller passes canonical limbs; the window index
// is public, the returned value is secret and must be used only with
// constant-time table lookups.
func window4(x *limbs, i int) uint64 {
	return (x[i/16] >> (uint(i%16) * 4)) & 0xF
}
