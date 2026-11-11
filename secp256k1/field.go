// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

import "math/bits"

// Field arithmetic modulo p = 2^256 - 2^32 - 977 (SEC 2 v2.0, §2.4.1).
// fieldElement values are always fully reduced canonical integers (< p) in
// four little-endian 64-bit limbs. All operations are constant time with
// respect to the element values.
//
// Multiplication uses the special form of p: 2^256 ≡ c (mod p) with
// c = 2^32 + 977 = 0x1000003D1, so a 512-bit product hi·2^256 + lo is
// reduced as lo + hi·c, folded twice, then conditionally corrected.

type fieldElement struct{ v limbs }

// fieldP holds p for the generic add/sub/neg helpers (which do not depend
// on the representation) and for constant derivation.
var fieldP = newModulus(limbs{
	0xFFFFFFFEFFFFFC2F, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
})

// fieldC is 2^256 mod p.
const fieldC = 0x1000003D1

// Public exponents (big-endian), derived from p at start-up: p-2 for
// inversion (Fermat) and (p+1)/4 for square roots (p ≡ 3 mod 4).
var (
	fieldInvExp  = exponentBytes(fieldP.m, -2, 0)
	fieldSqrtExp = exponentBytes(fieldP.m, 1, 2)
)

func (z *fieldElement) setZero() *fieldElement { z.v = limbs{}; return z }
func (z *fieldElement) setOne() *fieldElement  { z.v = limbs{1, 0, 0, 0}; return z }

// setBytes sets z from 32 big-endian bytes and returns 1 if the value is a
// canonical field element (< p), else 0 (z is then set to zero).
func (z *fieldElement) setBytes(b *[32]byte) uint64 {
	x := limbsFromBytes(b)
	ok := lessThan(&x, &fieldP.m)
	var zero limbs
	selectLimbs(&z.v, &x, &zero, ok)
	return ok
}

// bytes returns the canonical 32-byte big-endian encoding.
func (z *fieldElement) bytes() [32]byte {
	var out [32]byte
	limbsToBytes(&out, &z.v)
	return out
}

// isOdd returns the parity (1 or 0) of the canonical value.
func (z *fieldElement) isOdd() uint64 { return z.v[0] & 1 }

func (z *fieldElement) isZero() uint64               { return isZeroLimbs(&z.v) }
func (z *fieldElement) equal(x *fieldElement) uint64 { return equalLimbs(&z.v, &x.v) }

// add sets z = x + y mod p (x, y < p).
func (z *fieldElement) add(x, y *fieldElement) *fieldElement {
	r0, c := bits.Add64(x.v[0], y.v[0], 0)
	r1, c := bits.Add64(x.v[1], y.v[1], c)
	r2, c := bits.Add64(x.v[2], y.v[2], c)
	r3, c := bits.Add64(x.v[3], y.v[3], c)
	// fieldCorrect, written out (it is too large for the inliner and add
	// is on every hot path): subtract p, i.e. add fieldC mod 2^256, when
	// the sum carried or r + fieldC carries.
	d0, cc := bits.Add64(r0, fieldC, 0)
	d1, cc := bits.Add64(r1, 0, cc)
	d2, cc := bits.Add64(r2, 0, cc)
	d3, cc := bits.Add64(r3, 0, cc)
	m := -(c | cc)
	z.v[0] = r0 ^ ((r0 ^ d0) & m)
	z.v[1] = r1 ^ ((r1 ^ d1) & m)
	z.v[2] = r2 ^ ((r2 ^ d2) & m)
	z.v[3] = r3 ^ ((r3 ^ d3) & m)
	return z
}

// sub sets z = x - y mod p (x, y < p). On a borrow the 256-bit difference
// is d + 2^256 too large, and adding p is subtracting fieldC.
func (z *fieldElement) sub(x, y *fieldElement) *fieldElement {
	d0, b := bits.Sub64(x.v[0], y.v[0], 0)
	d1, b := bits.Sub64(x.v[1], y.v[1], b)
	d2, b := bits.Sub64(x.v[2], y.v[2], b)
	d3, b := bits.Sub64(x.v[3], y.v[3], b)
	z.v[0], b = bits.Sub64(d0, fieldC&-b, 0)
	z.v[1], b = bits.Sub64(d1, 0, b)
	z.v[2], b = bits.Sub64(d2, 0, b)
	z.v[3], _ = bits.Sub64(d3, 0, b)
	return z
}

// neg sets z = -x mod p (0 stays 0).
func (z *fieldElement) neg(x *fieldElement) *fieldElement {
	var zero fieldElement
	return z.sub(&zero, x)
}

// mul sets z = x·y mod p.
func (z *fieldElement) mul(x, y *fieldElement) *fieldElement {
	fieldMul(&z.v, &x.v, &y.v)
	return z
}

// square sets z = x^2 mod p.
func (z *fieldElement) square(x *fieldElement) *fieldElement {
	fieldSqr(&z.v, &x.v)
	return z
}

// reduce512 sets z = t mod p for a 512-bit t, in constant time.
func reduce512(z *limbs, t *[8]uint64) {
	reduceWords(z, t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7])
}

// reduceWords sets z = t mod p for the 512-bit value t0..t7 (little-endian).
func reduceWords(z *limbs, t0, t1, t2, t3, t4, t5, t6, t7 uint64) {
	// First fold: r = t[0..3] + t[4..7]·c. The four products are
	// independent; their low and high halves are added in two carry chains.
	h4, l4 := bits.Mul64(t4, fieldC)
	h5, l5 := bits.Mul64(t5, fieldC)
	h6, l6 := bits.Mul64(t6, fieldC)
	h7, l7 := bits.Mul64(t7, fieldC)
	var c uint64
	r0, c := bits.Add64(t0, l4, 0)
	r1, c := bits.Add64(t1, l5, c)
	r2, c := bits.Add64(t2, l6, c)
	r3, c := bits.Add64(t3, l7, c)
	r4 := h7 + c
	r1, c = bits.Add64(r1, h4, 0)
	r2, c = bits.Add64(r2, h5, c)
	r3, c = bits.Add64(r3, h6, c)
	r4 += c // r4 < 2^34

	// Second fold: r[0..3] + r4·c, with r4·c < 2^68.
	hi, lo := bits.Mul64(r4, fieldC)
	r0, c = bits.Add64(r0, lo, 0)
	r1, c = bits.Add64(r1, hi, c)
	r2, c = bits.Add64(r2, 0, c)
	r3, c = bits.Add64(r3, 0, c)

	// A carry out (c in {0,1}) is worth c·2^256 ≡ c·fieldC; the sum is then
	// small and cannot carry again.
	r0, c = bits.Add64(r0, fieldC&-c, 0)
	r1, c = bits.Add64(r1, 0, c)
	r2, c = bits.Add64(r2, 0, c)
	r3 += c

	fieldCorrect(z, r0, r1, r2, r3, 0)
}

// fieldCorrect sets z = (carry·2^256 + r) mod p for a value below 2p.
// Subtracting p is adding fieldC modulo 2^256: the subtraction applies
// exactly when the input carried or when r + fieldC carries.
func fieldCorrect(z *limbs, r0, r1, r2, r3, carry uint64) {
	d0, c := bits.Add64(r0, fieldC, 0)
	d1, c := bits.Add64(r1, 0, c)
	d2, c := bits.Add64(r2, 0, c)
	d3, c := bits.Add64(r3, 0, c)
	m := -(c | carry)
	z[0] = r0 ^ ((r0 ^ d0) & m)
	z[1] = r1 ^ ((r1 ^ d1) & m)
	z[2] = r2 ^ ((r2 ^ d2) & m)
	z[3] = r3 ^ ((r3 ^ d3) & m)
}

// mulSmall sets z = x·k mod p for a small constant k < 2^32.
func (z *fieldElement) mulSmall(x *fieldElement, k uint64) *fieldElement {
	h0, l0 := bits.Mul64(x.v[0], k)
	h1, l1 := bits.Mul64(x.v[1], k)
	h2, l2 := bits.Mul64(x.v[2], k)
	h3, l3 := bits.Mul64(x.v[3], k)
	var c uint64
	r1, c := bits.Add64(l1, h0, 0)
	r2, c := bits.Add64(l2, h1, c)
	r3, c := bits.Add64(l3, h2, c)
	r4 := h3 + c // < 2^32
	hi, lo := bits.Mul64(r4, fieldC)
	r0, c := bits.Add64(l0, lo, 0)
	r1, c = bits.Add64(r1, hi, c)
	r2, c = bits.Add64(r2, 0, c)
	r3, c = bits.Add64(r3, 0, c)
	r0, c = bits.Add64(r0, fieldC&-c, 0)
	r1, c = bits.Add64(r1, 0, c)
	r2, c = bits.Add64(r2, 0, c)
	r3 += c
	// fieldCorrect written out, as in add.
	d0, cc := bits.Add64(r0, fieldC, 0)
	d1, cc := bits.Add64(r1, 0, cc)
	d2, cc := bits.Add64(r2, 0, cc)
	d3, cc := bits.Add64(r3, 0, cc)
	m := -cc
	z.v[0] = r0 ^ ((r0 ^ d0) & m)
	z.v[1] = r1 ^ ((r1 ^ d1) & m)
	z.v[2] = r2 ^ ((r2 ^ d2) & m)
	z.v[3] = r3 ^ ((r3 ^ d3) & m)
	return z
}

// inv sets z = x^-1 = x^(p-2); the inverse of 0 is 0. Fixed addition
// chain (public structure; constant time): 255 squarings, 15 products.
func (z *fieldElement) inv(x *fieldElement) *fieldElement {
	// p - 2 in binary, from the top: 223 ones, 0, 22 ones, 0000, 1, 0,
	// 11, 0, 1.
	var x2, x22, x223, t fieldElement
	fieldPow2k1(&x2, &x22, &x223, x)
	t.sqrN(&x223, 23).mul(&t, &x22)
	t.sqrN(&t, 5).mul(&t, x)
	t.sqrN(&t, 3).mul(&t, &x2)
	t.sqrN(&t, 2).mul(&t, x)
	*z = t
	return z
}

// sqrt sets z to a square root of x and returns 1 if x is a quadratic
// residue (or zero), else returns 0 (z is then unspecified).
// p ≡ 3 (mod 4), so the candidate is x^((p+1)/4): 253 squarings, 13
// products.
func (z *fieldElement) sqrt(x *fieldElement) uint64 {
	// (p + 1)/4 in binary: 223 ones, 0, 22 ones, 0000, 11, 00.
	var x2, x22, x223, r, check fieldElement
	fieldPow2k1(&x2, &x22, &x223, x)
	r.sqrN(&x223, 23).mul(&r, &x22)
	r.sqrN(&r, 6).mul(&r, &x2)
	r.sqrN(&r, 2)
	check.square(&r)
	*z = r
	return check.equal(x)
}

// fieldPow2k1 sets x2 = x^(2^2-1), x22 = x^(2^22-1), x223 = x^(2^223-1)
// (222 squarings, 11 products).
func fieldPow2k1(x2, x22, x223, x *fieldElement) {
	var x3, x6, x9, x11, x44, x88, x176, x220 fieldElement
	x2.square(x).mul(x2, x)
	x3.square(x2).mul(&x3, x)
	x6.sqrN(&x3, 3).mul(&x6, &x3)
	x9.sqrN(&x6, 3).mul(&x9, &x3)
	x11.sqrN(&x9, 2).mul(&x11, x2)
	x22.sqrN(&x11, 11).mul(x22, &x11)
	x44.sqrN(x22, 22).mul(&x44, x22)
	x88.sqrN(&x44, 44).mul(&x88, &x44)
	x176.sqrN(&x88, 88).mul(&x176, &x88)
	x220.sqrN(&x176, 44).mul(&x220, &x44)
	x223.sqrN(&x220, 3).mul(x223, &x3)
}

// sqrN sets z = x^(2^n) for n >= 1.
func (z *fieldElement) sqrN(x *fieldElement, n int) *fieldElement {
	z.square(x)
	for i := 1; i < n; i++ {
		z.square(z)
	}
	return z
}

// selectFrom sets z = a if cond == 1, else b.
func (z *fieldElement) selectFrom(a, b *fieldElement, cond uint64) *fieldElement {
	selectLimbs(&z.v, &a.v, &b.v, cond)
	return z
}

// fieldFromUint returns the field element with small value v (< p).
func fieldFromUint(v uint64) fieldElement {
	return fieldElement{v: limbs{v, 0, 0, 0}}
}
