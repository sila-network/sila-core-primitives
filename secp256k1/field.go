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

func (z *fieldElement) add(x, y *fieldElement) *fieldElement { fieldP.add(&z.v, &x.v, &y.v); return z }
func (z *fieldElement) sub(x, y *fieldElement) *fieldElement { fieldP.sub(&z.v, &x.v, &y.v); return z }
func (z *fieldElement) neg(x *fieldElement) *fieldElement    { fieldP.neg(&z.v, &x.v); return z }

// mul sets z = x·y mod p.
func (z *fieldElement) mul(x, y *fieldElement) *fieldElement {
	var t [8]uint64
	mul256(&t, &x.v, &y.v)
	reduce512(&z.v, &t)
	return z
}

// square sets z = x^2 mod p.
func (z *fieldElement) square(x *fieldElement) *fieldElement {
	var t [8]uint64
	sqr256(&t, &x.v)
	reduce512(&z.v, &t)
	return z
}

// reduce512 sets z = t mod p for a 512-bit t, in constant time.
func reduce512(z *limbs, t *[8]uint64) {
	// First fold: r = t[0..3] + t[4..7]·c, a value below 2^256·(c+1).
	var r0, r1, r2, r3, r4, cc uint64
	hi, lo := bits.Mul64(t[4], fieldC)
	r0, cc = bits.Add64(t[0], lo, 0)
	carry := hi + cc
	hi, lo = bits.Mul64(t[5], fieldC)
	lo, cc = bits.Add64(lo, carry, 0)
	hi += cc
	r1, cc = bits.Add64(t[1], lo, 0)
	carry = hi + cc
	hi, lo = bits.Mul64(t[6], fieldC)
	lo, cc = bits.Add64(lo, carry, 0)
	hi += cc
	r2, cc = bits.Add64(t[2], lo, 0)
	carry = hi + cc
	hi, lo = bits.Mul64(t[7], fieldC)
	lo, cc = bits.Add64(lo, carry, 0)
	hi += cc
	r3, cc = bits.Add64(t[3], lo, 0)
	r4 = hi + cc // < 2^34

	// Second fold: r[0..3] + r4·c; r4·c < 2^68.
	hi, lo = bits.Mul64(r4, fieldC)
	r0, cc = bits.Add64(r0, lo, 0)
	r1, cc = bits.Add64(r1, hi, cc)
	r2, cc = bits.Add64(r2, 0, cc)
	r3, cc = bits.Add64(r3, 0, cc)

	// Third fold: a carry out (cc ∈ {0,1}) is worth c; the sum is then
	// small enough that it cannot carry again.
	r0, cc = bits.Add64(r0, fieldC&-cc, 0)
	r1, cc = bits.Add64(r1, 0, cc)
	r2, cc = bits.Add64(r2, 0, cc)
	r3, _ = bits.Add64(r3, 0, cc)

	// Final correction into [0, p).
	s := limbs{r0, r1, r2, r3}
	fieldP.reduceOnce(z, &s, 0)
}

// inv sets z = x^-1 (x^(p-2)); the inverse of 0 is 0.
func (z *fieldElement) inv(x *fieldElement) *fieldElement {
	fieldExp(z, x, &fieldInvExp)
	return z
}

// sqrt sets z to a square root of x and returns 1 if x is a quadratic
// residue (or zero), else returns 0 (z is then unspecified).
func (z *fieldElement) sqrt(x *fieldElement) uint64 {
	var r, check fieldElement
	fieldExp(&r, x, &fieldSqrtExp)
	check.square(&r)
	*z = r
	return check.equal(x)
}

// fieldExp sets z = x^e for a PUBLIC exponent e (big-endian), using fixed
// 4-bit windows: 15 multiplications for the table, then 4 squarings per
// window and one multiplication per non-zero window. The table index is
// the public exponent nibble, so plain indexing is safe.
func fieldExp(z, x *fieldElement, e *[32]byte) {
	var table [16]fieldElement
	table[0].setOne()
	table[1] = *x
	for i := 2; i < 16; i++ {
		table[i].mul(&table[i-1], x)
	}
	var acc fieldElement
	acc.setOne()
	for _, b := range e {
		for _, nib := range [2]byte{b >> 4, b & 0xF} {
			acc.square(&acc)
			acc.square(&acc)
			acc.square(&acc)
			acc.square(&acc)
			if nib != 0 {
				acc.mul(&acc, &table[nib])
			}
		}
	}
	*z = acc
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
