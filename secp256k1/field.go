// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

// Field arithmetic modulo p = 2^256 - 2^32 - 977 (SEC 2 v2.0, §2.4.1).
// fieldElement values are always fully reduced and held in Montgomery form.
// All operations are constant time with respect to the element values.

type fieldElement struct{ v limbs }

var fieldP = newModulus(limbs{
	0xFFFFFFFEFFFFFC2F, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
})

// Public exponents (big-endian), derived from p at start-up: p-2 for
// inversion (Fermat) and (p+1)/4 for square roots (p ≡ 3 mod 4).
var (
	fieldInvExp  = exponentBytes(fieldP.m, -2, 0)
	fieldSqrtExp = exponentBytes(fieldP.m, 1, 2)
)

func (z *fieldElement) setZero() *fieldElement { z.v = limbs{}; return z }
func (z *fieldElement) setOne() *fieldElement  { z.v = fieldP.one; return z }

// setBytes sets z from 32 big-endian bytes and returns 1 if the value is a
// canonical field element (< p), else 0 (z is then set to zero).
func (z *fieldElement) setBytes(b *[32]byte) uint64 {
	x := limbsFromBytes(b)
	ok := lessThan(&x, &fieldP.m)
	var zero limbs
	selectLimbs(&x, &x, &zero, ok)
	fieldP.toMont(&z.v, &x)
	return ok
}

// bytes returns the canonical 32-byte big-endian encoding.
func (z *fieldElement) bytes() [32]byte {
	var x limbs
	fieldP.fromMont(&x, &z.v)
	var out [32]byte
	limbsToBytes(&out, &x)
	return out
}

// isOdd returns the parity (1 or 0) of the canonical value.
func (z *fieldElement) isOdd() uint64 {
	var x limbs
	fieldP.fromMont(&x, &z.v)
	return x[0] & 1
}

func (z *fieldElement) isZero() uint64               { return isZeroLimbs(&z.v) }
func (z *fieldElement) equal(x *fieldElement) uint64 { return equalLimbs(&z.v, &x.v) }

func (z *fieldElement) add(x, y *fieldElement) *fieldElement { fieldP.add(&z.v, &x.v, &y.v); return z }
func (z *fieldElement) sub(x, y *fieldElement) *fieldElement { fieldP.sub(&z.v, &x.v, &y.v); return z }
func (z *fieldElement) neg(x *fieldElement) *fieldElement    { fieldP.neg(&z.v, &x.v); return z }
func (z *fieldElement) mul(x, y *fieldElement) *fieldElement { fieldP.mul(&z.v, &x.v, &y.v); return z }
func (z *fieldElement) square(x *fieldElement) *fieldElement { fieldP.mul(&z.v, &x.v, &x.v); return z }

// inv sets z = x^-1 (x^(p-2)); the inverse of 0 is 0.
func (z *fieldElement) inv(x *fieldElement) *fieldElement {
	fieldP.expPublic(&z.v, &x.v, &fieldInvExp)
	return z
}

// sqrt sets z to a square root of x and returns 1 if x is a quadratic
// residue (or zero), else returns 0 (z is then unspecified).
func (z *fieldElement) sqrt(x *fieldElement) uint64 {
	var r, check fieldElement
	fieldP.expPublic(&r.v, &x.v, &fieldSqrtExp)
	check.square(&r)
	*z = r
	return check.equal(x)
}

// selectFrom sets z = a if cond == 1, else b.
func (z *fieldElement) selectFrom(a, b *fieldElement, cond uint64) *fieldElement {
	selectLimbs(&z.v, &a.v, &b.v, cond)
	return z
}

// fieldFromUint returns the field element with small value v.
func fieldFromUint(v uint64) fieldElement {
	var z fieldElement
	x := limbs{v, 0, 0, 0}
	fieldP.toMont(&z.v, &x)
	return z
}
