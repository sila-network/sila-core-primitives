// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

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
func (z *scalar) mul(x, y *scalar) *scalar { scalarN.mul(&z.v, &x.v, &y.v); return z }

// inv sets z = x^-1 mod n (x^(n-2)); the inverse of 0 is 0.
func (z *scalar) inv(x *scalar) *scalar {
	scalarN.expPublic(&z.v, &x.v, &scalarInvExp)
	return z
}

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
