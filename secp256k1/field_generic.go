// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

//go:build !amd64 || purego

package secp256k1

// fieldMul sets z = x·y mod p (portable constant-time Go; the amd64 build
// uses field_amd64.s).
func fieldMul(z, x, y *limbs) {
	t0, t1, t2, t3, t4, t5, t6, t7 := mulWords(x, y)
	reduceWords(z, t0, t1, t2, t3, t4, t5, t6, t7)
}

// fieldSqr sets z = x^2 mod p.
func fieldSqr(z, x *limbs) {
	t0, t1, t2, t3, t4, t5, t6, t7 := sqrWords(x)
	reduceWords(z, t0, t1, t2, t3, t4, t5, t6, t7)
}

// scalarMul sets z = x·y·2^-256 mod n (Montgomery product; portable Go).
// n is the group order (the parameter mirrors the amd64 assembly).
func scalarMul(z, x, y, _ *limbs) {
	t0, t1, t2, t3, t4, t5, t6, t7 := mulWords(x, y)
	montReduceN(z, t0, t1, t2, t3, t4, t5, t6, t7)
}

// scalarSqr sets z = x^2·2^-256 mod n.
func scalarSqr(z, x, _ *limbs) {
	t0, t1, t2, t3, t4, t5, t6, t7 := sqrWords(x)
	montReduceN(z, t0, t1, t2, t3, t4, t5, t6, t7)
}

// lookupAffine sets r = table[mag-1] by scanning every entry (constant
// time); for mag == 0 it is left at an arbitrary table entry, and the
// caller discards the result of the addition.
func (r *affinePoint) lookupAffine(table *[baseEntries]affinePoint, mag uint64) {
	*r = table[0]
	for i := 1; i < baseEntries; i++ {
		d := uint64(i+1) ^ mag
		eq := 1 ^ ((d | -d) >> 63)
		r.x.selectFrom(&table[i].x, &r.x, eq)
		r.y.selectFrom(&table[i].y, &r.y, eq)
	}
}
