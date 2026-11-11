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
