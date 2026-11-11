// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

//go:build arm64 && !purego

package secp256k1

// Field and scalar arithmetic in field_arm64.s (constant time, no branch).
// fieldMul/fieldSqr: z = x·y (x^2) mod p for canonical inputs, canonical
// result. scalarMul/scalarSqr: z = x·y·2^-256 mod n for x, y < n (n points
// to the modulus limbs). z may alias x or y.

//go:noescape
func fieldMul(z, x, y *limbs)

//go:noescape
func fieldSqr(z, x *limbs)

//go:noescape
func scalarMul(z, x, y, n *limbs)

//go:noescape
func scalarSqr(z, x, n *limbs)

// lookupAffineNEON sets r = table[idx-1] for 1 <= idx <= 16, reading every
// entry (field_arm64.s).
//
//go:noescape
func lookupAffineNEON(r *affinePoint, table *[baseEntries]affinePoint, idx uint64)

// lookupAffine sets r = table[mag-1], or table[0] for mag = 0, reading
// every entry (constant time; mag <= 16).
func (r *affinePoint) lookupAffine(table *[baseEntries]affinePoint, mag uint64) {
	lookupAffineNEON(r, table, mag|((mag-1)>>63))
}
