// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

//go:build !amd64 || purego

package secp256k1

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
