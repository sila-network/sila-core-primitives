// SPDX-License-Identifier: Apache-2.0

//go:build !amd64 || purego

package keccak

func permute(a *[25]uint64) { permuteGeneric(a) }

// absorb XORs len(data)/Rate full blocks into a, permuting after each.
func absorb(a *[25]uint64, data []byte) { absorbGeneric(a, data) }
