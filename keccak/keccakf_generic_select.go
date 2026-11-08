// SPDX-License-Identifier: Apache-2.0

package keccak

// permuteGeneric is the portable kernel used when no assembly kernel
// applies. Two generated shapes exist (see internal/gen): "mem" addresses
// lanes in place, "locals" holds them in local variables.
// BenchmarkPermuteVariant measures both on a given CPU.
func permuteGeneric(a *[25]uint64) { permuteGenericMem(a) }
