// SPDX-License-Identifier: Apache-2.0

//go:build arm64

package keccak

// permuteGeneric is the portable kernel. On arm64 the "locals" shape (lanes
// in local variables) is used: with 31 general-purpose registers it measured
// ~4.8% faster than "mem" on Neoverse-N2 (267.8 vs 281.2 ns per permutation,
// GitHub ubuntu-24.04-arm, 2026-11-08) and was not slower on Apple M1.
// See BenchmarkPermuteVariant and docs/PERFORMANCE-2026-11-08.md.
func permuteGeneric(a *[25]uint64) { permuteGenericLocals(a) }
