// SPDX-License-Identifier: Apache-2.0

//go:build !arm64

package keccak

// permuteGeneric is the portable kernel. Outside arm64 the "mem" shape
// (lanes addressed in place) is used: on amd64 it measured ~247 ns per
// permutation against ~315 ns for "locals" (Intel Xeon, 2026-11-08).
// Other architectures have not been measured; see BenchmarkPermuteVariant.
func permuteGeneric(a *[25]uint64) { permuteGenericMem(a) }
