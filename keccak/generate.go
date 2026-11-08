// SPDX-License-Identifier: Apache-2.0

package keccak

// The permutation kernels are generated from the Keccak specification.
//go:generate go run ../internal/gen -mode go -out keccakf_generic.go
//go:generate go run ../internal/gen -mode asm -out keccakf_avx512_amd64.s
