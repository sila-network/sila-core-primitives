// SPDX-License-Identifier: Apache-2.0

package keccak

// The permutation kernels are generated from the Keccak specification.
//go:generate go run ../internal/gen -mode go -variant mem -func permuteGenericMem -out keccakf_generic.go
//go:generate go run ../internal/gen -mode go -variant locals -func permuteGenericLocals -rc=false -out keccakf_generic_locals.go
//go:generate go run ../internal/gen -mode asm -out keccakf_avx512_amd64.s
