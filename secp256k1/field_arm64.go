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
