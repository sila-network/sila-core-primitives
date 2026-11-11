// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

//go:build amd64 && !purego

package secp256k1

// The field multiplication and squaring are implemented in field_amd64.s
// (constant time). Each sets z = x·y (or x^2) mod p for canonical inputs
// (< p) and returns a canonical result; z may alias x or y.

//go:noescape
func fieldMul(z, x, y *limbs)

//go:noescape
func fieldSqr(z, x *limbs)

//go:noescape
func fieldMulADX(z, x, y *limbs)

//go:noescape
func fieldSqrADX(z, x *limbs)

//go:noescape
func fieldMulMULQ(z, x, y *limbs)

//go:noescape
func fieldSqrMULQ(z, x *limbs)

// useADX selects the MULX/ADCX/ADOX code. It is set once, before any other
// package-level initialisation can use the field arithmetic, from CPUID:
// BMI2 (MULX) and ADX (ADCX/ADOX), leaf 7 subleaf 0, EBX bits 8 and 19.
// It depends only on the processor, never on data.
var useADX = func() bool {
	maxLeaf, _, _, _ := cpuid(0, 0)
	if maxLeaf < 7 {
		return false
	}
	_, ebx, _, _ := cpuid(7, 0)
	const bmi2, adx = 1 << 8, 1 << 19
	return ebx&bmi2 != 0 && ebx&adx != 0
}()

// cpuid is implemented in field_amd64.s.
func cpuid(leaf, subleaf uint32) (eax, ebx, ecx, edx uint32)

// Scalar Montgomery multiplication and squaring modulo n (field_amd64.s):
// z = x·y·2^-256 mod n for x, y < n; n points to the modulus limbs.

//go:noescape
func scalarMul(z, x, y, n *limbs)

//go:noescape
func scalarSqr(z, x, n *limbs)

//go:noescape
func scalarMulADX(z, x, y, n *limbs)

//go:noescape
func scalarSqrADX(z, x, n *limbs)

//go:noescape
func scalarMulMULQ(z, x, y, n *limbs)

//go:noescape
func scalarSqrMULQ(z, x, n *limbs)
