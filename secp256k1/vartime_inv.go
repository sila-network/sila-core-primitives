// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

// Variable-time modular inversion for PUBLIC inputs only (signature
// components, recovered points, public-key tables). Like everything in the
// vartime*.go files, it branches on its input; the static test
// TestVariableTimeHelpersOnlyOnPublicPaths keeps it off the secret paths,
// which use the constant-time Fermat inversions in field.go and scalar.go.
//
// Algorithm: the "divstep" GCD of Bernstein and Yang ("Fast constant-time
// gcd computation and modular inversion", 2019), run in variable time:
// batches of 62 divsteps are computed on the low 64 bits of (f, g) only,
// yielding a 2x2 integer transition matrix T with row sums of absolute
// values at most 2^62 such that
//
//	(f', g') = T·(f, g) / 2^62.
//
// The same matrix is applied to (d, e), which track f ≡ d·x and g ≡ e·x
// (mod m); the division by 2^62 is made exact modulo m by adding a
// multiple of m. When g reaches 0, f = ±gcd(x, m) = ±1 and x^-1 = ±d.
//
// Big values are 320-bit two's-complement integers (wide). Every
// intermediate stays below 2^319 in absolute value (bounds below), so the
// arithmetic modulo 2^320 is exact.

import "math/bits"

func wideIsNeg(a *wide) bool { return int64(a[4]) < 0 }

func wideIsZero(a *wide) bool { return a[0]|a[1]|a[2]|a[3]|a[4] == 0 }

// divsteps62Vartime runs 62 divsteps on the low words of (f, g), f odd,
// and returns the updated zeta and the transition matrix (u, v; q, r):
// 2^62·f' = u·f + v·g and 2^62·g' = q·f + r·g. It uses the "half-delta"
// divstep (delta starts at 1/2, which needs fewer steps on average and
// keeps the Bernstein–Yang termination bound); zeta = delta - 1/2:
//
//	zeta >= 0 and g odd: (-zeta,    g, (g - f)/2)
//	g odd:               (zeta + 1, f, (g + f)/2)
//	g even:              (zeta + 1, f, g/2)
//
// After j steps only the low 64 - j bits of the tracked words are exact,
// which covers every parity decision of the batch. Each divstep at most
// doubles the row sums |u| + |v| and |q| + |r|, so they stay <= 2^62.
func divsteps62Vartime(zeta int64, f, g uint64) (int64, int64, int64, int64, int64) {
	u, v, q, r := int64(1), int64(0), int64(0), int64(1)
	left := 62
	for {
		// Even steps in bulk: halve g, double the f row.
		zeros := min(bits.TrailingZeros64(g), left)
		g >>= uint(zeros)
		u <<= uint(zeros)
		v <<= uint(zeros)
		zeta += int64(zeros)
		left -= zeros
		if left == 0 {
			return zeta, u, v, q, r
		}
		// g is odd: one full divstep.
		if zeta >= 0 {
			zeta = -zeta
			f, g = g, (g-f)>>1
			u, v, q, r = q<<1, r<<1, q-u, r-v
		} else {
			zeta++
			g = (g + f) >> 1
			q, r = q+u, r+v
			u, v = u<<1, v<<1
		}
		left--
		if left == 0 {
			return zeta, u, v, q, r
		}
	}
}

// modInverseVartime returns x^-1 mod m for an odd prime m and 0 < x < m,
// and 0 for x = 0. mInv62 is m^-1 mod 2^62. Variable time: public inputs
// only.
func modInverseVartime(x, m *limbs, mInv62 uint64) limbs {
	if isZeroLimbs(x) == 1 {
		return limbs{}
	}
	M := wideFromLimbs(m)
	f, g := M, wideFromLimbs(x)
	var d, e wide // f ≡ d·x, g ≡ e·x (mod m); -m < d, e < m
	e[0] = 1
	zeta := int64(0) // delta = 1/2
	for !wideIsZero(&g) {
		var u, v, q, r int64
		zeta, u, v, q, r = divsteps62Vartime(zeta, f[0], g[0])
		// Same updates as the constant-time inversion (inv_ct.go):
		// (f, g) <- T·(f, g) / 2^62 and (d, e) <- T·(d, e) / 2^62 mod m,
		// kept in (-m, m).
		f, g = linShr62(&f, &g, u, v), linShr62(&f, &g, q, r)
		d, e = linShr62Mod(&d, &e, u, v, m, &M, mInv62), linShr62Mod(&d, &e, q, r, m, &M, mInv62)
	}
	// f = ±1 and f ≡ d·x, so x^-1 ≡ ±d.
	if wideIsNeg(&f) {
		var zero wide
		d = wideSub(&zero, &d)
	}
	if wideIsNeg(&d) {
		d = wideAdd(&d, &M)
	}
	return limbs{d[0], d[1], d[2], d[3]}
}

// invVartime sets z = x^-1 mod p (0 for x = 0). Public inputs only.
func (z *fieldElement) invVartime(x *fieldElement) *fieldElement {
	z.v = modInverseVartime(&x.v, &fieldP.m, fieldPInv62)
	return z
}

// invVartime sets z = x^-1 mod n (0 for x = 0). Public inputs only.
func (z *scalar) invVartime(x *scalar) *scalar {
	// x.v = a·R mod n; (aR)^-1 · R^3 / R = a^-1·R.
	y := modInverseVartime(&x.v, &scalarN.m, scalarNInv62)
	scalarN.mul(&z.v, &y, &scalarR3)
	return z
}
