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

// wideLin returns u·a + v·b mod 2^320 for signed u, v. The words are
// multiplied by the unsigned images of u and v; a negative u is worth
// u + 2^64 as an unsigned word, which is corrected by subtracting a·2^64
// (and likewise for v).
func wideLin(a *wide, u int64, b *wide, v int64) wide {
	pa := wideMulWord(a, uint64(u))
	pb := wideMulWord(b, uint64(v))
	r := wideAdd(&pa, &pb)
	var c uint64
	if u < 0 {
		r[1], c = bits.Sub64(r[1], a[0], 0)
		r[2], c = bits.Sub64(r[2], a[1], c)
		r[3], c = bits.Sub64(r[3], a[2], c)
		r[4], _ = bits.Sub64(r[4], a[3], c)
	}
	if v < 0 {
		r[1], c = bits.Sub64(r[1], b[0], 0)
		r[2], c = bits.Sub64(r[2], b[1], c)
		r[3], c = bits.Sub64(r[3], b[2], c)
		r[4], _ = bits.Sub64(r[4], b[3], c)
	}
	return r
}

// wideLess reports a < b for non-negative a, b.
func wideLess(a, b *wide) bool {
	for i := 4; i >= 0; i-- {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// wideNormalize maps a value in (-m, 2m) into [0, m).
func wideNormalize(a, M *wide) wide {
	r := *a
	if wideIsNeg(&r) {
		r = wideAdd(&r, M)
	} else if !wideLess(&r, M) {
		r = wideSub(&r, M)
	}
	return r
}

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
	const mask62 = 1<<62 - 1
	M := wideFromLimbs(m)
	f, g := M, wideFromLimbs(x)
	var d, e wide // d = 0, e = 1: f ≡ d·x, g ≡ e·x (mod m)
	e[0] = 1
	zeta := int64(0) // delta = 1/2
	for !wideIsZero(&g) {
		var u, v, q, r int64
		zeta, u, v, q, r = divsteps62Vartime(zeta, f[0], g[0])

		// (f, g) <- T·(f, g) / 2^62. |f|, |g| <= m < 2^256, so the
		// combinations stay below 2^62·2^256 in absolute value.
		nf, ng := wideLin(&f, u, &g, v), wideLin(&f, q, &g, r)
		f, g = wideShr62(&nf), wideShr62(&ng)

		// (d, e) <- T·(d, e) / 2^62 mod m, with 0 <= d, e < m on entry.
		// The numerator lies in (-2^62·m, 2^62·m); adding md·m with
		// 0 <= md < 2^62 makes it divisible by 2^62 and keeps it in
		// (-2^62·m, 2^63·m) (below 2^319), so the result lies in
		// (-m, 2m) and one correction brings it back to [0, m).
		nd, ne := wideLin(&d, u, &e, v), wideLin(&d, q, &e, r)
		nd = wideMulAdd(&nd, m, (-nd[0]*mInv62)&mask62)
		ne = wideMulAdd(&ne, m, (-ne[0]*mInv62)&mask62)
		d, e = wideShr62(&nd), wideShr62(&ne)
		d = wideNormalize(&d, &M)
		e = wideNormalize(&e, &M)
	}
	// f = ±1 and f ≡ d·x, so x^-1 ≡ ±d.
	if wideIsNeg(&f) && !wideIsZero(&d) {
		d = wideSub(&M, &d)
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
