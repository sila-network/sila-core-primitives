// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

// Constant-time modular inversion by divsteps (Bernstein and Yang, "Fast
// constant-time gcd computation and modular inversion", TCHES 2019), used
// for SECRET-dependent inputs: the Z coordinate of R = k·G in Sign, the
// blinded nonce product k·ρ (invMaskedShares) and the affine conversion
// of PublicKey.
//
// The divstep (original form, delta starting at 1) is
//
//	delta > 0 and g odd: (1 - delta, g, (g - f)/2)
//	g odd:               (1 + delta, f, (g + f)/2)
//	g even:              (1 + delta, f, g/2)
//
// For f odd and 0 <= g < f < 2^256, Theorem 11.2 of the paper bounds the
// number of divsteps after which g = 0 by floor((49·256 + 57)/17) = 741.
// The inversion always runs 12 batches of 62 divsteps (744 >= 741): the
// number of operations does not depend on the input, and once g = 0 the
// further divsteps leave f (= ±1) and d unchanged.
//
// Constant time: every divstep is computed with masks (no branch, no
// data-dependent index); the 320-bit updates (wide.go, linComb,
// linShr62, linShr62Mod) are straight-line; the only loops are the fixed batch
// and step counters (checked on the compiled code by ctasm_test.go).
// Correctness is tested against math/big and the Fermat inversions.

import "math/bits"

// divsteps62 runs 62 divsteps on the low words of (f, g), f odd, in
// constant time, and returns the new delta and the transition matrix
// (u, v; q, r) with 2^62·f' = u·f + v·g and 2^62·g' = q·f + r·g. With
// c1 = (delta > 0) and c2 = (g odd) as masks, one divstep is
//
//	g += (c1 ? -f : f) if c2;  (q, r) += (c1 ? -(u, v) : (u, v)) if c2
//	if c1 and c2 (swap): f += g (the new g is g - f, so f becomes the old
//	  g), (u, v) += (q, r) (likewise), delta = -delta
//	g /= 2, (u, v) *= 2, delta += 1
//
// which gives (1 - delta, g, (g - f)/2) when swapping, (1 + delta, f,
// (g + f)/2) for g odd otherwise and (1 + delta, f, g/2) for g even.
// Only the low 64 - j bits are exact after j steps, enough for every
// parity decision; the row sums |u| + |v| and |q| + |r| stay <= 2^62.
func divsteps62(delta int64, f, g uint64) (int64, int64, int64, int64, int64) {
	u, v, q, r := int64(1), int64(0), int64(0), int64(1)
	for i := 0; i < 62; i++ {
		c1 := (-delta) >> 63      // all ones iff delta > 0
		c2 := -int64(g & 1)       // all ones iff g is odd
		x := (int64(f) ^ c1) - c1 // ±f
		y := (u ^ c1) - c1
		z := (v ^ c1) - c1
		g += uint64(x & c2)
		q += y & c2
		r += z & c2
		c1 &= c2 // swap
		delta = (delta ^ c1) - c1 + 1
		f += g & uint64(c1)
		u += q & c1
		v += r & c1
		g >>= 1
		u <<= 1
		v <<= 1
	}
	return delta, u, v, q, r
}

// linShr62 returns (u·a + v·b) / 2^62 (arithmetic shift) for signed u, v
// and 320-bit two's-complement a, b, without branches: the words are
// multiplied by the unsigned images of u and v, and a·2^64 (b·2^64) is
// subtracted under the sign mask of u (v). The caller guarantees that the
// exact result lies below 2^319 in absolute value and that the low 62 bits
// of the combination are zero (or are to be discarded).
func linShr62(a, b *wide, u, v int64) wide {
	n := linComb(a, b, u, v)
	return wideShr62(&n)
}

// linComb returns u·a + v·b mod 2^320 (see linShr62).
func linComb(a, b *wide, u, v int64) wide {
	uu, vv := uint64(u), uint64(v)
	mu, mv := uint64(u>>63), uint64(v>>63)
	var n wide
	var c, c2 uint64
	h0, l0 := bits.Mul64(a[0], uu)
	h1, l1 := bits.Mul64(a[1], uu)
	h2, l2 := bits.Mul64(a[2], uu)
	h3, l3 := bits.Mul64(a[3], uu)
	k0, j0 := bits.Mul64(b[0], vv)
	k1, j1 := bits.Mul64(b[1], vv)
	k2, j2 := bits.Mul64(b[2], vv)
	k3, j3 := bits.Mul64(b[3], vv)
	// Low halves.
	n[0], c = bits.Add64(l0, j0, 0)
	n[1], c = bits.Add64(l1, j1, c)
	n[2], c = bits.Add64(l2, j2, c)
	n[3], c = bits.Add64(l3, j3, c)
	n[4] = a[4]*uu + b[4]*vv + h3 + k3 + c
	// High halves, one word up.
	n[1], c = bits.Add64(n[1], h0, 0)
	n[2], c = bits.Add64(n[2], h1, c)
	n[3], c = bits.Add64(n[3], h2, c)
	n[4] += c
	n[1], c2 = bits.Add64(n[1], k0, 0)
	n[2], c2 = bits.Add64(n[2], k1, c2)
	n[3], c2 = bits.Add64(n[3], k2, c2)
	n[4] += c2
	// Sign corrections.
	n[1], c = bits.Sub64(n[1], a[0]&mu, 0)
	n[2], c = bits.Sub64(n[2], a[1]&mu, c)
	n[3], c = bits.Sub64(n[3], a[2]&mu, c)
	n[4], _ = bits.Sub64(n[4], a[3]&mu, c)
	n[1], c = bits.Sub64(n[1], b[0]&mv, 0)
	n[2], c = bits.Sub64(n[2], b[1]&mv, c)
	n[3], c = bits.Sub64(n[3], b[2]&mv, c)
	n[4], _ = bits.Sub64(n[4], b[3]&mv, c)
	return n
}

// linShr62Mod returns (u·d + v·e + md·m) / 2^62 reduced into (-m, m),
// where md in [0, 2^62) makes the numerator divisible by 2^62 (mInv62 is
// m^-1 mod 2^62). For -m < d, e < m and |u| + |v| <= 2^62 the numerator
// lies in (-2^62·m, 2^63·m), so the quotient is in (-m, 2m) and one
// conditional subtraction of m brings it into (-m, m). Constant time.
func linShr62Mod(d, e *wide, u, v int64, m *limbs, M *wide, mInv62 uint64) wide {
	const mask62 = 1<<62 - 1
	n := linComb(d, e, u, v)
	n = wideMulAdd(&n, m, (-n[0]*mInv62)&mask62)
	r := wideShr62(&n)
	// Subtract m unless r - m is negative.
	var t wide
	var c uint64
	t[0], c = bits.Sub64(r[0], M[0], 0)
	t[1], c = bits.Sub64(r[1], M[1], c)
	t[2], c = bits.Sub64(r[2], M[2], c)
	t[3], c = bits.Sub64(r[3], M[3], c)
	t[4], _ = bits.Sub64(r[4], M[4], c)
	keep := uint64(int64(t[4]) >> 63) // all ones iff r < m
	r[0] = t[0] ^ ((t[0] ^ r[0]) & keep)
	r[1] = t[1] ^ ((t[1] ^ r[1]) & keep)
	r[2] = t[2] ^ ((t[2] ^ r[2]) & keep)
	r[3] = t[3] ^ ((t[3] ^ r[3]) & keep)
	r[4] = t[4] ^ ((t[4] ^ r[4]) & keep)
	return r
}

// modInverseCT returns x^-1 mod m for an odd prime m < 2^256 and x < m
// (0 for x = 0), in constant time. mInv62 is m^-1 mod 2^62.
func modInverseCT(x, m *limbs, mInv62 uint64) limbs {
	M := wideFromLimbs(m)
	f, g := M, wideFromLimbs(x)
	var d, e wide // f ≡ d·x, g ≡ e·x (mod m); -m < d, e < m
	e[0] = 1
	delta := int64(1)
	for i := 0; i < 12; i++ {
		var u, v, q, r int64
		delta, u, v, q, r = divsteps62(delta, f[0], g[0])
		// (f, g) <- T·(f, g) / 2^62; |f|, |g| <= m keeps the
		// combinations below 2^318 in absolute value.
		f, g = linShr62(&f, &g, u, v), linShr62(&f, &g, q, r)
		// (d, e) <- T·(d, e) / 2^62 mod m (see linShr62Mod).
		d, e = linShr62Mod(&d, &e, u, v, m, &M, mInv62), linShr62Mod(&d, &e, q, r, m, &M, mInv62)
	}
	// g = 0 and f = ±gcd(x, m) = ±1, so x^-1 ≡ ±d with -m < d < m.
	// (For x = 0, f = m is positive and d = 0.) Negate d if f < 0, then
	// add m if the result is negative.
	neg := uint64(int64(f[4]) >> 63)
	var zero wide
	nd := wideSub(&zero, &d)
	for i := range d {
		d[i] ^= (d[i] ^ nd[i]) & neg
	}
	sign := uint64(int64(d[4]) >> 63)
	addM := wide{M[0] & sign, M[1] & sign, M[2] & sign, M[3] & sign, M[4] & sign}
	md := wideAdd(&d, &addM)
	out := limbs{md[0], md[1], md[2], md[3]}
	clear(d[:])
	clear(e[:])
	clear(md[:])
	clear(nd[:])
	return out
}
