// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

// Variable-time code for PUBLIC inputs only (signature verification and
// public-key recovery). Everything in this file branches on, and indexes
// tables by, its inputs. A static test (TestVariableTimeHelpersOnlyOnPublicPaths)
// enforces that functions defined here are called only from Verify,
// RecoverPublicKey and each other, so a private key or a nonce can never
// reach them.
//
// Techniques:
//   - Jacobian coordinates (x = X/Z^2, y = Y/Z^3) with the a = 0 doubling
//     (2M + 5S), mixed addition (7M + 4S) and general addition
//     (11M + 5S); the exceptional cases (identity, P = ±Q) are handled by
//     explicit branches, which is acceptable for public data.
//   - The GLV endomorphism of secp256k1: λ·(x, y) = (β·x, y), with
//     λ^3 = 1 mod n and β^3 = 1 mod p. Each scalar is split as
//     k = k1 + k2·λ mod n with |k1|, |k2| < 2^128, which halves the
//     number of doublings.
//   - Width-w NAF: w = 8 for G (precomputed odd multiples of G and λG),
//     w = 5 for the variable point.
//
// The constants below are mathematical facts about the curve; tests check
// each one against math/big (arith_test.go, vartime_test.go).

import "math/bits"

type jacobian struct {
	x, y, z fieldElement
	inf     bool
}

func jacDouble(r, p *jacobian) {
	if p.inf {
		r.inf = true
		return
	}
	// The group order is odd, so no point has y = 0.
	var a, b, c, d, e, f, t fieldElement
	a.square(&p.x)
	b.square(&p.y)
	c.square(&b)
	d.add(&p.x, &b)
	d.square(&d)
	d.sub(&d, &a)
	d.sub(&d, &c)
	d.add(&d, &d)
	e.add(&a, &a)
	e.add(&e, &a)
	f.square(&e)
	var z3 fieldElement
	z3.mul(&p.y, &p.z)
	z3.add(&z3, &z3)
	r.x.sub(&f, &d)
	r.x.sub(&r.x, &d)
	t.sub(&d, &r.x)
	t.mul(&t, &e)
	c.mulSmall(&c, 8)
	r.y.sub(&t, &c)
	r.z = z3
	r.inf = false
}

// jacAddAffine sets r = p + q for an affine q (not the identity).
func jacAddAffine(r, p *jacobian, q *affinePoint) {
	if p.inf {
		r.x, r.y = q.x, q.y
		r.z.setOne()
		r.inf = false
		return
	}
	var z1z1, u2, s2, h, rr fieldElement
	z1z1.square(&p.z)
	u2.mul(&q.x, &z1z1)
	s2.mul(&q.y, &p.z)
	s2.mul(&s2, &z1z1)
	h.sub(&u2, &p.x)
	rr.sub(&s2, &p.y)
	if h.isZero() == 1 {
		if rr.isZero() == 1 {
			jacDouble(r, p)
		} else {
			r.inf = true
		}
		return
	}
	rr.add(&rr, &rr)
	var hh, i, j, v, x3, y3, z3 fieldElement
	hh.square(&h)
	i.add(&hh, &hh)
	i.add(&i, &i)
	j.mul(&h, &i)
	v.mul(&p.x, &i)
	x3.square(&rr)
	x3.sub(&x3, &j)
	x3.sub(&x3, &v)
	x3.sub(&x3, &v)
	y3.sub(&v, &x3)
	y3.mul(&y3, &rr)
	j.mul(&j, &p.y)
	j.add(&j, &j)
	y3.sub(&y3, &j)
	z3.add(&p.z, &h)
	z3.square(&z3)
	z3.sub(&z3, &z1z1)
	z3.sub(&z3, &hh)
	r.x, r.y, r.z, r.inf = x3, y3, z3, false
}

// jacAdd sets r = p + q.
func jacAdd(r, p, q *jacobian) {
	if p.inf {
		*r = *q
		return
	}
	if q.inf {
		*r = *p
		return
	}
	var z1z1, z2z2, u1, u2, s1, s2, h, rr fieldElement
	z1z1.square(&p.z)
	z2z2.square(&q.z)
	u1.mul(&p.x, &z2z2)
	u2.mul(&q.x, &z1z1)
	s1.mul(&p.y, &q.z)
	s1.mul(&s1, &z2z2)
	s2.mul(&q.y, &p.z)
	s2.mul(&s2, &z1z1)
	h.sub(&u2, &u1)
	rr.sub(&s2, &s1)
	if h.isZero() == 1 {
		if rr.isZero() == 1 {
			jacDouble(r, p)
		} else {
			r.inf = true
		}
		return
	}
	rr.add(&rr, &rr)
	var i, j, v, x3, y3, z3 fieldElement
	i.add(&h, &h)
	i.square(&i)
	j.mul(&h, &i)
	v.mul(&u1, &i)
	x3.square(&rr)
	x3.sub(&x3, &j)
	x3.sub(&x3, &v)
	x3.sub(&x3, &v)
	y3.sub(&v, &x3)
	y3.mul(&y3, &rr)
	s1.mul(&s1, &j)
	s1.add(&s1, &s1)
	y3.sub(&y3, &s1)
	z3.add(&p.z, &q.z)
	z3.square(&z3)
	z3.sub(&z3, &z1z1)
	z3.sub(&z3, &z2z2)
	z3.mul(&z3, &h)
	r.x, r.y, r.z, r.inf = x3, y3, z3, false
}

// jacToProjective converts to homogeneous projective coordinates:
// (X, Y, Z) Jacobian is (X·Z, Y, Z^3) projective.
func jacToProjective(out *point, p *jacobian) {
	if p.inf {
		out.setIdentity()
		return
	}
	var z2 fieldElement
	z2.square(&p.z)
	out.x.mul(&p.x, &p.z)
	out.y = p.y
	out.z.mul(&z2, &p.z)
}

// wnafVartime returns the width-w NAF of k (least significant digit
// first): digits are 0 or odd in (-2^(w-1), 2^(w-1)), non-zero digits are
// at least w positions apart. top is the index of the highest non-zero
// digit, or -1 for k = 0.
func wnafVartime(k *limbs, w uint) (digits [257]int8, top int) {
	x := [5]uint64{k[0], k[1], k[2], k[3], 0}
	mask := uint64(1)<<w - 1
	half := int64(1) << (w - 1)
	top = -1
	for i := 0; i < 257 && (x[0]|x[1]|x[2]|x[3]|x[4]) != 0; i++ {
		if x[0]&1 == 1 {
			d := int64(x[0] & mask)
			if d >= half {
				d -= int64(1) << w
			}
			digits[i] = int8(d)
			top = i
			if d > 0 {
				var b uint64
				x[0], b = bits.Sub64(x[0], uint64(d), 0)
				x[1], b = bits.Sub64(x[1], 0, b)
				x[2], b = bits.Sub64(x[2], 0, b)
				x[3], b = bits.Sub64(x[3], 0, b)
				x[4], _ = bits.Sub64(x[4], 0, b)
			} else {
				var c uint64
				x[0], c = bits.Add64(x[0], uint64(-d), 0)
				x[1], c = bits.Add64(x[1], 0, c)
				x[2], c = bits.Add64(x[2], 0, c)
				x[3], c = bits.Add64(x[3], 0, c)
				x[4], _ = bits.Add64(x[4], 0, c)
			}
		}
		x[0] = x[0]>>1 | x[1]<<63
		x[1] = x[1]>>1 | x[2]<<63
		x[2] = x[2]>>1 | x[3]<<63
		x[3] = x[3]>>1 | x[4]<<63
		x[4] >>= 1
	}
	return digits, top
}

// GLV constants (see the file comment).
var (
	glvBeta = mustField("7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee")
	// Short lattice basis (a1, b1), (a2, b2) with a + b·λ ≡ 0 mod n;
	// b2 = a1. Stored mod n as scalars: a1, -b1, a2, -b2.
	glvA1    = mustScalar("3086d221a7d46bcde86c90e49284eb15")
	glvNegB1 = mustScalar("e4437ed6010e88286f547fa90abfe4c3")
	glvA2    = mustScalar("114ca50f7a8e2f3f657c1108d9d44cfd8")
	glvNegB2 = func() scalar { var s scalar; s.neg(&glvA1); return s }()
	// g1 = round(2^384·b2/n), g2 = round(2^384·(-b1)/n).
	glvG1 = mustLimbs("3086d221a7d46bcde86c90e49284eb153daa8a1471e8ca7fe893209a45dbb031")
	glvG2 = mustLimbs("e4437ed6010e88286f547fa90abfe4c4221208ac9df506c61571b4ae8ac47f71")
)

// mulShift384 returns round(k·g / 2^384) for k < n and g in {g1, g2}; the
// result is below 2^128 for these inputs (tests check the bound).
func mulShift384(k, g *limbs) limbs {
	_, _, _, _, _, t5, t6, t7 := mulWords(k, g)
	r0, c := bits.Add64(t6, t5>>63, 0)
	r1, _ := bits.Add64(t7, 0, c)
	return limbs{r0, r1, 0, 0}
}

// splitScalarVartime returns k1, k2 with k ≡ ±k1 ± k2·λ (mod n), as
// non-negative values below 2^128 and their signs (true = negative).
func splitScalarVartime(k *scalar) (k1, k2 limbs, neg1, neg2 bool) {
	kc := k.canonical()
	c1 := mulShift384(&kc, &glvG1)
	c2 := mulShift384(&kc, &glvG2)
	var s1, s2, t scalar
	s1.setLimbsVartime(&c1)
	s2.setLimbsVartime(&c2)
	// k2 = -c1·b1 - c2·b2; k1 = k - k2·λ is computed as k - c1·a1 - c2·a2.
	var r1, r2 scalar
	r2.mul(&s1, &glvNegB1)
	t.mul(&s2, &glvNegB2)
	r2.add(&r2, &t)
	r1.mul(&s1, &glvA1)
	t.mul(&s2, &glvA2)
	r1.add(&r1, &t)
	r1.sub(k, &r1)
	k1, neg1 = signedHalf(&r1)
	k2, neg2 = signedHalf(&r2)
	return
}

// signedHalf returns |s| as the smaller of s and n - s, and whether n - s
// was taken.
func signedHalf(s *scalar) (limbs, bool) {
	if s.isHigh() == 1 {
		var t scalar
		t.neg(s)
		return t.canonical(), true
	}
	return s.canonical(), false
}

const (
	glvWindowG = 8 // odd multiples 1..255 of G and λG
	glvWindowQ = 5 // odd multiples 1..15 of the variable point
)

// glvTableG[i] = (2i+1)·G and glvTableLG[i] = (2i+1)·λG, affine.
var glvTableG, glvTableLG = func() (*[1 << (glvWindowG - 2)]affinePoint, *[1 << (glvWindowG - 2)]affinePoint) {
	const size = 1 << (glvWindowG - 2)
	var proj [size]point
	var g2 point
	proj[0] = generator
	g2.double(&generator)
	for i := 1; i < size; i++ {
		proj[i].add(&proj[i-1], &g2)
	}
	var t, lt [size]affinePoint
	batchAffine(t[:], proj[:])
	for i := range t {
		lt[i].x.mul(&t[i].x, &glvBeta)
		lt[i].y = t[i].y
	}
	return &t, &lt
}()

// linearCombinationVartime sets out = u1·G + u2·q for PUBLIC u1, u2 and q
// (any point, including the identity).
func linearCombinationVartime(out *point, u1, u2 *scalar, q *point) {
	a1, a2, na1, na2 := splitScalarVartime(u1)
	da1, ta1 := wnafVartime(&a1, glvWindowG)
	da2, ta2 := wnafVartime(&a2, glvWindowG)
	top := max(ta1, ta2)

	var oddQ, oddLQ [1 << (glvWindowQ - 2)]jacobian
	var db1, db2 [257]int8
	var nb1, nb2 bool
	if q.isIdentity() == 0 {
		// Affine q (public: a variable-time inversion is fine).
		var qa affinePoint
		if q.z.equal(&fieldOne) == 1 {
			qa.x, qa.y = q.x, q.y
		} else {
			var zinv fieldElement
			zinv.inv(&q.z)
			qa.x.mul(&q.x, &zinv)
			qa.y.mul(&q.y, &zinv)
		}
		var b1, b2 limbs
		var tb1, tb2 int
		b1, b2, nb1, nb2 = splitScalarVartime(u2)
		db1, tb1 = wnafVartime(&b1, glvWindowQ)
		db2, tb2 = wnafVartime(&b2, glvWindowQ)
		top = max(top, tb1, tb2)
		var q2 jacobian
		oddQ[0] = jacobian{x: qa.x, y: qa.y, z: fieldOne}
		jacDouble(&q2, &oddQ[0])
		for i := 1; i < len(oddQ); i++ {
			jacAdd(&oddQ[i], &oddQ[i-1], &q2)
		}
		for i := range oddQ {
			oddLQ[i] = oddQ[i]
			oddLQ[i].x.mul(&oddQ[i].x, &glvBeta)
		}
	}

	acc := jacobian{inf: true}
	var ap affinePoint
	var jp jacobian
	for i := top; i >= 0; i-- {
		jacDouble(&acc, &acc)
		if d := da1[i]; d != 0 {
			ap = glvTableG[absHalf(d)]
			if (d < 0) != na1 {
				ap.y.neg(&ap.y)
			}
			jacAddAffine(&acc, &acc, &ap)
		}
		if d := da2[i]; d != 0 {
			ap = glvTableLG[absHalf(d)]
			if (d < 0) != na2 {
				ap.y.neg(&ap.y)
			}
			jacAddAffine(&acc, &acc, &ap)
		}
		if d := db1[i]; d != 0 {
			jp = oddQ[absHalf(d)]
			if (d < 0) != nb1 {
				jp.y.neg(&jp.y)
			}
			jacAdd(&acc, &acc, &jp)
		}
		if d := db2[i]; d != 0 {
			jp = oddLQ[absHalf(d)]
			if (d < 0) != nb2 {
				jp.y.neg(&jp.y)
			}
			jacAdd(&acc, &acc, &jp)
		}
	}
	jacToProjective(out, &acc)
}

// absHalf maps an odd digit ±(2i+1) to the table index i.
func absHalf(d int8) int {
	if d < 0 {
		d = -d
	}
	return int(d) >> 1
}

var fieldOne = fieldFromUint(1)

// Constant parsing for the tables above (start-up only).

func mustLimbs(h string) limbs {
	if len(h) > 64 {
		panic("sila/secp256k1: constant too long")
	}
	var b [32]byte
	for i := 0; i < len(h); i++ {
		// Hex digit j counted from the right.
		j := len(h) - 1 - i
		v := hexVal(h[i])
		pos := 31 - j/2
		if j%2 == 1 {
			v <<= 4
		}
		b[pos] |= v
	}
	return limbsFromBytes(&b)
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	panic("sila/secp256k1: bad hex constant")
}

func mustField(h string) fieldElement {
	l := mustLimbs(h)
	var b [32]byte
	limbsToBytes(&b, &l)
	var f fieldElement
	if f.setBytes(&b) != 1 {
		panic("sila/secp256k1: field constant out of range")
	}
	return f
}

func mustScalar(h string) scalar {
	l := mustLimbs(h)
	var s scalar
	s.setLimbsVartime(&l)
	return s
}

// setLimbsVartime sets z from canonical limbs (< n); public values only.
func (z *scalar) setLimbsVartime(x *limbs) {
	var b [32]byte
	limbsToBytes(&b, x)
	if z.setBytesCanonical(&b) != 1 {
		panic("sila/secp256k1: scalar constant out of range")
	}
}
