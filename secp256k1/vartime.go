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

import (
	"math/bits"
	"sync/atomic"
)

type jacobian struct {
	x, y, z fieldElement
	inf     bool
}

// jacDoubleGo is the portable doubling (jacDouble on architectures
// without vartime_arm64.s, and the reference it is tested against).
func jacDoubleGo(r, p *jacobian) {
	if p.inf {
		r.inf = true
		return
	}
	// The group order is odd, so no point has y = 0. Halved form of the
	// a = 0 doubling (the result is the usual one scaled by 1/2, which
	// is the same Jacobian point):
	//   L = (3/2)·X^2, S = Y^2, T = -X·S,
	//   X3 = L^2 + 2T, Y3 = -(L·(X3 + T) + S^2), Z3 = Y·Z.
	var l, s, t, u, w fieldElement
	s.square(&p.y)
	l.square(&p.x)
	addVartime(&u, &l, &l)
	addVartime(&l, &u, &l)
	l.halfVartime(&l)
	t.mul(&p.x, &s)
	t.neg(&t)
	r.z.mul(&p.y, &p.z)
	var x3 fieldElement
	x3.square(&l)
	addVartime(&x3, &x3, &t)
	addVartime(&x3, &x3, &t)
	addVartime(&u, &x3, &t)
	u.mul(&u, &l)
	w.square(&s)
	addVartime(&u, &u, &w)
	r.y.neg(&u)
	r.x = x3
	r.inf = false
}

// addVartime sets z = x + y mod p for canonical x, y. PUBLIC values only:
// the reduction is taken by a branch, which is almost never taken for
// uniformly distributed values (well predicted, cheaper than the
// constant-time selection).
func addVartime(z, x, y *fieldElement) {
	r0, c := bits.Add64(x.v[0], y.v[0], 0)
	r1, c := bits.Add64(x.v[1], y.v[1], c)
	r2, c := bits.Add64(x.v[2], y.v[2], c)
	r3, c := bits.Add64(x.v[3], y.v[3], c)
	if c == 0 && (r3 != ^uint64(0) || r2 != ^uint64(0) || r1 != ^uint64(0) || r0 < fieldP.m[0]) {
		z.v = limbs{r0, r1, r2, r3}
		return
	}
	// r >= p (or carried): subtract p, i.e. add fieldC mod 2^256.
	r0, c = bits.Add64(r0, fieldC, 0)
	r1, c = bits.Add64(r1, 0, c)
	r2, c = bits.Add64(r2, 0, c)
	r3, _ = bits.Add64(r3, 0, c)
	z.v = limbs{r0, r1, r2, r3}
}

// halfVartime sets z = x/2 mod p for a canonical x: x/2 if x is even,
// (x + p)/2 otherwise (computed with 257 bits). Branch-free, but only used
// on public values.
func (z *fieldElement) halfVartime(x *fieldElement) *fieldElement {
	m := -(x.v[0] & 1)
	r0, c := bits.Add64(x.v[0], fieldP.m[0]&m, 0)
	r1, c := bits.Add64(x.v[1], fieldP.m[1]&m, c)
	r2, c := bits.Add64(x.v[2], fieldP.m[2]&m, c)
	r3, c := bits.Add64(x.v[3], fieldP.m[3]&m, c)
	z.v[0] = r0>>1 | r1<<63
	z.v[1] = r1>>1 | r2<<63
	z.v[2] = r2>>1 | r3<<63
	z.v[3] = r3>>1 | c<<63
	return z
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
	addVartime(&rr, &rr, &rr)
	var hh, i, j, v, x3, y3, z3 fieldElement
	hh.square(&h)
	addVartime(&i, &hh, &hh)
	addVartime(&i, &i, &i)
	j.mul(&h, &i)
	v.mul(&p.x, &i)
	x3.square(&rr)
	x3.sub(&x3, &j)
	x3.sub(&x3, &v)
	x3.sub(&x3, &v)
	y3.sub(&v, &x3)
	y3.mul(&y3, &rr)
	j.mul(&j, &p.y)
	addVartime(&j, &j, &j)
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
	addVartime(&rr, &rr, &rr)
	var i, j, v, x3, y3, z3 fieldElement
	addVartime(&i, &h, &h)
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
	addVartime(&s1, &s1, &s1)
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
func wnafVartime(k *limbs, w uint) (digits [257]int16, top int) {
	if w < 2 || w > 15 {
		// Digits are int16: |d| < 2^(w-1) must fit.
		panic("sila/secp256k1: unsupported wNAF width")
	}
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
			digits[i] = int16(d)
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
	// odd multiples 1..2^glvWindowG - 1 of G and λG (2·2^(w-2) affine
	// points, 128 KiB for w = 12), built on first use.
	glvWindowG = 12
	glvWindowQ = 5 // odd multiples 1..15 of the variable point
)

// glvTables holds glvTables().g[i] = (2i+1)·G and lg[i] = (2i+1)·λG,
// affine. They are public constants, computed on first use (not at
// program start, to keep start-up cheap) and shared; concurrent first
// calls may both compute them, and one result is kept.
type glvGTables struct {
	g, lg [1 << (glvWindowG - 2)]affinePoint
}

var glvTablesG atomic.Pointer[glvGTables]

func glvTables() *glvGTables {
	if t := glvTablesG.Load(); t != nil {
		return t
	}
	const size = 1 << (glvWindowG - 2)
	t := new(glvGTables)
	proj := make([]point, size)
	var g2 point
	proj[0] = generator
	g2.double(&generator)
	for i := 1; i < size; i++ {
		proj[i].add(&proj[i-1], &g2)
	}
	batchAffine(t.g[:], proj)
	for i := range t.g {
		t.lg[i].x.mul(&t.g[i].x, &glvBeta)
		t.lg[i].y = t.g[i].y
	}
	glvTablesG.CompareAndSwap(nil, t)
	return glvTablesG.Load()
}

// linearCombinationVartimeGeneric sets out = u1·G + u2·q for PUBLIC u1, u2
// and q (any point, including the identity), with general Jacobian
// additions for the multiples of q. It is the fallback of
// linearCombinationVartime for the exceptional table cases and the
// reference it is tested against.
func linearCombinationVartimeGeneric(out *point, u1, u2 *scalar, q *point) {
	tg := glvTables()
	a1, a2, na1, na2 := splitScalarVartime(u1)
	da1, ta1 := wnafVartime(&a1, glvWindowG)
	da2, ta2 := wnafVartime(&a2, glvWindowG)
	top := max(ta1, ta2)

	var oddQ, oddLQ [1 << (glvWindowQ - 2)]jacobian
	var db1, db2 [257]int16
	var nb1, nb2 bool
	if q.isIdentity() == 0 {
		// Affine q (public: a variable-time inversion is fine).
		var qa affinePoint
		if q.z.equal(&fieldOne) == 1 {
			qa.x, qa.y = q.x, q.y
		} else {
			var zinv fieldElement
			zinv.invVartime(&q.z)
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
			ap = tg.g[absHalf(d)]
			if (d < 0) != na1 {
				ap.y.neg(&ap.y)
			}
			jacAddAffine(&acc, &acc, &ap)
		}
		if d := da2[i]; d != 0 {
			ap = tg.lg[absHalf(d)]
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

// publicKeyFromPointVartime is publicKeyFromPoint for a PUBLIC point
// (recovered keys): the affine conversion uses the variable-time
// inversion.
func publicKeyFromPointVartime(p *point) (PublicKey, error) {
	if p.isIdentity() == 1 {
		return PublicKey{}, ErrInvalidPublicKey
	}
	var zinv, x, y fieldElement
	zinv.invVartime(&p.z)
	x.mul(&p.x, &zinv)
	y.mul(&p.y, &zinv)
	return PublicKey{x: x.bytes(), y: y.bytes(), valid: true}, nil
}

// linearCombinationVartime sets out = u1·G + u2·q for PUBLIC u1, u2 and q
// (any point, including the identity). Same digits as the generic version,
// with the "effective affine" technique for q:
//
//   - the odd multiples (2i+1)·q are built so that they all share one
//     Jacobian Z (co-Z table, from additions of 2q treated as affine on an
//     isomorphic curve, then rescaled with the accumulated z ratios);
//   - with x' = x·Z^2, y' = y·Z^3 every point maps to the curve
//     y'^2 = x'^3 + 7·Z^6; the a = 0 Jacobian formulas do not use the
//     constant term, so the whole sum is computed on that curve, where the
//     table entries are affine (mixed additions, 7M + 4S instead of
//     11M + 5S, and no inversion);
//   - the affine G multiples are added as Jacobian points (x, y, 1/Z)
//     (jacAddZinv, one extra multiplication), and the result's Z is
//     multiplied by Z at the end to return to secp256k1.
func linearCombinationVartime(out *point, u1, u2 *scalar, q *point) {
	if q.isIdentity() == 1 {
		linearCombinationVartimeGeneric(out, u1, u2, q)
		return
	}
	// Affine q (public: a variable-time inversion is fine).
	// q is projective: x = X/Z, y = Y/Z.
	var qa affinePoint
	if q.z.equal(&fieldOne) == 1 {
		qa.x, qa.y = q.x, q.y
	} else {
		var zinv fieldElement
		zinv.invVartime(&q.z)
		qa.x.mul(&q.x, &zinv)
		qa.y.mul(&q.y, &zinv)
	}
	var tq, tlq [1 << (glvWindowQ - 2)]affinePoint
	var globalZ fieldElement
	if !coZOddMultiples(&tq, &globalZ, &qa) {
		linearCombinationVartimeGeneric(out, u1, u2, q)
		return
	}
	for i := range tq {
		tlq[i].x.mul(&tq[i].x, &glvBeta)
		tlq[i].y = tq[i].y
	}

	tg := glvTables()
	a1, a2, na1, na2 := splitScalarVartime(u1)
	da1, ta1 := wnafVartime(&a1, glvWindowG)
	da2, ta2 := wnafVartime(&a2, glvWindowG)
	b1, b2, nb1, nb2 := splitScalarVartime(u2)
	db1, tb1 := wnafVartime(&b1, glvWindowQ)
	db2, tb2 := wnafVartime(&b2, glvWindowQ)
	top := max(ta1, ta2, tb1, tb2)

	acc := jacobian{inf: true}
	var ap affinePoint
	for i := top; i >= 0; i-- {
		jacDouble(&acc, &acc)
		if d := db1[i]; d != 0 {
			ap = tq[absHalf(d)]
			if (d < 0) != nb1 {
				ap.y.neg(&ap.y)
			}
			jacAddAffine(&acc, &acc, &ap)
		}
		if d := db2[i]; d != 0 {
			ap = tlq[absHalf(d)]
			if (d < 0) != nb2 {
				ap.y.neg(&ap.y)
			}
			jacAddAffine(&acc, &acc, &ap)
		}
		if d := da1[i]; d != 0 {
			ap = tg.g[absHalf(d)]
			if (d < 0) != na1 {
				ap.y.neg(&ap.y)
			}
			jacAddZinv(&acc, &acc, &ap, &globalZ)
		}
		if d := da2[i]; d != 0 {
			ap = tg.lg[absHalf(d)]
			if (d < 0) != na2 {
				ap.y.neg(&ap.y)
			}
			jacAddZinv(&acc, &acc, &ap, &globalZ)
		}
	}
	if !acc.inf {
		acc.z.mul(&acc.z, &globalZ)
	}
	jacToProjective(out, &acc)
}

// coZOddMultiples sets t[i] = (X_i, Y_i) and Z such that the Jacobian
// points (X_i, Y_i, Z) are (2i+1)·q, for an affine q other than the
// identity. It returns false in the exceptional cases (2q or a sum being
// the identity or a doubling), which cannot occur for a point of the
// prime-order group but are handled by the caller's generic fallback.
func coZOddMultiples(t *[1 << (glvWindowQ - 2)]affinePoint, Z *fieldElement, q *affinePoint) bool {
	// d = 2q (Jacobian; with the halved doubling d.z = y_q).
	var d jacobian
	jacDouble(&d, &jacobian{x: q.x, y: q.y, z: fieldOne})
	if d.inf || d.z.isZero() == 1 {
		return false
	}
	// On the isomorphic curve scaled by d.z, d is the affine point
	// (d.x, d.y) and q is (x·dz^2, y·dz^3) with Z = 1.
	var dz2, dz3 fieldElement
	dz2.square(&d.z)
	dz3.mul(&dz2, &d.z)
	dAff := affinePoint{x: d.x, y: d.y}
	var pts [1 << (glvWindowQ - 2)]jacobian
	var zr [1 << (glvWindowQ - 2)]fieldElement // zr[i] = pts[i].z / pts[i-1].z
	pts[0].x.mul(&q.x, &dz2)
	pts[0].y.mul(&q.y, &dz3)
	pts[0].z = fieldOne
	for i := 1; i < len(pts); i++ {
		if !jacAddAffineZR(&pts[i], &zr[i], &pts[i-1], &dAff) {
			return false
		}
	}
	// Rescale every point to the last point's Z: point i is multiplied by
	// r_i = zr[i+1]·...·zr[last] (X·r^2, Y·r^3).
	last := len(pts) - 1
	t[last] = affinePoint{x: pts[last].x, y: pts[last].y}
	r := zr[last]
	for i := last - 1; i >= 0; i-- {
		var r2, r3 fieldElement
		r2.square(&r)
		r3.mul(&r2, &r)
		t[i].x.mul(&pts[i].x, &r2)
		t[i].y.mul(&pts[i].y, &r3)
		if i > 0 {
			r.mul(&r, &zr[i])
		}
	}
	// Back on secp256k1, the shared Z is (last Z)·dz.
	Z.mul(&pts[last].z, &d.z)
	return true
}

// jacAddAffineZR sets r = p + q (p Jacobian, not the identity; q affine)
// and zr = r.z / p.z. It returns false, leaving r unspecified, if the sum
// is a doubling or the identity (h = 0).
func jacAddAffineZR(r *jacobian, zr *fieldElement, p *jacobian, q *affinePoint) bool {
	var z1z1, u2, s2, h, rr fieldElement
	z1z1.square(&p.z)
	u2.mul(&q.x, &z1z1)
	s2.mul(&q.y, &p.z)
	s2.mul(&s2, &z1z1)
	h.sub(&u2, &p.x)
	if h.isZero() == 1 {
		return false
	}
	rr.sub(&s2, &p.y)
	addVartime(&rr, &rr, &rr)
	var hh, i, j, v, x3, y3 fieldElement
	hh.square(&h)
	addVartime(&i, &hh, &hh)
	addVartime(&i, &i, &i)
	j.mul(&h, &i)
	v.mul(&p.x, &i)
	x3.square(&rr)
	x3.sub(&x3, &j)
	x3.sub(&x3, &v)
	x3.sub(&x3, &v)
	y3.sub(&v, &x3)
	y3.mul(&y3, &rr)
	j.mul(&j, &p.y)
	addVartime(&j, &j, &j)
	y3.sub(&y3, &j)
	addVartime(zr, &h, &h) // z3 = 2·z1·h
	r.z.mul(&p.z, zr)
	r.x, r.y, r.inf = x3, y3, false
	return true
}

// jacAddZinv sets r = p + b, where b is given by affine coordinates
// (b.x, b.y) and stands for the Jacobian point (b.x, b.y, 1/bz). With
// az = p.z·bz, it is the mixed addition with az in place of p.z for b's
// scaling, and z3 = 2·p.z·h (the common factor bz^3 cancels).
func jacAddZinv(r, p *jacobian, b *affinePoint, bz *fieldElement) {
	if p.inf {
		// (b.x, b.y, 1/bz) ~ (b.x·bz^2, b.y·bz^3, 1).
		var bz2, bz3 fieldElement
		bz2.square(bz)
		bz3.mul(&bz2, bz)
		r.x.mul(&b.x, &bz2)
		r.y.mul(&b.y, &bz3)
		r.z = fieldOne
		r.inf = false
		return
	}
	var az, z1z1, u2, s2, h, rr fieldElement
	az.mul(&p.z, bz)
	z1z1.square(&az)
	u2.mul(&b.x, &z1z1)
	s2.mul(&b.y, &az)
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
	addVartime(&rr, &rr, &rr)
	var hh, i, j, v, x3, y3, z3 fieldElement
	hh.square(&h)
	addVartime(&i, &hh, &hh)
	addVartime(&i, &i, &i)
	j.mul(&h, &i)
	v.mul(&p.x, &i)
	x3.square(&rr)
	x3.sub(&x3, &j)
	x3.sub(&x3, &v)
	x3.sub(&x3, &v)
	y3.sub(&v, &x3)
	y3.mul(&y3, &rr)
	j.mul(&j, &p.y)
	addVartime(&j, &j, &j)
	y3.sub(&y3, &j)
	z3.mul(&p.z, &h)
	addVartime(&z3, &z3, &z3)
	r.x, r.y, r.z, r.inf = x3, y3, z3, false
}

// absHalf maps an odd digit ±(2i+1) to the table index i.
func absHalf(d int16) int {
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
