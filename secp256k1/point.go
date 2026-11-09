// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

import "math/bits"

// Group arithmetic on secp256k1: y^2 = x^3 + 7 over GF(p).
//
// Points use homogeneous projective coordinates (X:Y:Z), x = X/Z,
// y = Y/Z; the identity (point at infinity) is (0:1:0). Addition and
// doubling use the complete formulas for prime-order short Weierstrass
// curves with a = 0 from Renes, Costello and Batina, "Complete addition
// formulas for prime order elliptic curves" (EUROCRYPT 2016), Algorithms 7
// and 9. "Complete" means the same straight-line code is correct for every
// pair of inputs, including P + P, P + (-P) and the identity, so no branch
// depends on the (possibly secret) operands.

type point struct{ x, y, z fieldElement }

// curveB3 is 3·b = 21.
var curveB3 = fieldFromUint(21)

// curveB is b = 7.
var curveB = fieldFromUint(7)

func (p *point) setIdentity() *point {
	p.x.setZero()
	p.y.setOne()
	p.z.setZero()
	return p
}

// isIdentity returns 1 if p is the point at infinity (Z == 0).
func (p *point) isIdentity() uint64 { return p.z.isZero() }

// add sets r = p + q (complete; any inputs, r may alias p or q).
func (r *point) add(p, q *point) *point {
	var t0, t1, t2, t3, t4, x3, y3, z3 fieldElement
	t0.mul(&p.x, &q.x)
	t1.mul(&p.y, &q.y)
	t2.mul(&p.z, &q.z)
	t3.add(&p.x, &p.y)
	t4.add(&q.x, &q.y)
	t3.mul(&t3, &t4)
	t4.add(&t0, &t1)
	t3.sub(&t3, &t4)
	t4.add(&p.y, &p.z)
	x3.add(&q.y, &q.z)
	t4.mul(&t4, &x3)
	x3.add(&t1, &t2)
	t4.sub(&t4, &x3)
	x3.add(&p.x, &p.z)
	y3.add(&q.x, &q.z)
	x3.mul(&x3, &y3)
	y3.add(&t0, &t2)
	y3.sub(&x3, &y3)
	x3.add(&t0, &t0)
	t0.add(&x3, &t0)
	t2.mul(&curveB3, &t2)
	z3.add(&t1, &t2)
	t1.sub(&t1, &t2)
	y3.mul(&curveB3, &y3)
	x3.mul(&t4, &y3)
	t2.mul(&t3, &t1)
	x3.sub(&t2, &x3)
	y3.mul(&y3, &t0)
	t1.mul(&t1, &z3)
	y3.add(&t1, &y3)
	t0.mul(&t0, &t3)
	z3.mul(&z3, &t4)
	z3.add(&z3, &t0)
	r.x, r.y, r.z = x3, y3, z3
	return r
}

// double sets r = 2p (complete; r may alias p).
func (r *point) double(p *point) *point {
	var t0, t1, t2, x3, y3, z3 fieldElement
	t0.square(&p.y)
	z3.add(&t0, &t0)
	z3.add(&z3, &z3)
	z3.add(&z3, &z3)
	t1.mul(&p.y, &p.z)
	t2.square(&p.z)
	t2.mul(&curveB3, &t2)
	x3.mul(&t2, &z3)
	y3.add(&t0, &t2)
	z3.mul(&t1, &z3)
	t1.add(&t2, &t2)
	t2.add(&t1, &t2)
	t0.sub(&t0, &t2)
	y3.mul(&t0, &y3)
	y3.add(&x3, &y3)
	t1.mul(&p.x, &p.y)
	x3.mul(&t0, &t1)
	x3.add(&x3, &x3)
	r.x, r.y, r.z = x3, y3, z3
	return r
}

// neg sets r = -p.
func (r *point) neg(p *point) *point {
	r.x = p.x
	r.y.neg(&p.y)
	r.z = p.z
	return r
}

// selectFrom sets r = a if cond == 1, else b (constant time).
func (r *point) selectFrom(a, b *point, cond uint64) *point {
	r.x.selectFrom(&a.x, &b.x, cond)
	r.y.selectFrom(&a.y, &b.y, cond)
	r.z.selectFrom(&a.z, &b.z, cond)
	return r
}

// equal returns 1 if p and q represent the same group element, comparing
// cross products so no inversion is needed (constant time).
func (p *point) equal(q *point) uint64 {
	var a, b, c, d fieldElement
	a.mul(&p.x, &q.z)
	b.mul(&q.x, &p.z)
	c.mul(&p.y, &q.z)
	d.mul(&q.y, &p.z)
	bothInf := p.isIdentity() & q.isIdentity()
	noneInf := (1 ^ p.isIdentity()) & (1 ^ q.isIdentity())
	return bothInf | (noneInf & a.equal(&b) & c.equal(&d))
}

// affine returns the affine coordinates of p and 1, or zero values and 0
// for the identity. Constant time (single field inversion).
func (p *point) affine() (x, y fieldElement, ok uint64) {
	var zinv fieldElement
	zinv.inv(&p.z) // 0 for the identity
	x.mul(&p.x, &zinv)
	y.mul(&p.y, &zinv)
	return x, y, 1 ^ p.isIdentity()
}

// setAffine sets p = (x, y, 1) without validating the curve equation.
func (p *point) setAffine(x, y *fieldElement) *point {
	p.x = *x
	p.y = *y
	p.z.setOne()
	return p
}

// isOnCurve returns 1 if the affine point (x, y) satisfies y^2 = x^3 + 7.
func isOnCurve(x, y *fieldElement) uint64 {
	var lhs, rhs fieldElement
	lhs.square(y)
	rhs.square(x)
	rhs.mul(&rhs, x)
	rhs.add(&rhs, &curveB)
	return lhs.equal(&rhs)
}

// generator is G from SEC 2 v2.0, §2.4.1.
var generator = func() point {
	gx := [32]byte{
		0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
		0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
	}
	gy := [32]byte{
		0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
		0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8,
	}
	var x, y fieldElement
	if x.setBytes(&gx)&y.setBytes(&gy)&isOnCurve(&x, &y) != 1 {
		panic("sila/secp256k1: invalid generator constant")
	}
	var g point
	g.setAffine(&x, &y)
	return g
}()

// lookup sets r = table[idx] by scanning every entry, so the memory access
// pattern does not depend on the secret index (0 <= idx < len(table)).
func (r *point) lookup(table *[16]point, idx uint64) *point {
	r.setIdentity()
	for i := range table {
		// eq = 1 iff i == idx, computed without branches.
		d := uint64(i) ^ idx
		eq := 1 ^ ((d | -d) >> 63)
		r.selectFrom(&table[i], r, eq)
	}
	return r
}

// scalarMult sets r = k·p in constant time with respect to k and p:
// a fixed 4-bit window, 64 windows of 4 doublings and one complete
// addition each, with a constant-time table lookup.
func (r *point) scalarMult(k *scalar, p *point) *point {
	var table [16]point
	table[0].setIdentity()
	table[1] = *p
	for i := 2; i < 16; i++ {
		if i%2 == 0 {
			table[i].double(&table[i/2])
		} else {
			table[i].add(&table[i-1], p)
		}
	}
	kc := k.canonical()
	var acc, sel point
	acc.setIdentity()
	for w := 63; w >= 0; w-- {
		acc.double(&acc)
		acc.double(&acc)
		acc.double(&acc)
		acc.double(&acc)
		sel.lookup(&table, window4(&kc, w))
		acc.add(&acc, &sel)
	}
	*r = acc
	kc = limbs{}
	return r
}

// baseTable[w][j] = j·16^w·G for the 64 windows: k·G then needs only 64
// complete additions with constant-time lookups and no doublings.
var baseTable = func() *[64][16]point {
	var t [64][16]point
	base := generator
	for w := 0; w < 64; w++ {
		t[w][0].setIdentity()
		t[w][1] = base
		for j := 2; j < 16; j++ {
			t[w][j].add(&t[w][j-1], &base)
		}
		// Normalise entries to Z = 1 (public precomputation).
		for j := 1; j < 16; j++ {
			x, y, _ := t[w][j].affine()
			t[w][j].setAffine(&x, &y)
		}
		var next point
		next.double(&t[w][8]) // 16·base
		x, y, _ := next.affine()
		base.setAffine(&x, &y)
	}
	return &t
}()

// scalarBaseMult sets r = k·G in constant time with respect to k.
func (r *point) scalarBaseMult(k *scalar) *point {
	kc := k.canonical()
	var acc, sel point
	acc.setIdentity()
	for w := 0; w < 64; w++ {
		sel.lookup(&baseTable[w], window4(&kc, w))
		acc.add(&acc, &sel)
	}
	*r = acc
	kc = limbs{}
	return r
}

// ---------------------------------------------------------------------------
// Variable-time helpers. These branch on, and index tables by, their scalar
// inputs and are therefore restricted to PUBLIC values (signature
// verification and public-key recovery). They are never called with a
// private key or a nonce.

// wnaf5 returns the width-5 non-adjacent form of the canonical value k,
// least significant digit first: digits are 0 or odd in [-15, 15], and any
// two non-zero digits are at least 5 positions apart.
func wnaf5(k *limbs) [257]int8 {
	var digits [257]int8
	// x holds k with one extra limb of headroom for k + |d| carries.
	x := [5]uint64{k[0], k[1], k[2], k[3], 0}
	for i := 0; i < 257 && (x[0]|x[1]|x[2]|x[3]|x[4]) != 0; i++ {
		if x[0]&1 == 1 {
			d := int64(x[0] & 31)
			if d >= 16 {
				d -= 32
			}
			digits[i] = int8(d)
			// x -= d
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
	return digits
}

// linearCombinationVartime sets out = u1·G + u2·q for PUBLIC u1, u2, q.
// u1·G uses the precomputed base table (no doublings); u2·q uses a
// width-5 NAF with the odd multiples q, 3q, ..., 15q.
func linearCombinationVartime(out *point, u1, u2 *scalar, q *point) {
	var odd [8]point
	odd[0] = *q
	var q2 point
	q2.double(q)
	for i := 1; i < 8; i++ {
		odd[i].add(&odd[i-1], &q2)
	}
	k2 := u2.canonical()
	digits := wnaf5(&k2)
	top := 256
	for top >= 0 && digits[top] == 0 {
		top--
	}
	var acc, neg point
	acc.setIdentity()
	for i := top; i >= 0; i-- {
		acc.double(&acc)
		if d := digits[i]; d > 0 {
			acc.add(&acc, &odd[(d-1)/2])
		} else if d < 0 {
			neg.neg(&odd[(-d-1)/2])
			acc.add(&acc, &neg)
		}
	}
	k1 := u1.canonical()
	for w := 0; w < 64; w++ {
		if nib := window4(&k1, w); nib != 0 {
			acc.add(&acc, &baseTable[w][nib])
		}
	}
	*out = acc
}
