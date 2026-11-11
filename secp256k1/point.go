// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

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

// curveB is b = 7; the formulas multiply by 3b = 21 with mulSmall.
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
	t2.mulSmall(&t2, 21)
	z3.add(&t1, &t2)
	t1.sub(&t1, &t2)
	y3.mulSmall(&y3, 21)
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
	t2.mulSmall(&t2, 21)
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

// affinePoint is a point with Z = 1, stored as (x, y). It never
// represents the identity.
type affinePoint struct{ x, y fieldElement }

// addMixed sets r = p + q for a projective p (any point, including the
// identity) and an affine q (never the identity). Complete for these
// inputs: Renes–Costello–Batina 2016, Algorithm 8 (a = 0), 11
// multiplications and two multiplications by 3b. r may alias p.
func (r *point) addMixed(p *point, q *affinePoint) *point {
	var t0, t1, t2, t3, t4, x3, y3, z3 fieldElement
	t0.mul(&p.x, &q.x)
	t1.mul(&p.y, &q.y)
	t3.add(&q.x, &q.y)
	t4.add(&p.x, &p.y)
	t3.mul(&t3, &t4)
	t4.add(&t0, &t1)
	t3.sub(&t3, &t4)
	t4.mul(&q.y, &p.z)
	t4.add(&t4, &p.y)
	y3.mul(&q.x, &p.z)
	y3.add(&y3, &p.x)
	x3.add(&t0, &t0)
	t0.add(&x3, &t0)
	t2.mulSmall(&p.z, 21)
	z3.add(&t1, &t2)
	t1.sub(&t1, &t2)
	y3.mulSmall(&y3, 21)
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

// Fixed-base multiplication uses signed radix-32 digits (Booth
// recoding): k = sum of d_i·32^i for i < baseWindows, with
// d_i = (5-bit window i) + (bit 5i-1) - 32·(bit 5i+4), so d_i is in
// [-16, 16]. Bit 259 of k is 0, so the top digit is non-negative and 52
// windows cover every k < 2^256.
const (
	baseWindows = 52
	baseEntries = 16
)

// baseTable[w][j] = (j+1)·32^w·G in affine form.
var baseTable = func() *[baseWindows][baseEntries]affinePoint {
	var t [baseWindows][baseEntries]affinePoint
	base := generator
	var proj [baseEntries]point
	for w := 0; w < baseWindows; w++ {
		proj[0] = base
		for j := 1; j < baseEntries; j++ {
			proj[j].add(&proj[j-1], &base)
		}
		batchAffine(t[w][:], proj[:])
		// next base = 32·base = 2·(16·base)
		var next point
		next.double(&proj[baseEntries-1])
		base = next
	}
	return &t
}()

// batchAffine converts non-identity projective points to affine with one
// field inversion (Montgomery's simultaneous inversion). Public data only.
func batchAffine(out []affinePoint, in []point) {
	prefix := make([]fieldElement, len(in))
	acc := fieldFromUint(1)
	for i := range in {
		prefix[i] = acc
		acc.mul(&acc, &in[i].z)
	}
	var inv fieldElement
	inv.inv(&acc)
	for i := len(in) - 1; i >= 0; i-- {
		var zinv fieldElement
		zinv.mul(&inv, &prefix[i])
		inv.mul(&inv, &in[i].z)
		out[i].x.mul(&in[i].x, &zinv)
		out[i].y.mul(&in[i].y, &zinv)
	}
}

// boothDigit returns the magnitude (0..16) and sign (1 if negative) of
// the signed radix-32 digit w of the canonical value k, without branches.
// The window index is public; the digit is secret.
func boothDigit(k *limbs, w int) (mag, neg uint64) {
	// Six bits: bit 5w-1 (zero for w = 0) and bits 5w .. 5w+4.
	lo := 5*w - 1
	var v uint64
	if lo < 0 {
		v = bitsAt(k, 0, 5) << 1
	} else {
		v = bitsAt(k, lo, 6)
	}
	// d = (v >> 1) + (v & 1) - 32·(v >> 5).
	neg = v >> 5
	d := (v >> 1) + (v & 1) // 0..32
	// mag = neg ? 32 - d : d
	mag = d ^ ((d ^ (32 - d)) & -neg)
	return mag, neg
}

// bitsAt returns the n (<= 6) bits of k starting at bit position pos
// (public); bits beyond 255 read as zero.
func bitsAt(k *limbs, pos, n int) uint64 {
	limb := pos / 64
	off := uint(pos % 64)
	var v uint64
	if limb < 4 {
		v = k[limb] >> off
		if off+uint(n) > 64 && limb+1 < 4 {
			v |= k[limb+1] << (64 - off)
		}
	}
	return v & (1<<uint(n) - 1)
}

// scalarBaseMult sets r = k·G in constant time with respect to k: 52
// complete mixed additions with constant-time lookups, conditional
// negations and conditional skips, and no doublings. It is used for fresh
// random values (blinding points); the signing and key paths use
// scalarBaseMultCanonical on a blinded canonical sum.
func (r *point) scalarBaseMult(k *scalar) *point {
	kc := k.canonical()
	one := fieldFromUint(1)
	r.scalarBaseMultCanonical(&kc, &one)
	kc = limbs{}
	return r
}

// scalarBaseMultCanonical sets r = k·G for a canonical k (k < n), in
// constant time with respect to k, without any multiplication that takes
// k as an operand (Booth digits are extracted with shifts and masks).
// The accumulator starts as the identity (0 : lambda : 0); the complete
// formulas are homogeneous, so every intermediate coordinate is the
// projective representation scaled by lambda. With a fresh secret lambda
// per call (lambda != 0), the field multiplications of two calls on the
// same k see unrelated operands.
func (r *point) scalarBaseMultCanonical(k *limbs, lambda *fieldElement) *point {
	kc := *k
	var acc, sum point
	var sel affinePoint
	var negY fieldElement
	acc.x.setZero()
	acc.y = *lambda
	acc.z.setZero()
	for w := 0; w < baseWindows; w++ {
		mag, neg := boothDigit(&kc, w)
		sel.lookupAffine(&baseTable[w], mag)
		negY.neg(&sel.y)
		sel.y.selectFrom(&negY, &sel.y, neg)
		sum.addMixed(&acc, &sel)
		// Keep acc when the digit is zero.
		nz := (mag | -mag) >> 63
		acc.selectFrom(&sum, &acc, nz)
	}
	*r = acc
	kc = limbs{}
	return r
}
