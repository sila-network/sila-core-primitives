// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

import (
	"math/big"
	"math/rand"
	"testing"
)

var (
	bigLambda, _ = new(big.Int).SetString("5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72", 16)
	bigBeta, _   = new(big.Int).SetString("7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee", 16)
)

func limbsToBig(l limbs) *big.Int {
	var b [32]byte
	limbsToBytes(&b, &l)
	return new(big.Int).SetBytes(b[:])
}

func TestGLVConstants(t *testing.T) {
	one := big.NewInt(1)
	if new(big.Int).Exp(bigLambda, big.NewInt(3), bigN).Cmp(one) != 0 || bigLambda.Cmp(one) == 0 {
		t.Fatal("lambda is not a non-trivial cube root of unity mod n")
	}
	if new(big.Int).Exp(bigBeta, big.NewInt(3), bigP).Cmp(one) != 0 || bigBeta.Cmp(one) == 0 {
		t.Fatal("beta is not a non-trivial cube root of unity mod p")
	}
	if fromBytes(glvBeta.bytes()).Cmp(bigBeta) != 0 {
		t.Fatal("glvBeta constant")
	}
	// λ·G = (β·Gx, Gy).
	lg := refMul(bigLambda, refG)
	if lg.x.Cmp(new(big.Int).Mod(new(big.Int).Mul(bigBeta, refG.x), bigP)) != 0 || lg.y.Cmp(refG.y) != 0 {
		t.Fatal("lambda·G != (beta·x, y)")
	}
	// Lattice vectors: a + b·λ ≡ 0 (mod n).
	a1 := fromBytes(glvA1.bytes())
	b1 := new(big.Int).Neg(fromBytes(glvNegB1.bytes()))
	a2 := fromBytes(glvA2.bytes())
	b2 := new(big.Int).Sub(bigN, fromBytes(glvNegB2.bytes())) // -(-b2) mod n
	for _, v := range [][2]*big.Int{{a1, b1}, {a2, b2}} {
		s := new(big.Int).Add(v[0], new(big.Int).Mul(v[1], bigLambda))
		if s.Mod(s, bigN).Sign() != 0 {
			t.Fatal("lattice vector")
		}
	}
	if b2.Cmp(a1) != 0 {
		t.Fatal("b2 != a1")
	}
	// g1 = round(2^384·b2/n), g2 = round(2^384·(-b1)/n).
	half := new(big.Int).Rsh(bigN, 1)
	g1 := new(big.Int).Lsh(b2, 384)
	g1.Add(g1, half).Div(g1, bigN)
	g2 := new(big.Int).Lsh(new(big.Int).Neg(b1), 384)
	g2.Add(g2, half).Div(g2, bigN)
	if limbsToBig(glvG1).Cmp(g1) != 0 || limbsToBig(glvG2).Cmp(g2) != 0 {
		t.Fatal("g1/g2 constants")
	}
}

func TestSplitScalar(t *testing.T) {
	rng := rand.New(rand.NewSource(70))
	ks := interesting(rng, bigN, 3000)
	ks = append(ks, bigLambda, new(big.Int).Sub(bigN, bigLambda), new(big.Int).Lsh(big.NewInt(1), 128))
	bound := new(big.Int).Lsh(big.NewInt(1), 128)
	for _, k := range ks {
		s := scalarFromBig(k)
		k1, k2, n1, n2 := splitScalarVartime(&s)
		v1, v2 := limbsToBig(k1), limbsToBig(k2)
		if v1.Cmp(bound) >= 0 || v2.Cmp(bound) >= 0 {
			t.Fatalf("split of %x exceeds 2^128", k)
		}
		if n1 {
			v1.Neg(v1)
		}
		if n2 {
			v2.Neg(v2)
		}
		sum := new(big.Int).Add(v1, new(big.Int).Mul(v2, bigLambda))
		if sum.Mod(sum, bigN).Cmp(new(big.Int).Mod(k, bigN)) != 0 {
			t.Fatalf("split of %x does not recombine", k)
		}
	}
}

func jacFromPoint(p *point) jacobian {
	if p.isIdentity() == 1 {
		return jacobian{inf: true}
	}
	x, y, _ := p.affine()
	return jacobian{x: x, y: y, z: fieldOne}
}

// The Jacobian formulas agree with the complete projective formulas,
// including P + P, P + (-P), the identity and non-trivial Z.
func TestJacobianFormulas(t *testing.T) {
	rng := rand.New(rand.NewSource(71))
	rp := func() point {
		var b [32]byte
		rng.Read(b[:])
		var k scalar
		k.setBytesReduced(&b)
		var p point
		return *p.scalarBaseMult(&k)
	}
	for i := 0; i < 200; i++ {
		p, q := rp(), rp()
		var qn point
		qn.neg(&q)
		var ident point
		ident.setIdentity()
		// Give p a non-trivial Z by doubling then adding (Jacobian).
		jp := jacFromPoint(&p)
		var jp2 jacobian
		jacDouble(&jp2, &jp)
		var p2 point
		p2.double(&p)
		for _, c := range []struct{ a, b point }{{p, q}, {q, q}, {q, qn}, {ident, q}, {q, ident}, {p2, q}, {p2, p2}} {
			ja, jb := jacFromPoint(&c.a), jacFromPoint(&c.b)
			if c.a.equal(&p2) == 1 {
				ja = jp2 // Z != 1
			}
			if c.b.equal(&p2) == 1 {
				jb = jp2
			}
			var want point
			want.add(&c.a, &c.b)
			var jr jacobian
			jacAdd(&jr, &ja, &jb)
			var got point
			jacToProjective(&got, &jr)
			if got.equal(&want) != 1 {
				t.Fatalf("jacAdd case %d", i)
			}
			if c.b.isIdentity() == 0 {
				bx, by, _ := c.b.affine()
				jacAddAffine(&jr, &ja, &affinePoint{bx, by})
				jacToProjective(&got, &jr)
				if got.equal(&want) != 1 {
					t.Fatalf("jacAddAffine case %d", i)
				}
			}
			var dw point
			dw.double(&c.a)
			jacDouble(&jr, &ja)
			jacToProjective(&got, &jr)
			if got.equal(&dw) != 1 {
				t.Fatalf("jacDouble case %d", i)
			}
		}
	}
}

// The variable-time combination agrees with the constant-time scalar
// multiplications for random and adversarial inputs, including results
// equal to the identity and points with Z != 1.
func TestLinearCombinationAgainstConstantTime(t *testing.T) {
	rng := rand.New(rand.NewSource(72))
	ks := interesting(rng, bigN, 400)
	for i := 0; i+2 < len(ks); i += 3 {
		u1, u2, m := scalarFromBig(ks[i]), scalarFromBig(ks[i+1]), scalarFromBig(ks[i+2])
		var q point
		q.scalarBaseMult(&m) // projective, Z != 1 in general
		var got, a, b, want point
		linearCombinationVartime(&got, &u1, &u2, &q)
		a.scalarBaseMult(&u1)
		b.scalarMult(&u2, &q)
		want.add(&a, &b)
		if got.equal(&want) != 1 {
			t.Fatalf("u1·G + u2·Q mismatch at %d", i)
		}
		// Cancellation: u1 = -u2·m gives the identity.
		var c scalar
		c.mul(&u2, &m)
		c.neg(&c)
		linearCombinationVartime(&got, &c, &u2, &q)
		if got.isIdentity() != 1 {
			t.Fatalf("cancellation at %d", i)
		}
		// Identity q.
		var id point
		id.setIdentity()
		linearCombinationVartime(&got, &u1, &u2, &id)
		if got.equal(&a) != 1 {
			t.Fatalf("identity q at %d", i)
		}
		// q = ±G and q = λG (shared table entries with the G part).
		for _, qq := range []point{generator, *new(point).neg(&generator)} {
			linearCombinationVartime(&got, &u1, &u1, &qq)
			a.scalarBaseMult(&u1)
			b.scalarMult(&u1, &qq)
			want.add(&a, &b)
			if got.equal(&want) != 1 {
				t.Fatalf("q = ±G at %d", i)
			}
		}
	}
}

func TestWNAFWidthLimits(t *testing.T) {
	k := limbs{^uint64(0), ^uint64(0), ^uint64(0), 0x7fffffffffffffff}
	for w := uint(2); w <= 15; w++ {
		digits, _ := wnafVartime(&k, w)
		sum := new(big.Int)
		for i := len(digits) - 1; i >= 0; i-- {
			sum.Lsh(sum, 1).Add(sum, big.NewInt(int64(digits[i])))
		}
		if sum.Cmp(limbsToBig(k)) != 0 {
			t.Fatalf("width %d does not reconstruct", w)
		}
	}
	for _, w := range []uint{0, 1, 16, 17} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("width %d accepted", w)
				}
			}()
			wnafVartime(&k, w)
		}()
	}
}

// The effective-affine combination agrees with the generic one (general
// Jacobian additions for q) on random and adversarial inputs, and its
// co-Z table holds the odd multiples of q.
func TestLinearCombinationEffectiveAffine(t *testing.T) {
	rng := rand.New(rand.NewSource(73))
	ks := interesting(rng, bigN, 600)
	for i := 0; i+2 < len(ks); i += 3 {
		u1, u2, m := scalarFromBig(ks[i]), scalarFromBig(ks[i+1]), scalarFromBig(ks[i+2])
		var q point
		q.scalarBaseMult(&m)
		var got, want point
		linearCombinationVartime(&got, &u1, &u2, &q)
		linearCombinationVartimeGeneric(&want, &u1, &u2, &q)
		if got.equal(&want) != 1 {
			t.Fatalf("effective affine differs from generic at %d", i)
		}
		if q.isIdentity() == 1 {
			continue
		}
		x, y, _ := q.affine()
		var tbl [1 << (glvWindowQ - 2)]affinePoint
		var Z fieldElement
		if !coZOddMultiples(&tbl, &Z, &affinePoint{x: x, y: y}) {
			t.Fatalf("co-Z table failed at %d", i)
		}
		var mul point
		for j := range tbl {
			var k scalar
			k.setLimbsVartime(&limbs{uint64(2*j + 1)})
			mul.scalarMult(&k, &q)
			var z2, z3, ex, ey fieldElement
			z2.square(&Z)
			z3.mul(&z2, &Z)
			// Jacobian (X, Y, Z) is affine (X/Z^2, Y/Z^3).
			mx, my, _ := mul.affine()
			ex.mul(&mx, &z2)
			ey.mul(&my, &z3)
			if ex.equal(&tbl[j].x) != 1 || ey.equal(&tbl[j].y) != 1 {
				t.Fatalf("co-Z table entry %d wrong at %d", j, i)
			}
		}
	}
}

// addVartime and halfVartime against the constant-time arithmetic,
// including the values next to p where the reduction branch is taken.
func TestAddHalfVartime(t *testing.T) {
	rng := rand.New(rand.NewSource(74))
	pm := func(k uint64) fieldElement {
		return fieldElement{v: limbs{fieldP.m[0] - k, fieldP.m[1], fieldP.m[2], fieldP.m[3]}}
	}
	vals := []fieldElement{{}, fieldFromUint(1), fieldFromUint(2), pm(1), pm(2), pm(1 << 40)}
	for i := 0; i < 2000; i++ {
		var b [32]byte
		rng.Read(b[:])
		var f fieldElement
		f.setBytes(&b)
		vals = append(vals, f)
	}
	for i := range vals {
		for j := 0; j < len(vals); j += 97 {
			x, y := vals[i], vals[(i+j)%len(vals)]
			var a, b fieldElement
			addVartime(&a, &x, &y)
			b.add(&x, &y)
			if a.equal(&b) != 1 {
				t.Fatalf("addVartime(%x, %x)", x.v, y.v)
			}
		}
		var h, two fieldElement
		h.halfVartime(&vals[i])
		two.add(&h, &h)
		if two.equal(&vals[i]) != 1 {
			t.Fatalf("halfVartime(%x)", vals[i].v)
		}
	}
}

// TestFusedVartimeHelpers checks subTwiceVartime, subThriceVartime,
// subPairVartime and threeHalvesVartime against the operations they
// combine, on edge values (0, 1, 2, p-1, p-2, values next to word
// boundaries) and random ones.
func TestFusedVartimeHelpers(t *testing.T) {
	edges := []fieldElement{
		{}, fieldFromUint(1), fieldFromUint(2),
		{v: limbs{fieldP.m[0] - 1, fieldP.m[1], fieldP.m[2], fieldP.m[3]}},
		{v: limbs{fieldP.m[0] - 2, fieldP.m[1], fieldP.m[2], fieldP.m[3]}},
		{v: limbs{^uint64(0), 0, 0, 0}}, {v: limbs{0, 0, 0, 1 << 63}},
		{v: limbs{fieldC, 0, 0, 0}},
	}
	vals := append([]fieldElement{}, edges...)
	var b [32]byte
	for len(vals) < 3000 {
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatal(err)
		}
		var f fieldElement
		if f.setBytes(&b) == 1 {
			vals = append(vals, f)
		}
	}
	for i := range vals {
		x, y, w := vals[i], vals[(i*7+1)%len(vals)], vals[(i*13+2)%len(vals)]
		var got, want fieldElement
		subTwiceVartime(&got, &x, &y)
		want.sub(&x, &y)
		want.sub(&want, &y)
		if got != want {
			t.Fatalf("subTwiceVartime(%x, %x)", x.v, y.v)
		}
		subThriceVartime(&got, &x, &y, &w)
		want.sub(&x, &y)
		want.sub(&want, &w)
		want.sub(&want, &w)
		if got != want {
			t.Fatalf("subThriceVartime(%x, %x, %x)", x.v, y.v, w.v)
		}
		var h1, r1, h2, r2 fieldElement
		subPairVartime(&h1, &r1, &x, &y, &w, &x)
		h2.sub(&x, &y)
		r2.sub(&w, &x)
		if h1 != h2 || r1 != r2 {
			t.Fatalf("subPairVartime(%x, %x, %x)", x.v, y.v, w.v)
		}
		threeHalvesVartime(&got, &x)
		var h fieldElement
		h.halfVartime(&x)
		addVartime(&want, &x, &h)
		if got != want {
			t.Fatalf("threeHalvesVartime(%x)", x.v)
		}
		// Aliasing (z = x), as used by jacDouble and jacAddFinish.
		a := x
		subTwiceVartime(&a, &a, &y)
		c := x
		subThriceVartime(&c, &c, &y, &w)
		d := x
		threeHalvesVartime(&d, &d)
		var w2, w3 fieldElement
		subTwiceVartime(&w2, &x, &y)
		subThriceVartime(&w3, &x, &y, &w)
		if a != w2 || c != w3 || d != want {
			t.Fatalf("aliasing changes the result for %x", x.v)
		}
	}
}

// wnafReference is the straightforward bit-by-bit width-w NAF (one digit
// per iteration), kept as the reference for wnafVartime.
func wnafReference(k *limbs, w uint) (digits [257]int16, top int) {
	x := new(big.Int).Set(limbsToBig(*k))
	mod := new(big.Int).Lsh(big.NewInt(1), w)
	half := int64(1) << (w - 1)
	top = -1
	for i := 0; x.Sign() != 0; i++ {
		if x.Bit(0) == 1 {
			d := new(big.Int).Mod(x, mod).Int64()
			if d >= half {
				d -= int64(1) << w
			}
			digits[i] = int16(d)
			top = i
			x.Sub(x, big.NewInt(d))
		}
		x.Rsh(x, 1)
	}
	return digits, top
}

// TestWNAFMatchesReference compares wnafVartime (which skips runs of zero
// digits) with the bit-by-bit reference: every width, edge values, sparse
// values with long zero runs (including whole zero words) and random
// 129- and 256-bit values.
func TestWNAFMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	vals := []limbs{
		{}, {1}, {2}, {3}, {^uint64(0)}, {0, 1}, {0, 0, 1}, {0, 0, 0, 1},
		{0, 0, 0, 1 << 63}, {^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)},
		{1, 0, 0, 1 << 63}, {1 << 63, 0, 0, 0}, {0, 1 << 63, 0, 1},
		scalarN.m, {scalarN.m[0] - 1, scalarN.m[1], scalarN.m[2], scalarN.m[3]},
	}
	for i := 0; i < 256; i += 3 {
		var l limbs
		l[i/64] |= 1 << (i % 64)
		vals = append(vals, l)
		l[(255-i)/64] |= 1 << ((255 - i) % 64)
		vals = append(vals, l)
	}
	for len(vals) < 2000 {
		l := limbs{rng.Uint64(), rng.Uint64(), rng.Uint64(), rng.Uint64()}
		switch len(vals) % 3 {
		case 0:
			l[2] &= 1 // 129-bit, as after the GLV split
			l[3] = 0
		case 1:
			l[1] = 0 // a whole zero word
		}
		vals = append(vals, l)
	}
	for w := uint(2); w <= 15; w++ {
		for _, k := range vals {
			got, gtop := wnafVartime(&k, w)
			want, wtop := wnafReference(&k, w)
			if got != want || gtop != wtop {
				t.Fatalf("width %d, k = %x: digits or top differ (%d vs %d)", w, k, gtop, wtop)
			}
		}
	}
}
