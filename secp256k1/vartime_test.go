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
