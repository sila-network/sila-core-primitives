// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

import (
	"math/big"
	"math/rand"
	"testing"
)

// refPoint is an affine reference implementation over math/big, written
// directly from the textbook chord-and-tangent rules. It is used only as a
// test oracle (variable time, public test data).
type refPoint struct {
	x, y *big.Int
	inf  bool
}

var refG = refPoint{
	x: mustBig("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
	y: mustBig("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
}

func refAdd(a, b refPoint) refPoint {
	if a.inf {
		return b
	}
	if b.inf {
		return a
	}
	var lam *big.Int
	if a.x.Cmp(b.x) == 0 {
		if new(big.Int).Mod(new(big.Int).Add(a.y, b.y), bigP).Sign() == 0 {
			return refPoint{inf: true}
		}
		num := new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(a.x, a.x))
		den := new(big.Int).ModInverse(new(big.Int).Mul(big.NewInt(2), a.y), bigP)
		lam = new(big.Int).Mul(num, den)
	} else {
		num := new(big.Int).Sub(b.y, a.y)
		den := new(big.Int).ModInverse(new(big.Int).Mod(new(big.Int).Sub(b.x, a.x), bigP), bigP)
		lam = new(big.Int).Mul(num, den)
	}
	lam.Mod(lam, bigP)
	x := new(big.Int).Sub(new(big.Int).Mul(lam, lam), new(big.Int).Add(a.x, b.x))
	x.Mod(x, bigP)
	y := new(big.Int).Sub(new(big.Int).Mul(lam, new(big.Int).Sub(a.x, x)), a.y)
	y.Mod(y, bigP)
	return refPoint{x: x, y: y}
}

func refMul(k *big.Int, p refPoint) refPoint {
	acc := refPoint{inf: true}
	for i := k.BitLen() - 1; i >= 0; i-- {
		acc = refAdd(acc, acc)
		if k.Bit(i) == 1 {
			acc = refAdd(acc, p)
		}
	}
	return acc
}

func toRef(p *point) refPoint {
	x, y, ok := p.affine()
	if ok == 0 {
		return refPoint{inf: true}
	}
	return refPoint{x: fromBytes(x.bytes()), y: fromBytes(y.bytes())}
}

func fromRef(r refPoint) point {
	var p point
	if r.inf {
		p.setIdentity()
		return p
	}
	var x, y fieldElement
	x.setBytes(to32(r.x))
	y.setBytes(to32(r.y))
	p.setAffine(&x, &y)
	return p
}

func refEqual(a, b refPoint) bool {
	if a.inf || b.inf {
		return a.inf == b.inf
	}
	return a.x.Cmp(b.x) == 0 && a.y.Cmp(b.y) == 0
}

func scalarFromBig(k *big.Int) scalar {
	var s scalar
	s.setBytesReduced(to32(new(big.Int).Mod(k, bigN)))
	return s
}

func TestGeneratorIsOnCurveAndHasOrderN(t *testing.T) {
	x, y, ok := generator.affine()
	if ok != 1 || isOnCurve(&x, &y) != 1 {
		t.Fatal("generator invalid")
	}
	// n·G = identity, (n-1)·G = -G, computed by the reference.
	if !refMul(bigN, refG).inf {
		t.Fatal("reference: n·G is not the identity")
	}
	var nm1 scalar
	nm1.setBytesCanonical(to32(new(big.Int).Sub(bigN, big.NewInt(1))))
	var r, negG point
	negG.neg(&generator)
	if r.scalarBaseMult(&nm1).equal(&negG) != 1 || r.scalarMult(&nm1, &generator).equal(&negG) != 1 {
		t.Fatal("(n-1)·G != -G")
	}
	var zero scalar
	if r.scalarBaseMult(&zero).isIdentity() != 1 || r.scalarMult(&zero, &generator).isIdentity() != 1 {
		t.Fatal("0·G != identity")
	}
}

func TestCompleteFormulasEdgeCases(t *testing.T) {
	var id, g2, sum, negG point
	id.setIdentity()
	if sum.add(&id, &id).isIdentity() != 1 || sum.double(&id).isIdentity() != 1 {
		t.Fatal("identity + identity")
	}
	if sum.add(&generator, &id).equal(&generator) != 1 || sum.add(&id, &generator).equal(&generator) != 1 {
		t.Fatal("G + identity")
	}
	negG.neg(&generator)
	if sum.add(&generator, &negG).isIdentity() != 1 {
		t.Fatal("G + (-G)")
	}
	g2.double(&generator)
	if sum.add(&generator, &generator).equal(&g2) != 1 {
		t.Fatal("G + G != 2G (add used as doubling)")
	}
	if !refEqual(toRef(&g2), refAdd(refG, refG)) {
		t.Fatal("2G vs reference")
	}
	// Projectively scaled inputs must give the same results.
	var scaled point
	lambda := fieldFromUint(123456789)
	scaled.x.mul(&generator.x, &lambda)
	scaled.y.mul(&generator.y, &lambda)
	scaled.z.mul(&generator.z, &lambda)
	if scaled.equal(&generator) != 1 || sum.add(&scaled, &generator).equal(&g2) != 1 {
		t.Fatal("scaled representation")
	}
}

func TestScalarMultAgainstReference(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	ks := interesting(rng, bigN, 40)
	// A second base point Q = 7·G (any multiple works as an independent base).
	refQ := refMul(big.NewInt(7), refG)
	q := fromRef(refQ)
	for _, k := range ks {
		s := scalarFromBig(k)
		var r point
		if !refEqual(toRef(r.scalarBaseMult(&s)), refMul(k, refG)) {
			t.Fatalf("scalarBaseMult(%x)", k)
		}
		if !refEqual(toRef(r.scalarMult(&s, &generator)), refMul(k, refG)) {
			t.Fatalf("scalarMult(%x, G)", k)
		}
		if !refEqual(toRef(r.scalarMult(&s, &q)), refMul(k, refQ)) {
			t.Fatalf("scalarMult(%x, Q)", k)
		}
	}
}

func TestRandomAdditionsAgainstReference(t *testing.T) {
	rng := rand.New(rand.NewSource(4))
	for i := 0; i < 50; i++ {
		var a, b [32]byte
		rng.Read(a[:])
		rng.Read(b[:])
		ka, kb := new(big.Int).SetBytes(a[:]), new(big.Int).SetBytes(b[:])
		ra, rb := refMul(ka, refG), refMul(kb, refG)
		pa, pb := fromRef(ra), fromRef(rb)
		var sum, dbl point
		if !refEqual(toRef(sum.add(&pa, &pb)), refAdd(ra, rb)) {
			t.Fatal("random add")
		}
		if !refEqual(toRef(dbl.double(&pa)), refAdd(ra, ra)) {
			t.Fatal("random double")
		}
	}
}

func TestWNAFAndVartimeCombination(t *testing.T) {
	rng := rand.New(rand.NewSource(14))
	ks := interesting(rng, bigN, 200)
	for _, k := range ks {
		kl := limbsFromBytes(to32(k))
		digits := wnaf5(&kl)
		// Reconstruct k = Σ d_i·2^i and check the NAF properties.
		sum := new(big.Int)
		last := -10
		for i := len(digits) - 1; i >= 0; i-- {
			sum.Lsh(sum, 1)
			sum.Add(sum, big.NewInt(int64(digits[i])))
		}
		for i, d := range digits {
			if d == 0 {
				continue
			}
			if d%2 == 0 || d > 15 || d < -15 || i-last < 5 {
				t.Fatalf("bad wNAF digit %d at %d for %x", d, i, k)
			}
			last = i
		}
		if sum.Cmp(k) != 0 {
			t.Fatalf("wNAF of %x reconstructs to %x", k, sum)
		}
	}
	refQ := refMul(big.NewInt(11), refG)
	q := fromRef(refQ)
	for i := 0; i+1 < len(ks); i += 2 {
		u1, u2 := scalarFromBig(ks[i]), scalarFromBig(ks[i+1])
		var got point
		linearCombinationVartime(&got, &u1, &u2, &q)
		want := refAdd(refMul(ks[i], refG), refMul(ks[i+1], refQ))
		if !refEqual(toRef(&got), want) {
			t.Fatalf("u1·G + u2·Q mismatch for %x, %x", ks[i], ks[i+1])
		}
	}
	// u1·G + u2·Q = identity when u2·Q = -u1·G.
	var u1, u2 scalar
	u1.setBytesCanonical(to32(big.NewInt(5)))
	u2.setBytesCanonical(to32(new(big.Int).Sub(bigN, big.NewInt(5))))
	var got point
	linearCombinationVartime(&got, &u1, &u2, &generator)
	if got.isIdentity() != 1 {
		t.Fatal("5G + (n-5)G != identity")
	}
}
