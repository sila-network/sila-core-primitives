// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

import (
	"crypto/rand"
	"math/big"
	mrand "math/rand"
	"testing"
)

// TestModInverseCTAgainstBig checks the constant-time divstep inversion
// against math/big for both moduli: edge values, sparse and dense bit
// patterns (many even steps or long runs of swaps), and random values.
func TestModInverseCTAgainstBig(t *testing.T) {
	rng := mrand.New(mrand.NewSource(75))
	for _, mod := range []struct {
		name string
		m    limbs
		inv  uint64
	}{{"p", fieldP.m, fieldPInv62}, {"n", scalarN.m, scalarNInv62}} {
		M := limbsToBig(mod.m)
		vals := []*big.Int{
			big.NewInt(1), big.NewInt(2), big.NewInt(3),
			new(big.Int).Sub(M, big.NewInt(1)), new(big.Int).Sub(M, big.NewInt(2)),
			new(big.Int).Rsh(M, 1), new(big.Int).Add(new(big.Int).Rsh(M, 1), big.NewInt(1)),
		}
		for i := 0; i < 256; i++ {
			vals = append(vals, new(big.Int).Lsh(big.NewInt(1), uint(i)))
			ones := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(i+1)), big.NewInt(1))
			vals = append(vals, ones)
			// Values close to fractions of m (long quotient runs).
			vals = append(vals, new(big.Int).Div(M, big.NewInt(int64(i+2))))
		}
		for i := 0; i < 20000; i++ {
			v, err := rand.Int(rand.Reader, M)
			if err != nil {
				t.Fatal(err)
			}
			vals = append(vals, v)
			// Low Hamming weight values.
			w := new(big.Int)
			for j := 0; j < 1+rng.Intn(6); j++ {
				w.SetBit(w, rng.Intn(256), 1)
			}
			vals = append(vals, w)
		}
		for _, v := range vals {
			v = new(big.Int).Mod(v, M)
			x := bigToLimbs(v)
			got := modInverseCT(&x, &mod.m, mod.inv)
			want := new(big.Int)
			if v.Sign() != 0 {
				want.ModInverse(v, M)
			}
			if limbsToBig(got).Cmp(want) != 0 {
				t.Fatalf("%s: inverse of %x: got %x want %x", mod.name, v, limbsToBig(got), want)
			}
		}
	}
}

// TestScalarInvMatchesFermat checks the scalar wrapper (Montgomery
// conversion) against the Fermat inversion it replaced.
func TestScalarInvMatchesFermat(t *testing.T) {
	var b [32]byte
	for i := 0; i < 5000; i++ {
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatal(err)
		}
		var s, a, f scalar
		s.setBytesReduced(&b)
		a.inv(&s)
		f.invFermat(&s)
		if a.equal(&f) != 1 {
			t.Fatalf("scalar inverse of %x", b)
		}
	}
	var z, zi scalar
	if zi.inv(&z).isZero() != 1 {
		t.Fatal("inverse of 0 must be 0")
	}
}

// TestDivstepsBound runs the divstep recurrence on full-size integers
// (math/big) for many inputs and checks that g reaches 0 within the 744
// steps the constant-time inversion runs (the proven bound is 741).
func TestDivstepsBound(t *testing.T) {
	rng := mrand.New(mrand.NewSource(76))
	M := limbsToBig(scalarN.m)
	P := limbsToBig(fieldP.m)
	max := 0
	for i := 0; i < 3000; i++ {
		m := M
		if i%2 == 1 {
			m = P
		}
		g := new(big.Int).Rand(rng, m)
		f := new(big.Int).Set(m)
		delta := 1
		steps := 0
		for g.Sign() != 0 {
			if delta > 0 && g.Bit(0) == 1 {
				delta, f, g = 1-delta, g, new(big.Int).Rsh(new(big.Int).Sub(g, f), 1)
			} else if g.Bit(0) == 1 {
				delta, g = 1+delta, new(big.Int).Rsh(new(big.Int).Add(g, f), 1)
			} else {
				delta, g = 1+delta, new(big.Int).Rsh(g, 1)
			}
			steps++
		}
		if steps > max {
			max = steps
		}
	}
	if max > 741 {
		t.Fatalf("divsteps needed %d > 741", max)
	}
	t.Logf("maximum divsteps over the sample: %d (bound 741, run 744)", max)
}
