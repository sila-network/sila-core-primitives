// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

import (
	"math/big"
	mrand "math/rand"
	"testing"
)

// TestFieldMulNearReductionBoundary checks fieldMul and fieldSqr (assembly
// or Go, whichever this build uses) against math/big on products whose
// reduced value is small or close to p. Those are the inputs for which the
// last reduction steps (the carry folds and the final conditional
// subtraction of p) take their rare branches, which random inputs almost
// never reach.
func TestFieldMulNearReductionBoundary(t *testing.T) {
	P := limbsToBig(fieldP.m)
	rng := mrand.New(mrand.NewSource(256))
	check := func(x, y *big.Int) {
		xl, yl := bigToLimbs(x), bigToLimbs(y)
		want := new(big.Int).Mul(x, y)
		want.Mod(want, P)
		var z limbs
		fieldMul(&z, &xl, &yl)
		if limbsToBig(z).Cmp(want) != 0 {
			t.Fatalf("fieldMul(%x, %x) = %x, want %x", x, y, limbsToBig(z), want)
		}
		if x.Cmp(y) == 0 {
			fieldSqr(&z, &xl)
			if limbsToBig(z).Cmp(want) != 0 {
				t.Fatalf("fieldSqr(%x) = %x, want %x", x, limbsToBig(z), want)
			}
		}
	}
	var targets []*big.Int
	for _, k := range []int64{0, 1, 2, 3, 0x3D1, 0x1000003D0, 0x1000003D1, 0x1000003D2} {
		targets = append(targets, big.NewInt(k), new(big.Int).Sub(P, big.NewInt(k+1)))
	}
	for i := 0; i < 200; i++ {
		k := new(big.Int).Rand(rng, new(big.Int).Lsh(big.NewInt(1), uint(rng.Intn(80))))
		targets = append(targets, k, new(big.Int).Sub(P, new(big.Int).Add(k, big.NewInt(1))))
	}
	for _, k := range targets {
		for j := 0; j < 20; j++ {
			// x·y ≡ k with x random, y = k·x^-1.
			x := new(big.Int).Rand(rng, P)
			if x.Sign() == 0 {
				continue
			}
			y := new(big.Int).ModInverse(x, P)
			y.Mul(y, k).Mod(y, P)
			check(x, y)
		}
	}
	// Squares of p - s (a full-size product with a small square s^2).
	for i := 0; i < 5000; i++ {
		s := new(big.Int).Rand(rng, new(big.Int).Lsh(big.NewInt(1), uint(rng.Intn(129))))
		x := new(big.Int).Sub(P, s)
		if x.Cmp(P) < 0 && x.Sign() > 0 {
			check(x, x)
		}
	}
}
