// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

import (
	"math/big"
	"math/rand"
	"testing"
)

// The unrolled Montgomery reduction for n agrees with the generic CIOS
// product, and the chain inversion with math/big, on edge and random
// values.
func TestScalarFastPaths(t *testing.T) {
	if scalarNInv != scalarN.m0inv || scalarN0 != scalarN.m[0] || scalarN1 != scalarN.m[1] ||
		scalarN2 != scalarN.m[2] || scalarN3 != scalarN.m[3] {
		t.Fatal("constants differ from the derived modulus")
	}
	rng := rand.New(rand.NewSource(50))
	vals := []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(2), new(big.Int).Sub(bigN, big.NewInt(1)),
		new(big.Int).Sub(bigN, big.NewInt(2)), new(big.Int).Rsh(bigN, 1), new(big.Int).Lsh(big.NewInt(1), 255)}
	for i := 0; i < 2000; i++ {
		var b [32]byte
		rng.Read(b[:])
		vals = append(vals, new(big.Int).Mod(new(big.Int).SetBytes(b[:]), bigN))
	}
	toS := func(v *big.Int) scalar {
		var s scalar
		if s.setBytesCanonical(to32(v)) != 1 {
			t.Fatal("non-canonical test value")
		}
		return s
	}
	for i, a := range vals {
		b := vals[(i*7+3)%len(vals)]
		sa, sb := toS(a), toS(b)
		var got, want scalar
		got.mul(&sa, &sb)
		scalarN.mul(&want.v, &sa.v, &sb.v)
		if got != want {
			t.Fatalf("mul mismatch for %x * %x", a, b)
		}
		got.square(&sa)
		scalarN.mul(&want.v, &sa.v, &sa.v)
		if got != want {
			t.Fatalf("square mismatch for %x", a)
		}
		if i%10 == 0 {
			got.inv(&sa)
			exp := new(big.Int).ModInverse(a, bigN)
			if exp == nil {
				exp = new(big.Int)
			}
			gb := got.bytes()
			if new(big.Int).SetBytes(gb[:]).Cmp(exp) != 0 {
				t.Fatalf("inverse mismatch for %x", a)
			}
		}
	}
}
