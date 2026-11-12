// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

//go:build arm64 && !purego

package secp256k1

import (
	"crypto/rand"
	"testing"
)

// TestArm64AsmMatchesGo checks the arm64 field and scalar assembly against
// the portable Go arithmetic (mulWords/sqrWords + reduceWords and
// montReduceN, checked against math/big elsewhere): edge values next to p
// and n and to the word boundaries, random values, and aliasing of the
// output with the inputs.
func TestArm64AsmMatchesGo(t *testing.T) {
	type mod struct {
		name   string
		m      limbs
		mul    func(z, x, y *limbs)
		sqr    func(z, x *limbs)
		refMul func(x, y *limbs) limbs
	}
	n := scalarN.m
	mods := []mod{
		{"field", fieldP.m, fieldMul, fieldSqr, func(x, y *limbs) limbs {
			var z limbs
			t0, t1, t2, t3, t4, t5, t6, t7 := mulWords(x, y)
			reduceWords(&z, t0, t1, t2, t3, t4, t5, t6, t7)
			return z
		}},
		{"scalar", n,
			func(z, x, y *limbs) { scalarMul(z, x, y, &n) },
			func(z, x *limbs) { scalarSqr(z, x, &n) },
			func(x, y *limbs) limbs {
				var z limbs
				t0, t1, t2, t3, t4, t5, t6, t7 := mulWords(x, y)
				montReduceN(&z, t0, t1, t2, t3, t4, t5, t6, t7)
				return z
			}},
	}
	for _, md := range mods {
		m := md.m
		vals := []limbs{
			{}, {1}, {2}, {m[0] - 1, m[1], m[2], m[3]}, {m[0] - 2, m[1], m[2], m[3]},
			{^uint64(0), 0, 0, 0}, {0, ^uint64(0), 0, 0}, {0, 0, 0, 1 << 63},
			{^uint64(0), ^uint64(0), ^uint64(0), 0}, {0x1000003D1, 0, 0, 0},
		}
		var b [32]byte
		for len(vals) < 20000 {
			if _, err := rand.Read(b[:]); err != nil {
				t.Fatal(err)
			}
			x := limbsFromBytes(&b)
			if lessThan(&x, &m) == 1 {
				vals = append(vals, x)
			}
		}
		for i := range vals {
			x := vals[i]
			y := vals[(i*7919+1)%len(vals)]
			want := md.refMul(&x, &y)
			wantSq := md.refMul(&x, &x)
			var z limbs
			md.mul(&z, &x, &y)
			if z != want {
				t.Fatalf("%s mul(%x, %x) = %x, want %x", md.name, x, y, z, want)
			}
			md.sqr(&z, &x)
			if z != wantSq {
				t.Fatalf("%s sqr(%x) = %x, want %x", md.name, x, z, wantSq)
			}
			a, c, d, e := x, y, x, x
			md.mul(&a, &a, &y)
			md.mul(&c, &x, &c)
			md.sqr(&d, &d)
			md.mul(&e, &e, &e)
			if a != want || c != want || d != wantSq || e != wantSq {
				t.Fatalf("%s: aliasing changes the result for %x, %x", md.name, x, y)
			}
		}
	}
}

// TestLookupAffineNEONMatchesGo checks the NEON table scan against a plain
// indexed read for every index of every base table, including the mag = 0
// convention (entry 1).
func TestLookupAffineNEONMatchesGo(t *testing.T) {
	for w := 0; w < baseWindows; w++ {
		for mag := uint64(0); mag <= baseEntries; mag++ {
			var got affinePoint
			got.lookupAffine(&baseTable[w], mag)
			want := baseTable[w][0]
			if mag > 0 {
				want = baseTable[w][mag-1]
			}
			if got != want {
				t.Fatalf("window %d, magnitude %d", w, mag)
			}
		}
	}
}
