// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

//go:build amd64 && !purego

package secp256k1

import (
	"crypto/rand"
	"testing"
)

// TestFieldAsmMatchesGo checks both assembly implementations (MULX/ADX,
// when the CPU has it, and the portable MULQ code) against the portable Go
// arithmetic (mulWords/sqrWords + reduceWords, itself checked against
// math/big in arith_test.go): random values, values next to p and to the
// word boundaries, and aliasing of the output with the inputs.
func TestFieldAsmMatchesGo(t *testing.T) {
	t.Logf("useADX = %v", useADX)
	pm1 := limbs{fieldP.m[0] - 1, fieldP.m[1], fieldP.m[2], fieldP.m[3]}
	edges := []limbs{
		{}, {1}, {2}, pm1,
		{fieldP.m[0] - 2, fieldP.m[1], fieldP.m[2], fieldP.m[3]},
		{^uint64(0), 0, 0, 0},
		{0, ^uint64(0), 0, 0},
		{0, 0, 0, 1 << 63},
		{^uint64(0), ^uint64(0), ^uint64(0), 0},
		{0xFFFFFFFEFFFFFC2E, 0, 0, 0}, // p0 - 1 in the low word
		{0x1000003D1, 0, 0, 0},
	}
	vals := append([]limbs{}, edges...)
	var b [32]byte
	for len(vals) < 20000 {
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatal(err)
		}
		var f fieldElement
		if f.setBytes(&b) == 1 {
			vals = append(vals, f.v)
		}
	}
	goMul := func(x, y *limbs) limbs {
		var z limbs
		t0, t1, t2, t3, t4, t5, t6, t7 := mulWords(x, y)
		reduceWords(&z, t0, t1, t2, t3, t4, t5, t6, t7)
		return z
	}
	type impl struct {
		name string
		mul  func(z, x, y *limbs)
		sqr  func(z, x *limbs)
	}
	impls := []impl{{"MULQ", fieldMulMULQ, fieldSqrMULQ}, {"dispatch", fieldMul, fieldSqr}}
	if useADX {
		impls = append(impls, impl{"ADX", fieldMulADX, fieldSqrADX})
	}
	for _, im := range impls {
		for i := range vals {
			x := vals[i]
			y := vals[(i*7919+1)%len(vals)]
			want := goMul(&x, &y)
			var z limbs
			im.mul(&z, &x, &y)
			if z != want {
				t.Fatalf("%s mul(%x, %x) = %x, want %x", im.name, x, y, z, want)
			}
			wantSq := goMul(&x, &x)
			im.sqr(&z, &x)
			if z != wantSq {
				t.Fatalf("%s sqr(%x) = %x, want %x", im.name, x, z, wantSq)
			}
			// Aliasing: z = x, z = y, z = x = y.
			a := x
			im.mul(&a, &a, &y)
			c := y
			im.mul(&c, &x, &c)
			d := x
			im.sqr(&d, &d)
			e := x
			im.mul(&e, &e, &e)
			if a != want || c != want || d != wantSq || e != wantSq {
				t.Fatalf("%s: aliasing changes the result for %x, %x", im.name, x, y)
			}
		}
	}
}

// TestScalarAsmMatchesGo checks the scalar Montgomery assembly (MULX/ADX
// when available, and MULQ) against the portable Go code (mulWords /
// sqrWords + montReduceN): edge values next to n and to word boundaries,
// random values, and aliasing.
func TestScalarAsmMatchesGo(t *testing.T) {
	n := scalarN.m
	nm1 := limbs{n[0] - 1, n[1], n[2], n[3]}
	vals := []limbs{
		{}, {1}, {2}, nm1, {n[0] - 2, n[1], n[2], n[3]},
		{^uint64(0), 0, 0, 0}, {0, ^uint64(0), 0, 0},
		{^uint64(0), ^uint64(0), ^uint64(0), 0},
		{0, 0, 0, 1 << 63}, scalarN.one, scalarN.r2,
	}
	var b [32]byte
	for len(vals) < 20000 {
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatal(err)
		}
		var s scalar
		if s.setBytesCanonical(&b) == 1 {
			vals = append(vals, s.v)
		}
	}
	goMul := func(x, y *limbs) limbs {
		var z limbs
		t0, t1, t2, t3, t4, t5, t6, t7 := mulWords(x, y)
		montReduceN(&z, t0, t1, t2, t3, t4, t5, t6, t7)
		return z
	}
	type impl struct {
		name string
		mul  func(z, x, y, n *limbs)
		sqr  func(z, x, n *limbs)
	}
	impls := []impl{{"MULQ", scalarMulMULQ, scalarSqrMULQ}, {"dispatch", scalarMul, scalarSqr}}
	if useADX {
		impls = append(impls, impl{"ADX", scalarMulADX, scalarSqrADX})
	}
	for _, im := range impls {
		for i := range vals {
			x := vals[i]
			y := vals[(i*7919+3)%len(vals)]
			want := goMul(&x, &y)
			wantSq := goMul(&x, &x)
			var z limbs
			im.mul(&z, &x, &y, &n)
			if z != want {
				t.Fatalf("%s mul(%x, %x) = %x, want %x", im.name, x, y, z, want)
			}
			im.sqr(&z, &x, &n)
			if z != wantSq {
				t.Fatalf("%s sqr(%x) = %x, want %x", im.name, x, z, wantSq)
			}
			a, c, d := x, y, x
			im.mul(&a, &a, &y, &n)
			im.mul(&c, &x, &c, &n)
			im.sqr(&d, &d, &n)
			if a != want || c != want || d != wantSq {
				t.Fatalf("%s: aliasing changes the result for %x, %x", im.name, x, y)
			}
		}
	}
}
