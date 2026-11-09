// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

import (
	"math/big"
	"math/rand"
	"testing"
)

// Tests in this file compare the constant-time limb arithmetic with
// math/big, which is used here only as an independent oracle on random,
// non-secret test values.

var (
	bigP = mustBig("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
	bigN = mustBig("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
)

func mustBig(h string) *big.Int {
	v, ok := new(big.Int).SetString(h, 16)
	if !ok {
		panic(h)
	}
	return v
}

func to32(v *big.Int) *[32]byte {
	var b [32]byte
	v.FillBytes(b[:])
	return &b
}

func fromBytes(b [32]byte) *big.Int { return new(big.Int).SetBytes(b[:]) }

// interesting returns edge values below m plus random values.
func interesting(rng *rand.Rand, m *big.Int, n int) []*big.Int {
	out := []*big.Int{
		big.NewInt(0), big.NewInt(1), big.NewInt(2), big.NewInt(3),
		new(big.Int).Sub(m, big.NewInt(1)), new(big.Int).Sub(m, big.NewInt(2)),
		new(big.Int).Rsh(m, 1), new(big.Int).Add(new(big.Int).Rsh(m, 1), big.NewInt(1)),
		new(big.Int).Lsh(big.NewInt(1), 255), new(big.Int).Lsh(big.NewInt(1), 128),
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1)),
	}
	for i := 0; i < n; i++ {
		var b [32]byte
		rng.Read(b[:])
		out = append(out, new(big.Int).Mod(new(big.Int).SetBytes(b[:]), m))
	}
	return out
}

func TestModulusConstants(t *testing.T) {
	for _, c := range []struct {
		md *modulus
		m  *big.Int
	}{{fieldP, bigP}, {scalarN, bigN}} {
		R := new(big.Int).Lsh(big.NewInt(1), 256)
		var b [32]byte
		limbsToBytes(&b, &c.md.one)
		if fromBytes(b).Cmp(new(big.Int).Mod(R, c.m)) != 0 {
			t.Fatal("R mod m wrong")
		}
		limbsToBytes(&b, &c.md.r2)
		if fromBytes(b).Cmp(new(big.Int).Mod(new(big.Int).Mul(R, R), c.m)) != 0 {
			t.Fatal("R^2 mod m wrong")
		}
		if c.md.m0inv*c.md.m[0] != ^uint64(0) {
			t.Fatal("m0inv wrong")
		}
	}
	if fromBytes(fieldInvExp).Cmp(new(big.Int).Sub(bigP, big.NewInt(2))) != 0 {
		t.Fatal("p-2 wrong")
	}
	sq := new(big.Int).Add(bigP, big.NewInt(1))
	if fromBytes(fieldSqrtExp).Cmp(sq.Rsh(sq, 2)) != 0 {
		t.Fatal("(p+1)/4 wrong")
	}
	if fromBytes(scalarInvExp).Cmp(new(big.Int).Sub(bigN, big.NewInt(2))) != 0 {
		t.Fatal("n-2 wrong")
	}
	var hb [32]byte
	limbsToBytes(&hb, &halfN)
	if fromBytes(hb).Cmp(new(big.Int).Rsh(bigN, 1)) != 0 {
		t.Fatal("(n-1)/2 wrong")
	}
}

func TestFieldArithmeticAgainstBig(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	vals := interesting(rng, bigP, 60)
	for _, a := range vals {
		var fa fieldElement
		if fa.setBytes(to32(a)) != 1 {
			t.Fatal("canonical value rejected")
		}
		if fromBytes(fa.bytes()).Cmp(a) != 0 {
			t.Fatal("roundtrip")
		}
		if fa.isOdd() != uint64(a.Bit(0)) {
			t.Fatal("parity")
		}
		for _, b := range vals[:30] {
			var fb, r fieldElement
			fb.setBytes(to32(b))
			check := func(name string, got *fieldElement, want *big.Int) {
				t.Helper()
				want = new(big.Int).Mod(want, bigP)
				if fromBytes(got.bytes()).Cmp(want) != 0 {
					t.Fatalf("%s(%x, %x) = %x, want %x", name, a, b, got.bytes(), want)
				}
			}
			check("add", r.add(&fa, &fb), new(big.Int).Add(a, b))
			check("sub", r.sub(&fa, &fb), new(big.Int).Sub(a, b))
			check("mul", r.mul(&fa, &fb), new(big.Int).Mul(a, b))
			if (fa.equal(&fb) == 1) != (a.Cmp(b) == 0) {
				t.Fatal("equal")
			}
		}
		var r fieldElement
		if fromBytes(r.neg(&fa).bytes()).Cmp(new(big.Int).Mod(new(big.Int).Neg(a), bigP)) != 0 {
			t.Fatal("neg")
		}
		if fromBytes(r.square(&fa).bytes()).Cmp(new(big.Int).Mod(new(big.Int).Mul(a, a), bigP)) != 0 {
			t.Fatal("square")
		}
		wantInv := new(big.Int).ModInverse(a, bigP)
		if wantInv == nil {
			wantInv = big.NewInt(0)
		}
		if fromBytes(r.inv(&fa).bytes()).Cmp(wantInv) != 0 {
			t.Fatal("inv")
		}
		isQR := big.Jacobi(a, bigP) >= 0
		var s fieldElement
		ok := s.sqrt(&fa)
		if (ok == 1) != isQR {
			t.Fatalf("sqrt residuosity of %x", a)
		}
		if ok == 1 {
			var sq fieldElement
			if sq.square(&s).equal(&fa) != 1 {
				t.Fatal("sqrt value")
			}
		}
	}
	// Non-canonical encodings are rejected.
	for _, v := range []*big.Int{bigP, new(big.Int).Add(bigP, big.NewInt(1)), new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))} {
		var f fieldElement
		if f.setBytes(to32(v)) != 0 || f.isZero() != 1 {
			t.Fatalf("non-canonical %x accepted", v)
		}
	}
}

func TestScalarArithmeticAgainstBig(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	vals := interesting(rng, bigN, 60)
	for _, a := range vals {
		var sa scalar
		if sa.setBytesCanonical(to32(a)) != 1 || fromBytes(sa.bytes()).Cmp(a) != 0 {
			t.Fatal("canonical scalar")
		}
		if (sa.isHigh() == 1) != (a.Cmp(new(big.Int).Rsh(bigN, 1)) > 0) {
			t.Fatalf("isHigh(%x)", a)
		}
		for _, b := range vals[:30] {
			var sb, r scalar
			sb.setBytesCanonical(to32(b))
			chk := func(name string, got *scalar, want *big.Int) {
				t.Helper()
				want = new(big.Int).Mod(want, bigN)
				if fromBytes(got.bytes()).Cmp(want) != 0 {
					t.Fatalf("%s mismatch", name)
				}
			}
			chk("add", r.add(&sa, &sb), new(big.Int).Add(a, b))
			chk("sub", r.sub(&sa, &sb), new(big.Int).Sub(a, b))
			chk("mul", r.mul(&sa, &sb), new(big.Int).Mul(a, b))
		}
		var r scalar
		wantInv := new(big.Int).ModInverse(a, bigN)
		if wantInv == nil {
			wantInv = big.NewInt(0)
		}
		if fromBytes(r.inv(&sa).bytes()).Cmp(wantInv) != 0 {
			t.Fatal("scalar inv")
		}
		if fromBytes(r.neg(&sa).bytes()).Cmp(new(big.Int).Mod(new(big.Int).Neg(a), bigN)) != 0 {
			t.Fatal("scalar neg")
		}
	}
	// Reduction of arbitrary 256-bit digests, including values >= n.
	for _, v := range []*big.Int{bigN, new(big.Int).Add(bigN, big.NewInt(5)), new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))} {
		var s scalar
		if s.setBytesCanonical(to32(v)) != 0 {
			t.Fatal("non-canonical scalar accepted")
		}
		s.setBytesReduced(to32(v))
		if fromBytes(s.bytes()).Cmp(new(big.Int).Mod(v, bigN)) != 0 {
			t.Fatal("reduced digest")
		}
	}
}
