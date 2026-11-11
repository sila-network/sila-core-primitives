// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func bigToLimbs(x *big.Int) limbs {
	var b [32]byte
	x.FillBytes(b[:])
	return limbsFromBytes(&b)
}

// TestModInverseVartimeAgainstBig checks the variable-time inversion
// against math/big for both moduli: edge values and random values,
// including values with long runs of zero or one bits (which exercise the
// bulk even steps and long batches).
func TestModInverseVartimeAgainstBig(t *testing.T) {
	for _, mod := range []struct {
		name string
		m    limbs
		inv  uint64
	}{{"p", fieldP.m, fieldPInv62}, {"n", scalarN.m, scalarNInv62}} {
		M := limbsToBig(mod.m)
		vals := []*big.Int{
			big.NewInt(1), big.NewInt(2), big.NewInt(3),
			new(big.Int).Sub(M, big.NewInt(1)),
			new(big.Int).Sub(M, big.NewInt(2)),
			new(big.Int).Lsh(big.NewInt(1), 255),
			new(big.Int).Lsh(big.NewInt(1), 128),
			new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(1)),
			new(big.Int).Rsh(M, 1),
		}
		for i := 0; i < 64; i++ {
			// Sparse values: a single run of ones.
			v := new(big.Int).Lsh(big.NewInt(1), uint(i*4))
			v.Sub(v, big.NewInt(1))
			v.Lsh(v, uint(255-i*4))
			v.Mod(v, M)
			if v.Sign() != 0 {
				vals = append(vals, v)
			}
		}
		for i := 0; i < 20000; i++ {
			v, err := rand.Int(rand.Reader, M)
			if err != nil {
				t.Fatal(err)
			}
			if v.Sign() != 0 {
				vals = append(vals, v)
			}
		}
		for _, v := range vals {
			x := bigToLimbs(v)
			got := modInverseVartime(&x, &mod.m, mod.inv)
			want := new(big.Int).ModInverse(v, M)
			if limbsToBig(got).Cmp(want) != 0 {
				t.Fatalf("%s: inverse of %x: got %x want %x", mod.name, v, limbsToBig(got), want)
			}
		}
		zero := limbs{}
		if got := modInverseVartime(&zero, &mod.m, mod.inv); got != zero {
			t.Fatalf("%s: inverse of 0 must be 0", mod.name)
		}
	}
}

// TestInvVartimeMatchesConstantTime checks the field and scalar wrappers
// (including the Montgomery conversion for scalars) against the
// constant-time inversions.
func TestInvVartimeMatchesConstantTime(t *testing.T) {
	var b [32]byte
	for i := 0; i < 5000; i++ {
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatal(err)
		}
		var f, fi, fv fieldElement
		f.setBytes(&b)
		fi.inv(&f)
		fv.invVartime(&f)
		if fi.equal(&fv) != 1 {
			t.Fatalf("field: %x", b)
		}
		var s, si, sv scalar
		s.setBytesReduced(&b)
		si.inv(&s)
		sv.invVartime(&s)
		if si.equal(&sv) != 1 {
			t.Fatalf("scalar: %x", b)
		}
	}
	var zf, zfv fieldElement
	if zfv.invVartime(&zf).isZero() != 1 {
		t.Fatal("field inverse of 0")
	}
	var zs, zsv scalar
	if zsv.invVartime(&zs).isZero() != 1 {
		t.Fatal("scalar inverse of 0")
	}
}

func BenchmarkFieldInvVartime(b *testing.B) {
	x := mustField("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	for i := 0; i < b.N; i++ {
		x.invVartime(&x)
	}
}

func BenchmarkScalarInvVartime(b *testing.B) {
	x := mustScalar("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	for i := 0; i < b.N; i++ {
		x.invVartime(&x)
	}
}
