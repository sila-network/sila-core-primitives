// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

//go:build arm64 && !purego

package secp256k1

import (
	"math/rand"
	"testing"
)

// TestJacDoubleArm64MatchesGo compares the inlined arm64 doubling with the
// Go formula on random points with random Jacobian Z, on coordinates next
// to p and 0, and with the output aliasing the input; it also checks the
// result against the constant-time projective doubling.
func TestJacDoubleArm64MatchesGo(t *testing.T) {
	rng := rand.New(rand.NewSource(77))
	pm := func(k uint64) fieldElement {
		return fieldElement{v: limbs{fieldP.m[0] - k, fieldP.m[1], fieldP.m[2], fieldP.m[3]}}
	}
	for i := 0; i < 3000; i++ {
		var k scalar
		var b [32]byte
		rng.Read(b[:])
		k.setBytesReduced(&b)
		var pp point
		pp.scalarBaseMult(&k)
		x, y, _ := pp.affine()
		// Random Jacobian representative (X·z^2, Y·z^3, z).
		var z fieldElement
		rng.Read(b[:])
		z.setBytes(&b)
		switch i % 5 {
		case 1:
			z = pm(1)
		case 2:
			z = fieldFromUint(1)
		}
		if z.isZero() == 1 {
			z = fieldFromUint(2)
		}
		var z2, z3 fieldElement
		z2.square(&z)
		z3.mul(&z2, &z)
		j := jacobian{z: z}
		j.x.mul(&x, &z2)
		j.y.mul(&y, &z3)
		var want, got jacobian
		jacDoubleGo(&want, &j)
		jacDouble(&got, &j)
		if got != want {
			t.Fatalf("doubling differs at %d", i)
		}
		alias := j
		jacDouble(&alias, &alias)
		if alias != want {
			t.Fatalf("aliased doubling differs at %d", i)
		}
		// Against the constant-time projective doubling.
		var d, conv point
		d.double(&pp)
		jacToProjective(&conv, &got)
		if conv.equal(&d) != 1 {
			t.Fatalf("doubling is not 2P at %d", i)
		}
	}
	var inf, out jacobian
	inf.inf = true
	jacDouble(&out, &inf)
	if !out.inf {
		t.Fatal("2·O must be O")
	}
}
