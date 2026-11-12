// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

import (
	"crypto/sha256"
	"math/rand"
	"testing"
)

func benchSetup(b *testing.B) (*PrivateKey, PublicKey, [32]byte, Signature) {
	priv, _ := GeneratePrivateKey(rand.New(rand.NewSource(1)))
	pub, _ := priv.PublicKey()
	d := sha256.Sum256([]byte("bench"))
	sig, _ := Sign(priv, d)
	return priv, pub, d, sig
}

func BenchmarkSign(b *testing.B) {
	priv, _, d, _ := benchSetup(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Sign(priv, d)
	}
}

func BenchmarkVerify(b *testing.B) {
	_, pub, d, sig := benchSetup(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Verify(pub, d, sig)
	}
}

func BenchmarkRecover(b *testing.B) {
	_, _, d, sig := benchSetup(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		RecoverPublicKey(d, sig)
	}
}

func BenchmarkPublicKey(b *testing.B) {
	priv, _, _, _ := benchSetup(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		priv.PublicKey()
	}
}

func BenchmarkFieldMul(b *testing.B) {
	x, y := generator.x, generator.y
	for i := 0; i < b.N; i++ {
		x.mul(&x, &y)
	}
}

func BenchmarkFieldSquare(b *testing.B) {
	x := generator.x
	for i := 0; i < b.N; i++ {
		x.square(&x)
	}
}

func BenchmarkFieldInv(b *testing.B) {
	x := generator.x
	for i := 0; i < b.N; i++ {
		x.inv(&x)
	}
}

func BenchmarkScalarInv(b *testing.B) {
	var k scalar
	k.setBytesReduced(ptr(sha256.Sum256([]byte("k"))))
	for i := 0; i < b.N; i++ {
		k.inv(&k)
	}
}

func BenchmarkScalarBaseMult(b *testing.B) {
	var k scalar
	k.setBytesReduced(ptr(sha256.Sum256([]byte("k"))))
	var r point
	for i := 0; i < b.N; i++ {
		r.scalarBaseMult(&k)
	}
}
