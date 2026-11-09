// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package gethcompare

import (
	"math/rand"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	decredecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	sila "github.com/sila-network/sila-core-primitives/secp256k1"
)

// Head-to-head secp256k1 benchmarks. libsecp256k1 is C (cgo) with
// hand-tuned field arithmetic; decred is pure Go. SILA is pure Go with a
// constant-time design.

type secpFixture struct {
	priv   *sila.PrivateKey
	kb     [32]byte
	digest [32]byte
	sig    sila.Signature
	rec    [65]byte
	pub    sila.PublicKey
	pubU   [65]byte
}

func newSecpFixture() secpFixture {
	rng := rand.New(rand.NewSource(1))
	priv, _ := sila.GeneratePrivateKey(rng)
	var f secpFixture
	f.priv = priv
	f.kb, _ = priv.Bytes()
	rng.Read(f.digest[:])
	f.sig, _ = sila.Sign(priv, f.digest)
	f.rec, _ = f.sig.Recoverable()
	f.pub, _ = priv.PublicKey()
	f.pubU, _ = f.pub.Uncompressed()
	return f
}

func BenchmarkSecp256k1(b *testing.B) {
	f := newSecpFixture()
	gk, _ := gethcrypto.ToECDSA(f.kb[:])
	dk := secp256k1.PrivKeyFromBytes(f.kb[:])
	dpub := dk.PubKey()
	var dr, ds secp256k1.ModNScalar
	dr.SetByteSlice(f.rec[:32])
	ds.SetByteSlice(f.rec[32:64])
	dsig := decredecdsa.NewSignature(&dr, &ds)
	dcompact := decredecdsa.SignCompact(dk, f.digest[:], false)

	b.Run("op=sign/impl=sila", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			sila.Sign(f.priv, f.digest)
		}
	})
	b.Run("op=sign/impl=libsecp256k1", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			gethcrypto.Sign(f.digest[:], gk)
		}
	})
	b.Run("op=sign/impl=decred", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			decredecdsa.SignCompact(dk, f.digest[:], false)
		}
	})
	b.Run("op=verify/impl=sila", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			sila.Verify(f.pub, f.digest, f.sig)
		}
	})
	b.Run("op=verify/impl=libsecp256k1", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			gethcrypto.VerifySignature(f.pubU[:], f.digest[:], f.rec[:64])
		}
	})
	b.Run("op=verify/impl=decred", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			dsig.Verify(f.digest[:], dpub)
		}
	})
	b.Run("op=recover/impl=sila", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			sila.RecoverPublicKey(f.digest, f.sig)
		}
	})
	b.Run("op=recover/impl=libsecp256k1", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			gethcrypto.Ecrecover(f.digest[:], f.rec[:])
		}
	})
	b.Run("op=recover/impl=decred", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			decredecdsa.RecoverCompact(dcompact, f.digest[:])
		}
	})
	b.Run("op=pubkey/impl=sila", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			f.priv.PublicKey()
		}
	})
	b.Run("op=pubkey/impl=decred", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			secp256k1.PrivKeyFromBytes(f.kb[:]).PubKey()
		}
	})
}
