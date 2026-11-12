// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package gethcompare

// Differential tests of SILA secp256k1 against two independent external
// implementations, used here only as test oracles:
//
//   - libsecp256k1 (C), through go-ethereum v1.17.10 crypto (cgo build);
//   - decred dcrd secp256k1/v4 v4.0.1 (pure Go).
//
// Both produce deterministic RFC 6979 low-S signatures. The SILA signature
// (r, s, v) must be byte-identical to libsecp256k1 for every digest, and to
// decred for digests below n (see TestSecp256k1DigestAboveOrder).

import (
	"bytes"
	"math/big"
	"math/rand"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	decredecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	sila "github.com/sila-network/sila-core-primitives/secp256k1"
)

var orderN, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

func randomKeyAndDigest(t *testing.T, rng *rand.Rand) (*sila.PrivateKey, [32]byte, [32]byte) {
	t.Helper()
	priv, err := sila.GeneratePrivateKey(rng)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := priv.Bytes()
	var d [32]byte
	rng.Read(d[:])
	return priv, kb, d
}

func TestSecp256k1SignaturesMatchLibsecp256k1AndDecred(t *testing.T) {
	rng := rand.New(rand.NewSource(20261109))
	for i := 0; i < 1000; i++ {
		priv, kb, d := randomKeyAndDigest(t, rng)
		sig, err := sila.Sign(priv, d)
		if err != nil {
			t.Fatal(err)
		}
		silaRec, _ := sig.Recoverable()

		// libsecp256k1: 65 bytes r || s || recid.
		gk, err := gethcrypto.ToECDSA(kb[:])
		if err != nil {
			t.Fatal(err)
		}
		libSig, err := gethcrypto.Sign(d[:], gk)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(libSig, silaRec[:]) {
			t.Fatalf("case %d: SILA %x != libsecp256k1 %x", i, silaRec, libSig)
		}

		// decred: header (27 + recid [+4 if compressed]) || r || s; equal for
		// digests < n (practically all random digests).
		dk := secp256k1.PrivKeyFromBytes(kb[:])
		dc := decredecdsa.SignCompact(dk, d[:], false)
		dv := dc[0] - 27
		if new(big.Int).SetBytes(d[:]).Cmp(orderN) < 0 && (!bytes.Equal(dc[1:], silaRec[:64]) || dv != silaRec[64]) {
			t.Fatalf("case %d: SILA %x != decred %x", i, silaRec, dc)
		}

		// Public keys agree.
		pub, _ := priv.PublicKey()
		pu, _ := pub.Uncompressed()
		if !bytes.Equal(gethcrypto.FromECDSAPub(&gk.PublicKey), pu[:]) || !bytes.Equal(dk.PubKey().SerializeUncompressed(), pu[:]) {
			t.Fatalf("case %d: public key mismatch", i)
		}

		// Cross verification and recovery in both directions.
		if !gethcrypto.VerifySignature(pu[:], d[:], silaRec[:64]) {
			t.Fatal("libsecp256k1 rejects SILA signature")
		}
		rec, err := gethcrypto.Ecrecover(d[:], silaRec[:])
		if err != nil || !bytes.Equal(rec, pu[:]) {
			t.Fatal("libsecp256k1 recovery of SILA signature")
		}
		dpub, _, err := decredecdsa.RecoverCompact(dc, d[:])
		if err != nil || !bytes.Equal(dpub.SerializeUncompressed(), pu[:]) {
			t.Fatal("decred recovery")
		}
		ls, err := sila.ParseRecoverableSignature(libSig)
		if err != nil || !sila.Verify(pub, d, ls) {
			t.Fatal("SILA rejects libsecp256k1 signature")
		}
		sk, err := sila.RecoverPublicKey(d, ls)
		if err != nil || !sk.Equal(pub) {
			t.Fatal("SILA recovery of libsecp256k1 signature")
		}
	}
}

// For digests >= n, RFC 6979 §2.3.4 feeds bits2octets(h) = int(h) mod n to
// the nonce generator. SILA and libsecp256k1 both do this and must stay
// byte-identical; decred v4.0.1 feeds the raw digest bytes, so its nonce
// (and r) differs. Every signature must still verify under every
// implementation. This was measured: 50/50 equal to libsecp256k1, 0/50 to
// decred.
func TestSecp256k1DigestAboveOrder(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 50; i++ {
		priv, kb, _ := randomKeyAndDigest(t, rng)
		var d [32]byte
		x := new(big.Int).Add(orderN, big.NewInt(int64(rng.Intn(1<<30))))
		x.FillBytes(d[:])
		sig, _ := sila.Sign(priv, d)
		rc, _ := sig.Recoverable()
		pub, _ := priv.PublicKey()
		pu, _ := pub.Uncompressed()

		gk, _ := gethcrypto.ToECDSA(kb[:])
		libSig, _ := gethcrypto.Sign(d[:], gk)
		if !bytes.Equal(libSig, rc[:]) {
			t.Fatalf("case %d: SILA != libsecp256k1 for digest >= n", i)
		}
		if !gethcrypto.VerifySignature(pu[:], d[:], rc[:64]) {
			t.Fatal("libsecp256k1 rejects SILA signature (digest >= n)")
		}
		dk := secp256k1.PrivKeyFromBytes(kb[:])
		dc := decredecdsa.SignCompact(dk, d[:], false)
		ds, err := sila.ParseRecoverableSignature(append(append([]byte{}, dc[1:]...), dc[0]-27))
		if err != nil || !sila.Verify(pub, d, ds) {
			t.Fatal("SILA rejects decred signature (digest >= n)")
		}
		if k, err := sila.RecoverPublicKey(d, ds); err != nil || !k.Equal(pub) {
			t.Fatal("SILA recovery of decred signature (digest >= n)")
		}
		var r, s secp256k1.ModNScalar
		r.SetByteSlice(rc[:32])
		s.SetByteSlice(rc[32:64])
		if !decredecdsa.NewSignature(&r, &s).Verify(d[:], dk.PubKey()) {
			t.Fatal("decred rejects SILA signature (digest >= n)")
		}
	}
}

// Negative differential: tampered and random signatures get the same
// verdict from SILA and libsecp256k1 (which also enforces low-S).
func TestSecp256k1VerifyVerdictsMatchLibsecp256k1(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	agreeReject, agreeAccept := 0, 0
	for i := 0; i < 2000; i++ {
		priv, _, d := randomKeyAndDigest(t, rng)
		pub, _ := priv.PublicKey()
		pu, _ := pub.Uncompressed()
		sig, _ := sila.Sign(priv, d)
		c, _ := sig.Compact()
		cand := c
		switch i % 5 {
		case 0: // unchanged
		case 1: // single bit flip
			cand[rng.Intn(64)] ^= 1 << uint(rng.Intn(8))
		case 2: // high-S malleation
			s := new(big.Int).SetBytes(cand[32:])
			new(big.Int).Sub(orderN, s).FillBytes(cand[32:])
		case 3: // random bytes
			rng.Read(cand[:])
		case 4: // wrong digest
			d[rng.Intn(32)] ^= 1
		}
		silaOK := false
		if s, err := sila.ParseSignature(cand[:]); err == nil {
			silaOK = sila.Verify(pub, d, s)
		}
		libOK := gethcrypto.VerifySignature(pu[:], d[:], cand[:])
		if silaOK != libOK {
			t.Fatalf("case %d (kind %d): SILA %v, libsecp256k1 %v for %x", i, i%5, silaOK, libOK, cand)
		}
		if silaOK {
			agreeAccept++
		} else {
			agreeReject++
		}
	}
	if agreeAccept < 300 || agreeReject < 1000 {
		t.Fatalf("unbalanced test: %d accepts, %d rejects", agreeAccept, agreeReject)
	}
}

// Public-key parsing agrees with decred on valid and invalid SEC 1 input
// (decred also rejects hybrid 0x06/0x07 encodings).
func TestSecp256k1PublicKeyParsingMatchesDecred(t *testing.T) {
	rng := rand.New(rand.NewSource(12))
	for i := 0; i < 4000; i++ {
		var in []byte
		priv, _, _ := randomKeyAndDigest(t, rng)
		pub, _ := priv.PublicKey()
		switch i % 4 {
		case 0:
			c, _ := pub.Compressed()
			in = c[:]
		case 1:
			u, _ := pub.Uncompressed()
			in = u[:]
		case 2: // random x with a valid prefix: about half are on the curve
			in = make([]byte, 33)
			rng.Read(in)
			in[0] = 2 + byte(rng.Intn(2))
		case 3: // corrupted uncompressed key
			u, _ := pub.Uncompressed()
			u[1+rng.Intn(64)] ^= 1 << uint(rng.Intn(8))
			in = u[:]
		}
		sp, serr := sila.ParsePublicKey(in)
		dp, derr := secp256k1.ParsePubKey(in)
		if (serr == nil) != (derr == nil) {
			t.Fatalf("case %d: SILA err=%v decred err=%v for %x", i, serr, derr, in)
		}
		if serr == nil {
			u, _ := sp.Uncompressed()
			if !bytes.Equal(u[:], dp.SerializeUncompressed()) {
				t.Fatalf("case %d: decoded points differ", i)
			}
		}
	}
}
