// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"math/big"
	"math/rand"
	"testing"
)

// highSForm returns (r, n-s, v^1) for a low-S signature, as 65 bytes.
func highSForm(t *testing.T, sig Signature) [65]byte {
	t.Helper()
	b, err := sig.Recoverable()
	if err != nil {
		t.Fatal(err)
	}
	s := new(big.Int).SetBytes(b[32:64])
	copy(b[32:64], to32(new(big.Int).Sub(bigN, s))[:])
	b[64] ^= 1
	return b
}

// The strict and the recovery-compatible contexts differ only in the range
// of s: strict parsing and Verify reject high-S; the AllowHighS parsers
// accept it, recovery returns the same key, and Normalize maps it back.
func TestHighSContexts(t *testing.T) {
	rng := rand.New(rand.NewSource(40))
	for i := 0; i < 50; i++ {
		priv := testKey(t, rng)
		pub, _ := priv.PublicKey()
		var digest [32]byte
		rng.Read(digest[:])
		low, err := Sign(priv, digest)
		if err != nil {
			t.Fatal(err)
		}
		hb := highSForm(t, low)

		if _, err := ParseRecoverableSignature(hb[:]); err == nil {
			t.Fatal("strict parser accepted high-S")
		}
		if _, err := ParseSignature(hb[:64]); err == nil {
			t.Fatal("strict compact parser accepted high-S")
		}
		high, err := ParseRecoverableSignatureAllowHighS(hb[:])
		if err != nil {
			t.Fatal(err)
		}
		if high.IsLowS() {
			t.Fatal("high-S reported as low")
		}
		if Verify(pub, digest, high) {
			t.Fatal("Verify accepted high-S")
		}
		rec, err := RecoverPublicKey(digest, high)
		if err != nil || !rec.Equal(pub) {
			t.Fatal("recovery-compatible signature did not recover the signer")
		}
		norm := high.Normalize()
		nb, _ := norm.Recoverable()
		lb, _ := low.Recoverable()
		if nb != lb || !norm.IsLowS() || !Verify(pub, digest, norm) {
			t.Fatal("Normalize did not return the canonical signature")
		}
		if low.Normalize() != low {
			t.Fatal("Normalize changed a low-S signature")
		}
		// The compact AllowHighS form round-trips and also fails Verify.
		hc, err := ParseSignatureAllowHighS(hb[:64])
		if err != nil || Verify(pub, digest, hc) {
			t.Fatal("compact high-S handling")
		}
		if c, _ := hc.Compact(); !bytes.Equal(c[:], hb[:64]) {
			t.Fatal("compact high-S round trip")
		}
		if _, ok := hc.Normalize().RecoveryID(); ok {
			t.Fatal("Normalize invented a recovery identifier")
		}
	}
}

// Boundary values of s: (n-1)/2 is low, (n+1)/2 is the first high value,
// n-1 is the largest accepted, n and above are rejected in every context.
func TestSBoundaries(t *testing.T) {
	half := new(big.Int).Rsh(bigN, 1)
	r := to32(big.NewInt(1))
	cases := []struct {
		s             *big.Int
		strict, relax bool
	}{
		{big.NewInt(0), false, false},
		{big.NewInt(1), true, true},
		{half, true, true},
		{new(big.Int).Add(half, big.NewInt(1)), false, true},
		{new(big.Int).Sub(bigN, big.NewInt(1)), false, true},
		{bigN, false, false},
		{new(big.Int).Add(bigN, big.NewInt(1)), false, false},
		{new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)), false, false},
	}
	for _, c := range cases {
		var b [65]byte
		copy(b[:32], r[:])
		copy(b[32:64], to32(c.s)[:])
		for v := byte(0); v < 6; v++ {
			b[64] = v
			_, e1 := ParseRecoverableSignature(b[:])
			_, e2 := ParseRecoverableSignatureAllowHighS(b[:])
			wantStrict := c.strict && v <= 3
			wantRelax := c.relax && v <= 3
			if (e1 == nil) != wantStrict || (e2 == nil) != wantRelax {
				t.Fatalf("s=%x v=%d: strict=%v relax=%v, want %v %v", c.s, v, e1 == nil, e2 == nil, wantStrict, wantRelax)
			}
		}
		_, e1 := ParseSignature(b[:64])
		_, e2 := ParseSignatureAllowHighS(b[:64])
		if (e1 == nil) != c.strict || (e2 == nil) != c.relax {
			t.Fatalf("compact s=%x", c.s)
		}
	}
}

// refNonceWithExtra is an independent RFC 6979 §3.2/§3.6 implementation
// over crypto/hmac and math/big (test oracle).
func refNonceWithExtra(d *big.Int, digest [32]byte, extra []byte) *big.Int {
	mac := func(key []byte, parts ...[]byte) []byte {
		var buf []byte
		for _, p := range parts {
			buf = append(buf, p...)
		}
		return hmacRef(key, buf)
	}
	x := to32(d)
	h := to32(new(big.Int).Mod(new(big.Int).SetBytes(digest[:]), bigN))
	v := bytes.Repeat([]byte{1}, 32)
	k := make([]byte, 32)
	k = mac(k, v, []byte{0}, x[:], h[:], extra)
	v = mac(k, v)
	k = mac(k, v, []byte{1}, x[:], h[:], extra)
	v = mac(k, v)
	for {
		v = mac(k, v)
		c := new(big.Int).SetBytes(v)
		if c.Sign() > 0 && c.Cmp(bigN) < 0 {
			return c
		}
		k = mac(k, v, []byte{0})
		v = mac(k, v)
	}
}

func TestSignWithExtraEntropy(t *testing.T) {
	rng := rand.New(rand.NewSource(41))
	for i := 0; i < 30; i++ {
		priv := testKey(t, rng)
		pub, _ := priv.PublicKey()
		var digest, extra [32]byte
		rng.Read(digest[:])
		rng.Read(extra[:])
		sig, err := SignWithExtraEntropy(priv, digest, extra)
		if err != nil {
			t.Fatal(err)
		}
		if !Verify(pub, digest, sig) {
			t.Fatal("hedged signature rejected")
		}
		if rec, err := RecoverPublicKey(digest, sig); err != nil || !rec.Equal(pub) {
			t.Fatal("hedged signature does not recover")
		}
		again, _ := SignWithExtraEntropy(priv, digest, extra)
		if again != sig {
			t.Fatal("same extra data must give the same signature")
		}
		det, _ := Sign(priv, digest)
		if det.R() == sig.R() {
			t.Fatal("extra data did not change the nonce")
		}
		// r must equal x(k·G) mod n for the reference nonce.
		db, _ := priv.Bytes()
		k := refNonceWithExtra(new(big.Int).SetBytes(db[:]), digest, extra[:])
		R := refMul(k, refG)
		r := sig.R()
		if new(big.Int).Mod(R.x, bigN).Cmp(new(big.Int).SetBytes(r[:])) != 0 {
			t.Fatal("nonce differs from the RFC 6979 §3.6 reference")
		}
	}
	// Without extra data the reference reproduces Sign.
	priv := testKey(t, rng)
	digest := sha256.Sum256([]byte("no extra"))
	db, _ := priv.Bytes()
	k := refNonceWithExtra(new(big.Int).SetBytes(db[:]), digest, nil)
	sig, _ := Sign(priv, digest)
	r := sig.R()
	if new(big.Int).Mod(refMul(k, refG).x, bigN).Cmp(new(big.Int).SetBytes(r[:])) != 0 {
		t.Fatal("reference nonce does not reproduce Sign")
	}
}

func TestSignHedged(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	priv := testKey(t, rng)
	pub, _ := priv.PublicKey()
	digest := sha256.Sum256([]byte("hedged"))
	a, err := SignHedged(priv, digest, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SignHedged(priv, digest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(pub, digest, a) || !Verify(pub, digest, b) || a.R() == b.R() {
		t.Fatal("hedged signatures must verify and use fresh nonces")
	}
	if _, err := SignHedged(priv, digest, failingReader{}); err == nil {
		t.Fatal("entropy failure not reported")
	}
	if _, err := SignWithExtraEntropy(nil, digest, [32]byte{}); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Fatal("nil key accepted")
	}
	if n := testing.AllocsPerRun(20, func() { SignWithExtraEntropy(priv, digest, [32]byte{1}) }); n != 0 {
		t.Fatalf("SignWithExtraEntropy allocates %v times", n)
	}
}

func hmacRef(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}
