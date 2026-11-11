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

// refVerify is a textbook ECDSA verification over math/big (test oracle,
// public data only). It accepts high-S, so callers check low-S separately.
func refVerify(pubX, pubY *big.Int, digest [32]byte, r, s *big.Int) bool {
	if r.Sign() <= 0 || r.Cmp(bigN) >= 0 || s.Sign() <= 0 || s.Cmp(bigN) >= 0 {
		return false
	}
	z := new(big.Int).Mod(new(big.Int).SetBytes(digest[:]), bigN)
	w := new(big.Int).ModInverse(s, bigN)
	u1 := new(big.Int).Mod(new(big.Int).Mul(z, w), bigN)
	u2 := new(big.Int).Mod(new(big.Int).Mul(r, w), bigN)
	R := refAdd(refMul(u1, refG), refMul(u2, refPoint{x: pubX, y: pubY}))
	if R.inf {
		return false
	}
	return new(big.Int).Mod(R.x, bigN).Cmp(r) == 0
}

func testKey(t testing.TB, rng *rand.Rand) *PrivateKey {
	t.Helper()
	k, err := GeneratePrivateKey(rng)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSignVerifyRecoverRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	for i := 0; i < 40; i++ {
		priv := testKey(t, rng)
		pub, err := priv.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		var digest [32]byte
		rng.Read(digest[:])
		sig, err := Sign(priv, digest)
		if err != nil {
			t.Fatal(err)
		}
		if !Verify(pub, digest, sig) {
			t.Fatal("valid signature rejected")
		}
		// Independent check with the math/big reference.
		r, s := sig.R(), sig.S()
		if !refVerify(new(big.Int).SetBytes(pub.x[:]), new(big.Int).SetBytes(pub.y[:]), digest,
			new(big.Int).SetBytes(r[:]), new(big.Int).SetBytes(s[:])) {
			t.Fatal("reference verifier rejects SILA signature")
		}
		if new(big.Int).SetBytes(s[:]).Cmp(new(big.Int).Rsh(bigN, 1)) > 0 {
			t.Fatal("high-S produced")
		}
		rec, err := RecoverPublicKey(digest, sig)
		if err != nil || !rec.Equal(pub) {
			t.Fatalf("recovery failed: %v", err)
		}
		// Determinism (RFC 6979): same key and digest, same signature.
		sig2, _ := Sign(priv, digest)
		if sig2 != sig {
			t.Fatal("signing is not deterministic")
		}
		// Encodings round-trip.
		c, _ := sig.Compact()
		rc, _ := sig.Recoverable()
		p1, err1 := ParseSignature(c[:])
		p2, err2 := ParseRecoverableSignature(rc[:])
		if err1 != nil || err2 != nil || !Verify(pub, digest, p1) || p2 != sig {
			t.Fatal("encoding roundtrip")
		}
		if _, err := RecoverPublicKey(digest, p1); !errors.Is(err, ErrRecoveryFailed) {
			t.Fatal("compact signature must not be recoverable")
		}
	}
}

func TestVerifyRejectsWrongInputs(t *testing.T) {
	rng := rand.New(rand.NewSource(6))
	priv := testKey(t, rng)
	pub, _ := priv.PublicKey()
	other, _ := testKey(t, rng).PublicKey()
	digest := sha256.Sum256([]byte("SILA"))
	sig, _ := Sign(priv, digest)

	if Verify(other, digest, sig) {
		t.Fatal("wrong key accepted")
	}
	bad := digest
	bad[0] ^= 1
	if Verify(pub, bad, sig) {
		t.Fatal("wrong digest accepted")
	}
	// Every single-bit flip of r||s must be rejected (or fail to parse).
	c, _ := sig.Compact()
	for i := 0; i < 512; i++ {
		m := c
		m[i/8] ^= 1 << (i % 8)
		if s, err := ParseSignature(m[:]); err == nil && Verify(pub, digest, s) {
			t.Fatalf("bit flip %d accepted", i)
		}
	}
	// Recovery with a tampered digest yields a different key (never pub).
	if k, err := RecoverPublicKey(bad, sig); err == nil && k.Equal(pub) {
		t.Fatal("recovery ignored the digest")
	}
	// Zero values are rejected everywhere.
	var zsig Signature
	var zpub PublicKey
	if Verify(zpub, digest, sig) || Verify(pub, digest, zsig) {
		t.Fatal("zero value accepted")
	}
	if _, err := RecoverPublicKey(digest, zsig); err == nil {
		t.Fatal("zero signature recovered")
	}
}

func TestSignatureParsingIsStrict(t *testing.T) {
	n := to32(bigN)
	nm1 := to32(new(big.Int).Sub(bigN, big.NewInt(1)))
	half := to32(new(big.Int).Rsh(bigN, 1))
	halfP1 := to32(new(big.Int).Add(new(big.Int).Rsh(bigN, 1), big.NewInt(1)))
	one := to32(big.NewInt(1))
	var zero [32]byte
	cat := func(r, s *[32]byte) []byte { return append(append([]byte{}, r[:]...), s[:]...) }
	reject := map[string][]byte{
		"r=0":          cat(&zero, one),
		"s=0":          cat(one, &zero),
		"r=n":          cat(n, one),
		"s=n":          cat(one, n),
		"s=n-1 (high)": cat(one, nm1),
		"s=(n-1)/2+1":  cat(one, halfP1),
		"short":        make([]byte, 63),
		"long":         make([]byte, 65),
		"all ones":     bytes.Repeat([]byte{0xFF}, 64),
	}
	for name, b := range reject {
		if _, err := ParseSignature(b); !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := ParseSignature(cat(nm1, half)); err != nil {
		t.Fatal("boundary r=n-1, s=(n-1)/2 rejected")
	}
	for _, v := range []byte{4, 27, 28, 255} {
		b := append(cat(one, one), v)
		if _, err := ParseRecoverableSignature(b); err == nil {
			t.Errorf("recovery id %d accepted", v)
		}
	}
	for v := byte(0); v < 4; v++ {
		if _, err := ParseRecoverableSignature(append(cat(one, one), v)); err != nil {
			t.Errorf("recovery id %d rejected", v)
		}
	}
}

func TestHighSIsRejectedByVerifyAndRecover(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	priv := testKey(t, rng)
	pub, _ := priv.PublicKey()
	digest := sha256.Sum256([]byte("malleability"))
	sig, _ := Sign(priv, digest)
	// Build the malleated (r, n-s) form directly as a strict signature
	// object (which the parsers never produce): it is mathematically valid
	// ECDSA, but the strict rules reject it in Verify and in recovery.
	s := new(big.Int).SetBytes(sig.s[:])
	high := Signature{r: sig.r, s: *to32(new(big.Int).Sub(bigN, s)), v: sig.v ^ 1, hasRecoveryID: true, valid: true}
	r := new(big.Int).SetBytes(sig.r[:])
	if !refVerify(new(big.Int).SetBytes(pub.x[:]), new(big.Int).SetBytes(pub.y[:]), digest, r, new(big.Int).SetBytes(high.s[:])) {
		t.Fatal("test setup: malleated signature should be textbook-valid")
	}
	if Verify(pub, digest, high) {
		t.Fatal("high-S accepted by Verify")
	}
	if _, err := RecoverPublicKey(digest, high); err == nil {
		t.Fatal("high-S accepted by RecoverPublicKey")
	}
}

func TestRecoveryIDsSelectDistinctKeys(t *testing.T) {
	rng := rand.New(rand.NewSource(8))
	priv := testKey(t, rng)
	pub, _ := priv.PublicKey()
	digest := sha256.Sum256([]byte("recovery"))
	sig, _ := Sign(priv, digest)
	other := sig
	other.v ^= 1
	k, err := RecoverPublicKey(digest, other)
	if err == nil && k.Equal(pub) {
		t.Fatal("flipped parity recovered the same key")
	}
	if err == nil && !Verify(k, digest, other) {
		t.Fatal("recovered key does not verify its own signature")
	}
	// v = 2/3 need r + n < p; for a typical r that x does not exist or is
	// not on the curve, and recovery must fail cleanly rather than panic.
	for _, v := range []byte{2, 3} {
		o := sig
		o.v = v
		if k, err := RecoverPublicKey(digest, o); err == nil && k.Equal(pub) {
			t.Fatalf("v=%d recovered the signer", v)
		}
	}
}

func TestPrivateKeyValidation(t *testing.T) {
	for name, b := range map[string][]byte{
		"zero":  make([]byte, 32),
		"n":     to32(bigN)[:],
		"n+1":   to32(new(big.Int).Add(bigN, big.NewInt(1)))[:],
		"max":   bytes.Repeat([]byte{0xFF}, 32),
		"short": make([]byte, 31),
		"long":  make([]byte, 33),
	} {
		if _, err := ParsePrivateKey(b); !errors.Is(err, ErrInvalidPrivateKey) {
			t.Errorf("%s accepted", name)
		}
	}
	for _, v := range []*big.Int{big.NewInt(1), new(big.Int).Sub(bigN, big.NewInt(1))} {
		k, err := ParsePrivateKey(to32(v)[:])
		if err != nil {
			t.Fatalf("%x rejected", v)
		}
		b, _ := k.Bytes()
		if fromBytes(b).Cmp(v) != 0 {
			t.Fatal("bytes roundtrip")
		}
		pub, _ := k.PublicKey()
		want := refMul(v, refG)
		if new(big.Int).SetBytes(pub.x[:]).Cmp(want.x) != 0 || new(big.Int).SetBytes(pub.y[:]).Cmp(want.y) != 0 {
			t.Fatal("public key mismatch")
		}
	}
	k, _ := ParsePrivateKey(to32(big.NewInt(5))[:])
	k.Zero()
	if _, err := k.Bytes(); err == nil {
		t.Fatal("zeroed key still usable")
	}
	if _, err := Sign(k, [32]byte{}); err == nil {
		t.Fatal("zeroed key signed")
	}
	if k.d1.v != (limbs{}) || k.d2.v != (limbs{}) {
		t.Fatal("scalar not overwritten")
	}
	var nilKey *PrivateKey
	if _, err := Sign(nilKey, [32]byte{}); err == nil {
		t.Fatal("nil key signed")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

type constReader byte

func (c constReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = byte(c)
	}
	return len(b), nil
}

func TestGeneratePrivateKeyFailures(t *testing.T) {
	if _, err := GeneratePrivateKey(failingReader{}); err == nil {
		t.Fatal("failing reader")
	}
	// A reader that always returns 0x00..00 (invalid) must not loop forever.
	if _, err := GeneratePrivateKey(constReader(0)); err == nil {
		t.Fatal("all-zero reader produced a key")
	}
	if _, err := GeneratePrivateKey(nil); err != nil {
		t.Fatal("crypto/rand")
	}
}

// Digests >= n are reduced mod n before signing and verification.
func TestDigestAtOrAboveOrder(t *testing.T) {
	rng := rand.New(rand.NewSource(9))
	priv := testKey(t, rng)
	pub, _ := priv.PublicKey()
	for _, d := range []*big.Int{bigN, new(big.Int).Add(bigN, big.NewInt(1)), new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))} {
		var digest [32]byte
		d.FillBytes(digest[:])
		sig, err := Sign(priv, digest)
		if err != nil || !Verify(pub, digest, sig) {
			t.Fatalf("digest %x", d)
		}
		r, s := sig.R(), sig.S()
		if !refVerify(new(big.Int).SetBytes(pub.x[:]), new(big.Int).SetBytes(pub.y[:]), digest, new(big.Int).SetBytes(r[:]), new(big.Int).SetBytes(s[:])) {
			t.Fatal("reference disagrees")
		}
		rec, err := RecoverPublicKey(digest, sig)
		if err != nil || !rec.Equal(pub) {
			t.Fatal("recovery")
		}
	}
}

// Recovery identifiers 2 and 3 (R.x >= n) occur with probability about
// 2^-127 when signing, so the success path is exercised with a
// constructed signature: pick a curve point R with n <= x < p, a low s and
// a digest; the key Q = r^-1 (s·R - z·G) (computed with the math/big
// reference) must be what recovery returns, and must verify.
func TestRecoveryWithOverflowedR(t *testing.T) {
	var R refPoint
	found := false
	for i := int64(1); i < 1000 && !found; i++ { // i >= 1 so that r = x - n != 0
		x := new(big.Int).Add(bigN, big.NewInt(i))
		rhs := new(big.Int).Add(new(big.Int).Exp(x, big.NewInt(3), bigP), big.NewInt(7))
		rhs.Mod(rhs, bigP)
		if y := new(big.Int).ModSqrt(rhs, bigP); y != nil {
			R, found = refPoint{x: x, y: y}, true
		}
	}
	if !found {
		t.Fatal("no curve point with x >= n found")
	}
	r := new(big.Int).Sub(R.x, bigN)
	for _, parity := range []uint{0, 1} {
		Rp := R
		if Rp.y.Bit(0) != parity {
			Rp.y = new(big.Int).Sub(bigP, Rp.y)
		}
		s := big.NewInt(0x5115A)
		digest := sha256.Sum256([]byte{byte(parity)})
		z := new(big.Int).Mod(new(big.Int).SetBytes(digest[:]), bigN)
		rinv := new(big.Int).ModInverse(r, bigN)
		u1 := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Neg(z), rinv), bigN)
		u2 := new(big.Int).Mod(new(big.Int).Mul(s, rinv), bigN)
		want := refAdd(refMul(u1, refG), refMul(u2, Rp))

		b := append(append(append([]byte{}, to32(r)[:]...), to32(s)[:]...), byte(2|parity))
		sig, err := ParseRecoverableSignature(b)
		if err != nil {
			t.Fatal(err)
		}
		got, err := RecoverPublicKey(digest, sig)
		if err != nil {
			t.Fatalf("v=%d: %v", 2|parity, err)
		}
		if new(big.Int).SetBytes(got.x[:]).Cmp(want.x) != 0 || new(big.Int).SetBytes(got.y[:]).Cmp(want.y) != 0 {
			t.Fatalf("v=%d: wrong key", 2|parity)
		}
		if !Verify(got, digest, sig) {
			t.Fatalf("v=%d: recovered key does not verify", 2|parity)
		}
		// The same (r, s) with v = parity (x = r < n) must not give this key.
		b[64] = byte(parity)
		sig0, _ := ParseRecoverableSignature(b)
		if k, err := RecoverPublicKey(digest, sig0); err == nil && k.Equal(got) {
			t.Fatal("v without overflow bit recovered the same key")
		}
	}
	// r with r + n >= p must be rejected for v >= 2.
	big1 := new(big.Int).Sub(bigP, bigN) // r = p - n gives x = p (invalid)
	b := append(append(append([]byte{}, to32(big1)[:]...), to32(big.NewInt(1))[:]...), 2)
	sig, _ := ParseRecoverableSignature(b)
	if _, err := RecoverPublicKey([32]byte{}, sig); !errors.Is(err, ErrRecoveryFailed) {
		t.Fatal("x = r + n >= p accepted")
	}
}

func TestHMACSHA256MatchesStandardLibrary(t *testing.T) {
	rng := rand.New(rand.NewSource(15))
	for i := 0; i < 500; i++ {
		var key [32]byte
		rng.Read(key[:])
		msg := make([]byte, rng.Intn(130))
		rng.Read(msg)
		cut := rng.Intn(len(msg) + 1)
		got := hmacSHA256(&key, msg[:cut], msg[cut:])
		m := hmac.New(sha256.New, key[:])
		m.Write(msg)
		if !bytes.Equal(got[:], m.Sum(nil)) {
			t.Fatalf("hmac mismatch for %d-byte message", len(msg))
		}
	}
}

func TestSignDoesNotAllocate(t *testing.T) {
	rng := rand.New(rand.NewSource(16))
	priv := testKey(t, rng)
	digest := sha256.Sum256([]byte("alloc"))
	if raceEnabled {
		t.Skip("allocation counts are not meaningful under -race")
	}
	if n := testing.AllocsPerRun(20, func() { Sign(priv, digest) }); n != 0 {
		t.Fatalf("Sign allocates %v times", n)
	}
}
