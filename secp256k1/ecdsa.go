// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"hash"
)

// SILA signature contract (development version; see
// docs/SECP256K1-SIGNATURE-CONTRACT.md):
//
//   - The signed value is a 32-byte message digest supplied by the caller
//     (for SILA, the Keccak-256 digest of the canonical encoding defined by
//     the protocol). It is interpreted as a big-endian integer mod n.
//   - Signing is deterministic (RFC 6979, HMAC-SHA-256) and always returns
//     a low-S signature (s <= (n-1)/2).
//   - Verification and recovery accept only canonical values:
//     1 <= r < n, 1 <= s <= (n-1)/2 (high-S is rejected).
//   - Compact encoding is r || s (64 bytes); the recoverable encoding is
//     r || s || v (65 bytes) with recovery identifier v in {0, 1, 2, 3}.

var (
	// ErrInvalidSignature denotes a malformed or non-canonical signature.
	ErrInvalidSignature = errors.New("sila/secp256k1: invalid signature")
	// ErrRecoveryFailed denotes a signature from which no public key can be
	// recovered (missing recovery identifier or no valid curve point).
	ErrRecoveryFailed = errors.New("sila/secp256k1: public key recovery failed")
)

const (
	// DigestSize is the size of the message digest that is signed.
	DigestSize = 32
	// SignatureSize is the size of the compact encoding r || s.
	SignatureSize = 64
	// RecoverableSignatureSize is the size of the encoding r || s || v.
	RecoverableSignatureSize = 65
)

// Signature is a validated ECDSA signature. It always holds canonical,
// low-S values. hasRecoveryID is false for signatures parsed from the
// 64-byte compact form.
type Signature struct {
	r, s          [32]byte
	v             byte
	hasRecoveryID bool
	valid         bool
}

// R returns a copy of the r component (32 bytes, big-endian).
func (sig Signature) R() [32]byte { return sig.r }

// S returns a copy of the s component (32 bytes, big-endian).
func (sig Signature) S() [32]byte { return sig.s }

// RecoveryID returns the recovery identifier v and whether one is present.
func (sig Signature) RecoveryID() (byte, bool) { return sig.v, sig.hasRecoveryID }

// Compact returns r || s.
func (sig Signature) Compact() ([SignatureSize]byte, error) {
	var out [SignatureSize]byte
	if !sig.valid {
		return out, ErrInvalidSignature
	}
	copy(out[:32], sig.r[:])
	copy(out[32:], sig.s[:])
	return out, nil
}

// Recoverable returns r || s || v. It fails for signatures without a
// recovery identifier.
func (sig Signature) Recoverable() ([RecoverableSignatureSize]byte, error) {
	var out [RecoverableSignatureSize]byte
	if !sig.valid || !sig.hasRecoveryID {
		return out, ErrInvalidSignature
	}
	copy(out[:32], sig.r[:])
	copy(out[32:64], sig.s[:])
	out[64] = sig.v
	return out, nil
}

// ParseSignature decodes the 64-byte compact form r || s with strict
// canonical checks (1 <= r < n, 1 <= s <= (n-1)/2).
func ParseSignature(b []byte) (Signature, error) {
	if len(b) != SignatureSize {
		return Signature{}, ErrInvalidSignature
	}
	return newSignature((*[32]byte)(b[:32]), (*[32]byte)(b[32:64]), 0, false)
}

// ParseRecoverableSignature decodes r || s || v with the same checks and
// v in {0, 1, 2, 3}.
func ParseRecoverableSignature(b []byte) (Signature, error) {
	if len(b) != RecoverableSignatureSize || b[64] > 3 {
		return Signature{}, ErrInvalidSignature
	}
	return newSignature((*[32]byte)(b[:32]), (*[32]byte)(b[32:64]), b[64], true)
}

func newSignature(r, s *[32]byte, v byte, hasV bool) (Signature, error) {
	var rs, ss scalar
	if rs.setBytesCanonical(r) != 1 || rs.isZero() == 1 ||
		ss.setBytesCanonical(s) != 1 || ss.isZero() == 1 || ss.isHigh() == 1 {
		return Signature{}, ErrInvalidSignature
	}
	return Signature{r: *r, s: *s, v: v, hasRecoveryID: hasV, valid: true}, nil
}

// scalars returns r and s as scalars; ok is false for an invalid value.
func (sig *Signature) scalars() (r, s scalar, ok bool) {
	if !sig.valid {
		return r, s, false
	}
	okR := r.setBytesCanonical(&sig.r) & (1 ^ r.isZero())
	okS := s.setBytesCanonical(&sig.s) & (1 ^ s.isZero()) & (1 ^ s.isHigh())
	return r, s, okR&okS == 1
}

// Sign produces a deterministic low-S ECDSA signature with a recovery
// identifier over a 32-byte digest. All operations involving the private
// key and the nonce are constant time.
func Sign(priv *PrivateKey, digest [DigestSize]byte) (Signature, error) {
	if priv == nil || !priv.valid {
		return Signature{}, ErrInvalidPrivateKey
	}
	var z scalar
	z.setBytesReduced(&digest)

	nonces := newRFC6979(&priv.d, &z)
	defer nonces.wipe()
	for {
		var k scalar
		if !nonces.next(&k) {
			continue // candidate outside [1, n-1]: try the next one
		}
		sig, ok := signWithNonce(&priv.d, &z, &k)
		k.zero()
		if ok {
			return sig, nil
		}
	}
}

// signWithNonce computes (r, s, v) for a given nonce k. It returns false
// if r or s is zero (probability about 2^-256), in which case the caller
// continues with the next nonce.
func signWithNonce(d, z, k *scalar) (Signature, bool) {
	var R point
	R.scalarBaseMult(k)
	x, y, _ := R.affine()
	xb := x.bytes()

	// r = x mod n. x < p < 2n, so one conditional subtraction suffices;
	// overflow records whether x >= n (recovery identifier bit 1).
	xl := limbsFromBytes(&xb)
	overflow := 1 ^ lessThan(&xl, &scalarN.m)
	var r scalar
	r.setBytesReduced(&xb)
	if r.isZero() == 1 {
		return Signature{}, false
	}

	// s = k^-1 (z + r·d) mod n.
	var s, kinv, rd scalar
	kinv.inv(k)
	rd.mul(&r, d)
	s.add(z, &rd)
	s.mul(&s, &kinv)
	kinv.zero()
	rd.zero()
	if s.isZero() == 1 {
		return Signature{}, false
	}

	v := byte(y.isOdd()) | byte(overflow)<<1
	// Normalise to low-S; negating s mirrors R, which flips y's parity.
	high := s.isHigh()
	var negS scalar
	negS.neg(&s)
	s.selectFrom(&negS, &s, high)
	v ^= byte(high)

	return Signature{r: r.bytes(), s: s.bytes(), v: v, hasRecoveryID: true, valid: true}, true
}

// Verify reports whether sig is a valid signature of digest by pub under
// the SILA contract (canonical, low-S). Inputs are public.
func Verify(pub PublicKey, digest [DigestSize]byte, sig Signature) bool {
	if !pub.valid {
		return false
	}
	r, s, ok := sig.scalars()
	if !ok {
		return false
	}
	var z, w, u1, u2 scalar
	z.setBytesReduced(&digest)
	w.inv(&s)
	u1.mul(&z, &w)
	u2.mul(&r, &w)

	q := pub.point()
	var R point
	linearCombination(&R, &u1, &u2, &q)
	if R.isIdentity() == 1 {
		return false
	}
	x, _, _ := R.affine()
	xb := x.bytes()
	var xr scalar
	xr.setBytesReduced(&xb)
	return xr.equal(&r) == 1
}

// RecoverPublicKey returns the public key that produced sig over digest,
// using the signature's recovery identifier. The recovered key is the
// unique key for which Verify(key, digest, sig) is true given (r, s, v).
func RecoverPublicKey(digest [DigestSize]byte, sig Signature) (PublicKey, error) {
	if !sig.valid || !sig.hasRecoveryID || sig.v > 3 {
		return PublicKey{}, ErrRecoveryFailed
	}
	r, s, ok := sig.scalars()
	if !ok {
		return PublicKey{}, ErrRecoveryFailed
	}

	// x-coordinate of R: r, or r + n when v >= 2; it must be < p.
	xl := limbsFromBytes(&sig.r)
	if sig.v >= 2 {
		var c uint64
		xl, c = addLimbs(&xl, &scalarN.m)
		if c != 0 || lessThan(&xl, &fieldP.m) != 1 {
			return PublicKey{}, ErrRecoveryFailed
		}
	}
	var xb [32]byte
	limbsToBytes(&xb, &xl)
	var x, y fieldElement
	if x.setBytes(&xb) != 1 || !liftX(&y, &x, uint64(sig.v&1)) {
		return PublicKey{}, ErrRecoveryFailed
	}
	var R point
	R.setAffine(&x, &y)

	// Q = r^-1 (s·R - z·G) = (-z·r^-1)·G + (s·r^-1)·R.
	var z, rinv, u1, u2 scalar
	z.setBytesReduced(&digest)
	rinv.inv(&r)
	u1.mul(&z, &rinv)
	u1.neg(&u1)
	u2.mul(&s, &rinv)
	var Q point
	linearCombination(&Q, &u1, &u2, &R)
	return publicKeyFromPoint(&Q)
}

// linearCombination sets out = u1·G + u2·Q. Used only on public values
// (verification and recovery).
func linearCombination(out *point, u1, u2 *scalar, q *point) {
	var a, b point
	a.scalarBaseMult(u1)
	b.scalarMult(u2, q)
	out.add(&a, &b)
}

// rfc6979 generates nonce candidates per RFC 6979 §3.2 with HMAC-SHA-256
// for a 256-bit group order: qlen = hlen = 256, so bits2int is the identity
// and bits2octets(h) = int(h) mod n.
type rfc6979 struct {
	k, v [32]byte
	mac  hash.Hash
	more bool
}

func newRFC6979(d, z *scalar) *rfc6979 {
	g := &rfc6979{}
	for i := range g.v {
		g.v[i] = 0x01
	}
	x := d.bytes()  // int2octets(d)
	h1 := z.bytes() // bits2octets(digest) = digest mod n
	defer clear(x[:])
	g.update(0x00, x[:], h1[:])
	g.update(0x01, x[:], h1[:])
	return g
}

// update performs K = HMAC_K(V || sep || x || h1); V = HMAC_K(V).
func (g *rfc6979) update(sep byte, x, h1 []byte) {
	mac := hmac.New(sha256.New, g.k[:])
	mac.Write(g.v[:])
	mac.Write([]byte{sep})
	mac.Write(x)
	mac.Write(h1)
	mac.Sum(g.k[:0])
	mac = hmac.New(sha256.New, g.k[:])
	mac.Write(g.v[:])
	mac.Sum(g.v[:0])
}

// next writes the next candidate into k and reports whether it lies in
// [1, n-1]. After each candidate the state advances per RFC 6979 §3.2 h.3.
func (g *rfc6979) next(k *scalar) bool {
	if g.more {
		// K = HMAC_K(V || 0x00); V = HMAC_K(V)
		mac := hmac.New(sha256.New, g.k[:])
		mac.Write(g.v[:])
		mac.Write([]byte{0x00})
		mac.Sum(g.k[:0])
		mac = hmac.New(sha256.New, g.k[:])
		mac.Write(g.v[:])
		mac.Sum(g.v[:0])
	}
	g.more = true
	mac := hmac.New(sha256.New, g.k[:])
	mac.Write(g.v[:])
	mac.Sum(g.v[:0])
	ok := k.setBytesCanonical(&g.v) & (1 ^ k.isZero())
	return ok == 1
}

func (g *rfc6979) wipe() {
	clear(g.k[:])
	clear(g.v[:])
}
