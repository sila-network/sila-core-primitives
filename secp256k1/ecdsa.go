// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

// SILA signature contract (development version; see
// docs/SECP256K1-SIGNATURE-CONTRACT.md):
//
//   - The signed value is a 32-byte message digest supplied by the caller
//     (for SILA, the Keccak-256 digest of the canonical encoding defined by
//     the protocol). It is interpreted as a big-endian integer mod n.
//   - Signing is deterministic (RFC 6979, HMAC-SHA-256) and always returns
//     a low-S signature (s <= (n-1)/2).
//   - Strict parsing (ParseSignature, ParseRecoverableSignature) and Verify
//     accept only canonical values: 1 <= r < n, 1 <= s <= (n-1)/2.
//     Verify always rejects high-S.
//   - Recovery-compatible parsing (the AllowHighS variants) also accepts
//     (n-1)/2 < s < n, as raw public-key recovery does; such signatures
//     can be recovered from but never pass Verify.
//   - Compact encoding is r || s (64 bytes); the recoverable encoding is
//     r || s || v (65 bytes) with recovery identifier v in {0, 1, 2, 3}.
//     Transaction-level rules (v in {0, 1} only, offsets such as 27/28)
//     belong to a higher layer (package txsig).

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

// Signature is a validated ECDSA signature: 1 <= r < n and 1 <= s < n.
// Signatures from Sign and from the strict parsers are always low-S;
// highS can only be set by the AllowHighS parsers. hasRecoveryID is false
// for signatures parsed from the 64-byte compact form.
type Signature struct {
	r, s          [32]byte
	v             byte
	hasRecoveryID bool
	highS         bool
	valid         bool
}

// IsLowS reports whether s <= (n-1)/2.
func (sig Signature) IsLowS() bool { return sig.valid && !sig.highS }

// Normalize returns the low-S form of sig: (r, n-s), with bit 0 of the
// recovery identifier flipped (negating s mirrors R). A low-S signature is
// returned unchanged. Both forms recover the same public key.
func (sig Signature) Normalize() Signature {
	if !sig.valid || !sig.highS {
		return sig
	}
	var s scalar
	s.setBytesCanonical(&sig.s)
	s.neg(&s)
	sig.s = s.bytes()
	sig.highS = false
	if sig.hasRecoveryID {
		sig.v ^= 1
	}
	return sig
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
	return newSignature((*[32]byte)(b[:32]), (*[32]byte)(b[32:64]), 0, false, false)
}

// ParseRecoverableSignature decodes r || s || v with the same checks and
// v in {0, 1, 2, 3}.
func ParseRecoverableSignature(b []byte) (Signature, error) {
	if len(b) != RecoverableSignatureSize || b[64] > 3 {
		return Signature{}, ErrInvalidSignature
	}
	return newSignature((*[32]byte)(b[:32]), (*[32]byte)(b[32:64]), b[64], true, false)
}

// ParseSignatureAllowHighS is ParseSignature for the recovery-compatible
// context: it also accepts (n-1)/2 < s < n. The result never passes Verify
// unless it is first normalized with Normalize.
func ParseSignatureAllowHighS(b []byte) (Signature, error) {
	if len(b) != SignatureSize {
		return Signature{}, ErrInvalidSignature
	}
	return newSignature((*[32]byte)(b[:32]), (*[32]byte)(b[32:64]), 0, false, true)
}

// ParseRecoverableSignatureAllowHighS is ParseRecoverableSignature for the
// recovery-compatible context (raw public-key recovery): 1 <= r < n,
// 1 <= s < n, v in {0, 1, 2, 3}. RecoverPublicKey accepts the result;
// Verify rejects high-S.
func ParseRecoverableSignatureAllowHighS(b []byte) (Signature, error) {
	if len(b) != RecoverableSignatureSize || b[64] > 3 {
		return Signature{}, ErrInvalidSignature
	}
	return newSignature((*[32]byte)(b[:32]), (*[32]byte)(b[32:64]), b[64], true, true)
}

func newSignature(r, s *[32]byte, v byte, hasV, allowHighS bool) (Signature, error) {
	var rs, ss scalar
	if rs.setBytesCanonical(r) != 1 || rs.isZero() == 1 ||
		ss.setBytesCanonical(s) != 1 || ss.isZero() == 1 {
		return Signature{}, ErrInvalidSignature
	}
	high := ss.isHigh() == 1
	if high && !allowHighS {
		return Signature{}, ErrInvalidSignature
	}
	return Signature{r: *r, s: *s, v: v, hasRecoveryID: hasV, highS: high, valid: true}, nil
}

// scalars returns r and s as scalars; ok is false for an invalid value.
// High s is accepted only if the signature was parsed as recovery-compatible.
func (sig *Signature) scalars() (r, s scalar, ok bool) {
	if !sig.valid {
		return r, s, false
	}
	okR := r.setBytesCanonical(&sig.r) & (1 ^ r.isZero())
	okS := s.setBytesCanonical(&sig.s) & (1 ^ s.isZero())
	if !sig.highS {
		okS &= 1 ^ s.isHigh()
	}
	return r, s, okR&okS == 1
}

// Sign produces a deterministic low-S ECDSA signature with a recovery
// identifier over a 32-byte digest. All operations involving the private
// key and the nonce are constant time.
//
// Interoperability evidence (byte-identical outputs against independent
// implementations) is recorded in docs/SECP256K1-PARITY.md.
func Sign(priv *PrivateKey, digest [DigestSize]byte) (Signature, error) {
	return sign(priv, &digest, nil)
}

// ExtraEntropySize is the size of the additional data mixed into the nonce
// by SignWithExtraEntropy.
const ExtraEntropySize = 32

// SignWithExtraEntropy signs like Sign but mixes 32 bytes of additional
// data into the RFC 6979 nonce derivation (RFC 6979 §3.6, "additional
// data" appended after the private key and the digest). With fresh random
// data this is "hedged" signing: it keeps the protection of RFC 6979
// against a weak random source and adds protection against fault attacks
// that need two signatures with the same nonce.
//
// The signature is valid and verifies like any other, but it is NOT
// byte-identical to Sign's deterministic output (unless extra repeats).
func SignWithExtraEntropy(priv *PrivateKey, digest [DigestSize]byte, extra [ExtraEntropySize]byte) (Signature, error) {
	defer clear(extra[:])
	return sign(priv, &digest, &extra)
}

// SignHedged is SignWithExtraEntropy with 32 bytes read from rand
// (crypto/rand.Reader when rand is nil). See SignWithExtraEntropy.
func SignHedged(priv *PrivateKey, digest [DigestSize]byte, rand io.Reader) (Signature, error) {
	if rand == nil {
		rand = cryptorand.Reader
	}
	var extra [ExtraEntropySize]byte
	defer clear(extra[:])
	if _, err := io.ReadFull(rand, extra[:]); err != nil {
		return Signature{}, err
	}
	return sign(priv, &digest, &extra)
}

func sign(priv *PrivateKey, digest *[DigestSize]byte, extra *[ExtraEntropySize]byte) (Signature, error) {
	if priv == nil || !priv.valid {
		return Signature{}, ErrInvalidPrivateKey
	}
	// All secret-dependent work runs in the processor's data-independent-
	// timing mode where available (withDIT).
	var sig Signature
	withDIT(func() { sig = signSecret(priv, digest, extra) })
	return sig, nil
}

// signSecret computes the signature; priv is valid.
func signSecret(priv *PrivateKey, digest *[DigestSize]byte, extra *[ExtraEntropySize]byte) Signature {
	var z scalar
	z.setBytesReduced(digest)

	x := priv.dBytes() // int2octets(d), rebuilt from the shares
	nonces := newRFC6979(&x, &z, extra)
	clear(x[:])
	defer nonces.wipe()
	for {
		var k scalar
		if !nonces.next(&k) {
			continue // candidate outside [1, n-1]: try the next one
		}
		// Per-signature inversion blinding rho, derived from the secret
		// RFC 6979 key K with a domain-separated message; it does not
		// change the RFC 6979 candidate sequence.
		rho, _ := derivedBlinding(&nonces.k, 'I', false)
		sig, ok := signWithNonce(&priv.d1, &priv.d2, &z, &k, &rho, func() (scalar, point) {
			return derivedBlinding(&nonces.k, 'B', true)
		})
		rho.zero()
		k.zero()
		if ok {
			return sig
		}
	}
}

// signWithNonce computes (r, s, v) for a given nonce k. It returns false
// if r or s is zero (probability about 2^-256), in which case the caller
// continues with the next nonce.
func signWithNonce(d1, d2, z, k, rho *scalar, fallback func() (scalar, point)) (Signature, bool) {
	var R point
	R.scalarBaseMultBlinded(k, fallback)
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

	// s = k^-1 (z + r·d) mod n, with r·d = r·d1 + r·d2 (the shares of
	// the masked private key; d itself never enters a multiplication).
	var s, kinv, rd, rd2 scalar
	kinv.invBlinded(k, rho)
	rd.mul(&r, d1)
	rd2.mul(&r, d2)
	s.add(z, &rd)
	s.add(&s, &rd2)
	rd2.zero()
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
// the strict rules (canonical, low-S). A high-S signature is always
// rejected; use
// Normalize first if the caller's context accepts malleable signatures.
// Inputs are public.
func Verify(pub PublicKey, digest [DigestSize]byte, sig Signature) bool {
	if !pub.valid || sig.highS {
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
	linearCombinationVartime(&R, &u1, &u2, &q)
	if R.isIdentity() == 1 {
		return false
	}
	// Accept iff x(R) mod n == r, i.e. x(R) is r or r + n (the latter only
	// if r + n < p). With x(R) = X/Z this is checked as X == r·Z without a
	// field inversion.
	rb := sig.r
	var rf, rz fieldElement
	rf.setBytes(&rb) // r < n < p
	if rz.mul(&rf, &R.z).equal(&R.x) == 1 {
		return true
	}
	rl := limbsFromBytes(&rb)
	rn, carry := addLimbs(&rl, &scalarN.m)
	if carry != 0 || lessThan(&rn, &fieldP.m) != 1 {
		return false
	}
	var rnb [32]byte
	limbsToBytes(&rnb, &rn)
	rf.setBytes(&rnb)
	return rz.mul(&rf, &R.z).equal(&R.x) == 1
}

// RecoverPublicKey returns the public key that produced sig over digest,
// using the signature's recovery identifier v in {0, 1, 2, 3}. It is the
// generic mathematical recovery: it accepts high-S signatures parsed with
// the AllowHighS variants and v = 2/3;
// transaction-level restrictions belong to a higher layer (package txsig).
// For a low-S signature, the recovered key is the unique key for which
// Verify(key, digest, sig) is true given (r, s, v).
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
	linearCombinationVartime(&Q, &u1, &u2, &R)
	return publicKeyFromPoint(&Q)
}

// rfc6979 generates nonce candidates per RFC 6979 §3.2 with HMAC-SHA-256
// for a 256-bit group order: qlen = hlen = 256, so bits2int is the identity
// and bits2octets(h) = int(h) mod n. HMAC is computed on fixed-size stack
// buffers (hmacSHA256) so that the key-derived state can be wiped.
//
// With extra != nil, the 32 extra bytes are appended to int2octets(d) ||
// bits2octets(h) in steps d and f (RFC 6979 §3.6, "additional data").
type rfc6979 struct {
	k, v [32]byte
	more bool
}

func newRFC6979(x *[32]byte, z *scalar, extra *[ExtraEntropySize]byte) rfc6979 {
	var g rfc6979
	for i := range g.v {
		g.v[i] = 0x01
	}
	// x is int2octets(d).
	h1 := z.bytes() // bits2octets(digest) = digest mod n
	var data []byte
	if extra != nil {
		data = extra[:]
	}
	g.k = hmacSHA256(&g.k, g.v[:], []byte{0x00}, x[:], h1[:], data) // step d
	g.v = hmacSHA256(&g.k, g.v[:])                                  // step e
	g.k = hmacSHA256(&g.k, g.v[:], []byte{0x01}, x[:], h1[:], data) // step f
	g.v = hmacSHA256(&g.k, g.v[:])                                  // step g
	return g
}

// next writes the next candidate into k and reports whether it lies in
// [1, n-1]. After each candidate the state advances per RFC 6979 §3.2 h.3.
func (g *rfc6979) next(k *scalar) bool {
	if g.more {
		g.k = hmacSHA256(&g.k, g.v[:], []byte{0x00})
		g.v = hmacSHA256(&g.k, g.v[:])
	}
	g.more = true
	g.v = hmacSHA256(&g.k, g.v[:])
	ok := k.setBytesCanonical(&g.v) & (1 ^ k.isZero())
	return ok == 1
}

func (g *rfc6979) wipe() {
	clear(g.k[:])
	clear(g.v[:])
}

// hmacSHA256 computes HMAC-SHA-256 (RFC 2104) with a 32-byte key over the
// concatenation of parts (at most 129 bytes in total, which covers every
// RFC 6979 message here, including 32 bytes of extra data). All buffers
// are on the stack and are cleared.
func hmacSHA256(key *[32]byte, parts ...[]byte) [32]byte {
	const block = 64
	var buf [block + 129]byte
	defer clear(buf[:])
	n := block
	for _, p := range parts {
		if n+len(p) > len(buf) {
			panic("sila/secp256k1: hmac message too long")
		}
		n += copy(buf[n:], p)
	}
	for i := 0; i < block; i++ {
		var kb byte
		if i < len(key) {
			kb = key[i]
		}
		buf[i] = kb ^ 0x36
	}
	inner := sha256.Sum256(buf[:n])
	var outer [block + 32]byte
	defer clear(outer[:])
	for i := 0; i < block; i++ {
		var kb byte
		if i < len(key) {
			kb = key[i]
		}
		outer[i] = kb ^ 0x5c
	}
	copy(outer[block:], inner[:])
	clear(inner[:])
	return sha256.Sum256(outer[:])
}
