// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

import (
	"crypto/rand"
	"errors"
	"io"
)

// ErrInvalidPrivateKey denotes a private key outside [1, n-1] or of the
// wrong length.
var ErrInvalidPrivateKey = errors.New("sila/secp256k1: invalid private key")

// PrivateKeySize is the length of an encoded private key in bytes.
const PrivateKeySize = 32

// PrivateKey is a secret scalar d in [1, n-1]. All arithmetic on it is
// constant time. Use Zero to overwrite it when it is no longer needed;
// note that Go cannot guarantee that no other copy exists in memory (for
// example after the garbage collector moved it, or in the caller's
// buffers), so this is best-effort hygiene, not a guarantee.
//
// The key is stored masked as two shares, d = d1 + d2 (mod n), with d1
// random (finding S-8): multiplications only ever see the uniformly random
// shares, never d itself, so value-dependent instruction timing in the
// processor cannot depend on d.
type PrivateKey struct {
	d1, d2 scalar // Montgomery form; d = d1 + d2 mod n
	// c1, c2 are the same shares in canonical form (c1 + c2 = d mod n),
	// kept so that d can be rebuilt for RFC 6979 and Bytes with a modular
	// addition only: converting d1, d2 out of Montgomery form would
	// multiply the fixed stored shares on every signature (finding S-14).
	c1, c2 limbs
	valid  bool
}

// ParsePrivateKey decodes a 32-byte big-endian scalar. It rejects zero,
// values >= n and any other length. The range check is constant time; only
// the final accept/reject decision is observable.
func ParsePrivateKey(b []byte) (*PrivateKey, error) {
	if len(b) != PrivateKeySize {
		return nil, ErrInvalidPrivateKey
	}
	d := limbsFromBytes((*[32]byte)(b))
	defer clear(d[:])
	ok := lessThan(&d, &scalarN.m) & (1 ^ isZeroLimbs(&d))
	if ok != 1 {
		return nil, ErrInvalidPrivateKey
	}
	k := new(PrivateKey)
	k.setShares(&d)
	k.valid = true
	return k, nil
}

// setShares stores the canonical value d (< n) as shares d = d1 + d2.
//
// The mask d1 = HMAC-SHA-256(key = d, "SILA-secp256k1-key-mask" || R) mod n,
// with 32 fresh bytes R from the random source. It is pseudo-random and
// secret even if R is missing or predictable (a failed or broken source
// leaves a fixed, still secret, mask instead of an unmasked key), and it
// is fresh for every parse when R is random. The shares are formed in the
// canonical domain with a modular subtraction (no multiplication involves
// d); each share is then converted to Montgomery form, which multiplies
// only pseudo-random values.
func (k *PrivateKey) setShares(d *limbs) {
	var rnd [32]byte
	if _, err := io.ReadFull(randomSource, rnd[:]); err != nil {
		clear(rnd[:]) // fall back to the deterministic, secret mask
	}
	var db [32]byte
	limbsToBytes(&db, d)
	h := hmacSHA256(&db, []byte("SILA-secp256k1-key-mask"), rnd[:])
	m := limbsFromBytes(&h)
	scalarN.reduceOnce(&m, &m, 0) // any 256-bit value is < 2n
	clear(db[:])
	clear(h[:])
	clear(rnd[:])
	var r limbs
	scalarN.sub(&r, d, &m) // d2 = d - d1 mod n
	k.c1, k.c2 = m, r
	scalarN.toMont(&k.d1.v, &m)
	scalarN.toMont(&k.d2.v, &r)
	clear(m[:])
	clear(r[:])
}

// canonicalD returns d = c1 + c2 mod n in canonical limbs: a modular
// addition of the canonical shares, with no multiplication (no stored
// share is ever a multiplication operand here; S-14).
func (k *PrivateKey) canonicalD() limbs {
	var d limbs
	scalarN.add(&d, &k.c1, &k.c2)
	return d
}

// dBytes returns the 32-byte big-endian encoding of d.
func (k *PrivateKey) dBytes() [32]byte {
	d := k.canonicalD()
	var out [32]byte
	limbsToBytes(&out, &d)
	clear(d[:])
	return out
}

// GeneratePrivateKey returns a uniformly random private key, reading from
// r (crypto/rand.Reader if r is nil) and rejecting out-of-range candidates.
func GeneratePrivateKey(r io.Reader) (*PrivateKey, error) {
	if r == nil {
		r = rand.Reader
	}
	var buf [32]byte
	defer clear(buf[:])
	// The probability that a uniform 256-bit value is not in [1, n-1] is
	// about 2^-128, so the loop practically never repeats; the bound stops a
	// broken reader from looping forever.
	for i := 0; i < 64; i++ {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return nil, err
		}
		if k, err := ParsePrivateKey(buf[:]); err == nil {
			return k, nil
		}
	}
	return nil, errors.New("sila/secp256k1: random source produced no valid key")
}

// Bytes returns the 32-byte big-endian encoding of the key. The caller
// owns the returned copy and should clear it after use.
func (k *PrivateKey) Bytes() ([32]byte, error) {
	if k == nil || !k.valid {
		return [32]byte{}, ErrInvalidPrivateKey
	}
	return k.dBytes(), nil
}

// PublicKey returns d·G, computed in constant time.
func (k *PrivateKey) PublicKey() (PublicKey, error) {
	if k == nil || !k.valid {
		return PublicKey{}, ErrInvalidPrivateKey
	}
	var pub PublicKey
	var err error
	withDIT(func() {
		var p point
		p.scalarBaseMultShares(&k.d1, &k.d2, func() (scalar, point) {
			seed := k.dBytes()
			defer clear(seed[:])
			return derivedBlinding(&seed, 'P', true, nil)
		})
		pub, err = publicKeyFromPoint(&p)
	})
	return pub, err
}

// Zero overwrites the key; it becomes invalid.
func (k *PrivateKey) Zero() {
	if k == nil {
		return
	}
	k.d1.zero()
	k.d2.zero()
	clear(k.c1[:])
	clear(k.c2[:])
	k.valid = false
}
