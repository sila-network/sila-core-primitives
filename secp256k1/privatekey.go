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

// setShares stores the canonical value d (< n) as random shares. The
// shares are formed in the canonical domain with a modular subtraction
// (no multiplication involves d); each share is then converted to
// Montgomery form, which multiplies only uniformly random values.
func (k *PrivateKey) setShares(d *limbs) {
	var m limbs
	var mb [32]byte
	if _, err := io.ReadFull(rand.Reader, mb[:]); err == nil {
		m = limbsFromBytes(&mb)
		scalarN.reduceOnce(&m, &m, 0) // any 256-bit value is < 2n
	} else {
		// No randomness: derive the mask from d itself (secret, pseudo-random).
		var db [32]byte
		limbsToBytes(&db, d)
		h := hmacSHA256(&db, []byte("SILA-secp256k1-key-mask"))
		m = limbsFromBytes(&h)
		scalarN.reduceOnce(&m, &m, 0)
		clear(db[:])
		clear(h[:])
	}
	clear(mb[:])
	var r limbs
	scalarN.sub(&r, d, &m) // d2 = d - d1 mod n
	scalarN.toMont(&k.d1.v, &m)
	scalarN.toMont(&k.d2.v, &r)
	clear(m[:])
	clear(r[:])
}

// canonicalD returns d = d1 + d2 mod n in canonical limbs: each share is
// converted out of Montgomery form (multiplying random values), and the
// shares are added (an addition, not a multiplication, produces d).
func (k *PrivateKey) canonicalD() limbs {
	a, b := k.d1.canonical(), k.d2.canonical()
	var d limbs
	scalarN.add(&d, &a, &b)
	clear(a[:])
	clear(b[:])
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
			return derivedBlinding(&seed, 'P', true)
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
	k.valid = false
}
