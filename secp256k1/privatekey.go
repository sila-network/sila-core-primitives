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
type PrivateKey struct {
	d     scalar
	valid bool
}

// ParsePrivateKey decodes a 32-byte big-endian scalar. It rejects zero,
// values >= n and any other length. The range check is constant time; only
// the final accept/reject decision is observable.
func ParsePrivateKey(b []byte) (*PrivateKey, error) {
	if len(b) != PrivateKeySize {
		return nil, ErrInvalidPrivateKey
	}
	k := new(PrivateKey)
	ok := k.d.setBytesCanonical((*[32]byte)(b))
	ok &= 1 ^ k.d.isZero()
	if ok != 1 {
		k.d.zero()
		return nil, ErrInvalidPrivateKey
	}
	k.valid = true
	return k, nil
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
	return k.d.bytes(), nil
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
		p.scalarBaseMultBlinded(&k.d, func() (scalar, point) {
			seed := k.d.bytes()
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
	k.d.zero()
	k.valid = false
}
