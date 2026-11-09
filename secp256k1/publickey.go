// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

// Package secp256k1 validates and serializes SEC 1 public keys for the
// secp256k1 curve used by the SILA protocol.
//
// This package currently handles PUBLIC data only. Its math/big operations
// are not constant time. Do not pass private scalars or other secrets to it.
package secp256k1

import (
	"errors"
	"math/big"
)

// ErrInvalidPublicKey denotes an unsupported encoding or a point that is not
// on the specified elliptic curve.
var ErrInvalidPublicKey = errors.New("sila/secp256k1: invalid public key")

const primeHex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"

var fieldPrime = func() *big.Int {
	p, ok := new(big.Int).SetString(primeHex, 16)
	if !ok {
		panic("sila/secp256k1: invalid field modulus")
	}
	return p
}()

var sqrtExponent = func() *big.Int {
	// For this field p mod 4 = 3, so sqrt(a) = a^((p+1)/4) mod p.
	exp := new(big.Int).Add(fieldPrime, big.NewInt(1))
	return exp.Rsh(exp, 2)
}()

// PublicKey is an immutable, validated affine point. Its zero value is
// invalid and cannot be serialized. Coordinates are always 32-byte big-endian.
// There is intentionally no secret scalar or signing API in this package.
type PublicKey struct {
	x, y  [32]byte
	valid bool
}

// ParsePublicKey accepts SEC 1 compressed (33-byte, 0x02/0x03 prefix) and
// uncompressed (65-byte, 0x04 prefix) public keys. It rejects infinity,
// hybrid encodings, noncanonical coordinates and points outside secp256k1.
func ParsePublicKey(data []byte) (PublicKey, error) {
	var out PublicKey

	switch {
	case len(data) == 33 && (data[0] == 0x02 || data[0] == 0x03):
		x := new(big.Int).SetBytes(data[1:])
		if x.Cmp(fieldPrime) >= 0 {
			return out, ErrInvalidPublicKey
		}

		// Solve y^2 = x^3 + 7 mod p, and verify a root actually exists.
		rhs := curveRHS(x)
		y := new(big.Int).Exp(rhs, sqrtExponent, fieldPrime)
		y2 := new(big.Int).Mul(y, y)
		y2.Mod(y2, fieldPrime)
		if y2.Cmp(rhs) != 0 {
			return out, ErrInvalidPublicKey
		}

		wantParity := uint(data[0] & 1)
		if y.Bit(0) != wantParity {
			y.Sub(fieldPrime, y)
		}
		if y.Bit(0) != wantParity || y.Cmp(fieldPrime) >= 0 {
			return out, ErrInvalidPublicKey
		}

		copy(out.x[:], data[1:])
		y.FillBytes(out.y[:])

	case len(data) == 65 && data[0] == 0x04:
		x := new(big.Int).SetBytes(data[1:33])
		y := new(big.Int).SetBytes(data[33:65])
		if x.Cmp(fieldPrime) >= 0 || y.Cmp(fieldPrime) >= 0 {
			return out, ErrInvalidPublicKey
		}
		y2 := new(big.Int).Mul(y, y)
		y2.Mod(y2, fieldPrime)
		if y2.Cmp(curveRHS(x)) != 0 {
			return out, ErrInvalidPublicKey
		}

		copy(out.x[:], data[1:33])
		copy(out.y[:], data[33:65])

	default:
		return out, ErrInvalidPublicKey
	}
	out.valid = true
	return out, nil
}

func curveRHS(x *big.Int) *big.Int {
	rhs := new(big.Int).Mul(x, x)
	rhs.Mul(rhs, x)
	rhs.Add(rhs, big.NewInt(7))
	return rhs.Mod(rhs, fieldPrime)
}

// Compressed returns the canonical 33-byte SEC 1 representation of a key.
func (k PublicKey) Compressed() ([33]byte, error) {
	var result [33]byte
	if !k.valid {
		return result, ErrInvalidPublicKey
	}
	result[0] = 0x02 | (k.y[31] & 1)
	copy(result[1:], k.x[:])
	return result, nil
}

// Uncompressed returns the canonical 65-byte SEC 1 representation of a key.
func (k PublicKey) Uncompressed() ([65]byte, error) {
	var result [65]byte
	if !k.valid {
		return result, ErrInvalidPublicKey
	}
	result[0] = 0x04
	copy(result[1:33], k.x[:])
	copy(result[33:65], k.y[:])
	return result, nil
}

// Coordinates returns a COPY of the validated public coordinates, not
// mutable internal big.Int references.
func (k PublicKey) Coordinates() ([32]byte, [32]byte, error) {
	if !k.valid {
		return [32]byte{}, [32]byte{}, ErrInvalidPublicKey
	}
	return k.x, k.y, nil
}
