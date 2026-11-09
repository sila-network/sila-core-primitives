// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

import "errors"

// ErrInvalidPublicKey denotes an unsupported encoding or a point that is not
// on the specified elliptic curve.
var ErrInvalidPublicKey = errors.New("sila/secp256k1: invalid public key")

// PublicKey is an immutable, validated affine point other than the point at
// infinity. Its zero value is invalid and cannot be serialized.
// Coordinates are always 32-byte big-endian.
type PublicKey struct {
	x, y  [32]byte
	valid bool
}

// ParsePublicKey accepts SEC 1 compressed (33-byte, 0x02/0x03 prefix) and
// uncompressed (65-byte, 0x04 prefix) public keys. It rejects infinity,
// hybrid encodings, noncanonical coordinates and points outside secp256k1.
// secp256k1 has prime order and cofactor 1, so every point on the curve
// other than infinity is in the prime-order subgroup.
//
// Inputs are public; validity decisions may branch.
func ParsePublicKey(data []byte) (PublicKey, error) {
	var out PublicKey
	var x, y fieldElement
	switch {
	case len(data) == 33 && (data[0] == 0x02 || data[0] == 0x03):
		if x.setBytes((*[32]byte)(data[1:33])) != 1 {
			return out, ErrInvalidPublicKey
		}
		if !liftX(&y, &x, uint64(data[0]&1)) {
			return out, ErrInvalidPublicKey
		}
	case len(data) == 65 && data[0] == 0x04:
		if x.setBytes((*[32]byte)(data[1:33]))&y.setBytes((*[32]byte)(data[33:65])) != 1 {
			return out, ErrInvalidPublicKey
		}
		if isOnCurve(&x, &y) != 1 {
			return out, ErrInvalidPublicKey
		}
	default:
		return out, ErrInvalidPublicKey
	}
	out.x = x.bytes()
	out.y = y.bytes()
	out.valid = true
	return out, nil
}

// liftX solves y^2 = x^3 + 7 for y with the requested parity. It returns
// false if x is not the x-coordinate of a curve point.
func liftX(y, x *fieldElement, oddY uint64) bool {
	var rhs fieldElement
	rhs.square(x)
	rhs.mul(&rhs, x)
	rhs.add(&rhs, &curveB)
	if y.sqrt(&rhs) != 1 {
		return false
	}
	var negY fieldElement
	negY.neg(y)
	y.selectFrom(&negY, y, y.isOdd()^oddY)
	return y.isOdd() == oddY
}

// publicKeyFromPoint converts a group element into a PublicKey, rejecting
// the point at infinity.
func publicKeyFromPoint(p *point) (PublicKey, error) {
	var out PublicKey
	x, y, ok := p.affine()
	if ok != 1 {
		return out, ErrInvalidPublicKey
	}
	out.x = x.bytes()
	out.y = y.bytes()
	out.valid = true
	return out, nil
}

// point returns the key as a projective point (Z = 1).
func (k *PublicKey) point() point {
	var x, y fieldElement
	x.setBytes(&k.x)
	y.setBytes(&k.y)
	var p point
	p.setAffine(&x, &y)
	return p
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

// Coordinates returns copies of the validated affine coordinates.
func (k PublicKey) Coordinates() ([32]byte, [32]byte, error) {
	if !k.valid {
		return [32]byte{}, [32]byte{}, ErrInvalidPublicKey
	}
	return k.x, k.y, nil
}

// Equal reports whether two keys are the same valid point.
func (k PublicKey) Equal(other PublicKey) bool {
	return k.valid && other.valid && k.x == other.x && k.y == other.y
}
