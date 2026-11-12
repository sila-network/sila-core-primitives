// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

// Package account derives 20-byte account addresses from secp256k1 public
// keys.
//
// The derivation is:
//
//	address = last 20 bytes of Keccak-256(X || Y)
//
// where X || Y is the 64-byte uncompressed public key without the 0x04
// prefix, and Keccak-256 is the SILA implementation (package keccak).
// Compatibility evidence is recorded in docs/SECP256K1-PARITY.md.
//
// The package defines only this byte-level derivation. A textual address
// format (prefix, checksum) for SILA is a protocol decision that is not
// defined here.
package account

import (
	"errors"

	"github.com/sila-network/sila-core-primitives/keccak"
	"github.com/sila-network/sila-core-primitives/secp256k1"
)

// AddressSize is the size of an account address in bytes.
const AddressSize = 20

// Address is a 20-byte account address.
type Address [AddressSize]byte

// ErrInvalidPublicKey is returned for a zero-value or invalid public key.
var ErrInvalidPublicKey = errors.New("sila/account: invalid public key")

// FromPublicKey returns the last 20 bytes of Keccak-256(X || Y) of pub.
func FromPublicKey(pub secp256k1.PublicKey) (Address, error) {
	u, err := pub.Uncompressed()
	if err != nil {
		return Address{}, ErrInvalidPublicKey
	}
	h := keccak.Sum256(u[1:])
	var a Address
	copy(a[:], h[32-AddressSize:])
	return a, nil
}
