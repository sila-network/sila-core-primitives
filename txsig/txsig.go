// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

// Package txsig holds the transaction-layer rules for secp256k1
// signatures, on top of the generic mathematics in package secp256k1.
//
// It defines:
//
//   - Two validation contexts for (r, s, v):
//     Strict (transaction signatures, non-malleable): 1 <= r < n,
//     1 <= s <= (n-1)/2, v in {0, 1};
//     RecoveryCompatible (raw public-key recovery): 1 <= r < n,
//     1 <= s < n, v in {0, 1}.
//     Neither context accepts the mathematically possible v = 2 or 3; only
//     the generic package secp256k1 does.
//   - Recovery-value encodings: the raw value v in {0, 1}; the legacy
//     offset form 27/28; and the chain-bound form v + 35 + 2·chainID.
//     The chain identifier is always a parameter: this package defines
//     no network constants.
//   - The 64-byte compact form with the y-parity in the top bit of s,
//     which is distinct from the generic 64-byte r || s.
//
// These are library formulas, not SILA protocol rules: whether a SILA
// transaction format uses any of them, and with which chain identifier,
// is decided by a SILA specification (docs/SECP256K1-SIGNATURE-CONTRACT.md,
// section 7). The package sets no default network, chain identifier,
// transaction type or domain.
//
// What is hashed and signed (transaction encoding, domain separation,
// chain identifiers) is protocol-level and is not defined here.
// Compatibility evidence against independent implementations is recorded
// in docs/SECP256K1-PARITY.md.
package txsig

import (
	"errors"

	"github.com/sila-network/sila-core-primitives/secp256k1"
)

// Rule selects the validation context for signature values.
type Rule int

const (
	// Strict is the transaction-signature rule: low-S only.
	Strict Rule = iota
	// RecoveryCompatible is the raw-recovery rule: s may be anywhere in
	// [1, n-1].
	RecoveryCompatible
)

var (
	// ErrInvalidSignature denotes signature values rejected by the rule.
	ErrInvalidSignature = errors.New("sila/txsig: invalid signature values")
	// ErrInvalidRecoveryValue denotes an encoded recovery value that does
	// not decode to 0 or 1 under the requested encoding.
	ErrInvalidRecoveryValue = errors.New("sila/txsig: invalid recovery value")
	// ErrInvalidChainID denotes a chain identifier of 0 or one for which
	// the chain-bound value would overflow 64 bits.
	ErrInvalidChainID = errors.New("sila/txsig: invalid chain identifier")
)

// LegacyOffset is added to v in the legacy recovery-value encoding.
const LegacyOffset = 27

// ParseValues validates r, s and v under rule and returns the signature.
// v must be 0 or 1 under both rules.
func ParseValues(r, s [32]byte, v byte, rule Rule) (secp256k1.Signature, error) {
	if v > 1 {
		return secp256k1.Signature{}, ErrInvalidSignature
	}
	var b [secp256k1.RecoverableSignatureSize]byte
	copy(b[:32], r[:])
	copy(b[32:64], s[:])
	b[64] = v
	var sig secp256k1.Signature
	var err error
	switch rule {
	case Strict:
		sig, err = secp256k1.ParseRecoverableSignature(b[:])
	case RecoveryCompatible:
		sig, err = secp256k1.ParseRecoverableSignatureAllowHighS(b[:])
	default:
		return secp256k1.Signature{}, ErrInvalidSignature
	}
	if err != nil {
		return secp256k1.Signature{}, ErrInvalidSignature
	}
	return sig, nil
}

// Parse validates a 65-byte r || s || v signature (v in {0, 1}) under rule.
func Parse(b []byte, rule Rule) (secp256k1.Signature, error) {
	if len(b) != secp256k1.RecoverableSignatureSize {
		return secp256k1.Signature{}, ErrInvalidSignature
	}
	return ParseValues([32]byte(b[:32]), [32]byte(b[32:64]), b[64], rule)
}

// Recover validates r, s, v under rule and recovers the signer's public
// key from digest.
func Recover(digest [secp256k1.DigestSize]byte, r, s [32]byte, v byte, rule Rule) (secp256k1.PublicKey, error) {
	sig, err := ParseValues(r, s, v, rule)
	if err != nil {
		return secp256k1.PublicKey{}, err
	}
	return secp256k1.RecoverPublicKey(digest, sig)
}

// LegacyV returns v + 27 for v in {0, 1}.
func LegacyV(v byte) (byte, error) {
	if v > 1 {
		return 0, ErrInvalidRecoveryValue
	}
	return v + LegacyOffset, nil
}

// FromLegacyV maps 27/28 back to 0/1 and rejects every other value.
func FromLegacyV(value byte) (byte, error) {
	if value != LegacyOffset && value != LegacyOffset+1 {
		return 0, ErrInvalidRecoveryValue
	}
	return value - LegacyOffset, nil
}

// maxChainID is the largest chain identifier for which 2·id + 36 fits in
// 64 bits.
const maxChainID = (1<<64 - 1 - 36) / 2

// ChainV returns the chain-bound recovery value v + 35 + 2·chainID for v in
// {0, 1} and 1 <= chainID <= (2^64 - 38) / 2.
func ChainV(v byte, chainID uint64) (uint64, error) {
	if v > 1 {
		return 0, ErrInvalidRecoveryValue
	}
	if chainID == 0 || chainID > maxChainID {
		return 0, ErrInvalidChainID
	}
	return uint64(v) + 35 + 2*chainID, nil
}

// FromChainV decodes a chain-bound recovery value for the expected
// chainID. Values for any other chain, and legacy 27/28, are rejected.
func FromChainV(value, chainID uint64) (byte, error) {
	if chainID == 0 || chainID > maxChainID {
		return 0, ErrInvalidChainID
	}
	base := 35 + 2*chainID
	if value != base && value != base+1 {
		return 0, ErrInvalidRecoveryValue
	}
	return byte(value - base), nil
}

// CompactYParitySize is the size of the r || (yParity·2^255 | s) form.
const CompactYParitySize = 64

// CompactYParity encodes a low-S signature with recovery value 0 or 1 as
// r || yParityAndS, where yParityAndS = (v << 255) | s. This is
// a different format from the generic 64-byte r || s and must not be
// mixed with it.
func CompactYParity(sig secp256k1.Signature) ([CompactYParitySize]byte, error) {
	var out [CompactYParitySize]byte
	v, ok := sig.RecoveryID()
	if !ok || v > 1 || !sig.IsLowS() {
		return out, ErrInvalidSignature
	}
	r, s := sig.R(), sig.S()
	copy(out[:32], r[:])
	copy(out[32:], s[:])
	out[32] |= v << 7
	return out, nil
}

// ParseCompactYParity decodes r || yParityAndS into a
// recoverable signature. s must be low (the Strict rule): with a high s,
// the top bit could not carry the parity.
func ParseCompactYParity(b []byte) (secp256k1.Signature, error) {
	if len(b) != CompactYParitySize {
		return secp256k1.Signature{}, ErrInvalidSignature
	}
	r := [32]byte(b[:32])
	s := [32]byte(b[32:64])
	v := s[0] >> 7
	s[0] &= 0x7f
	return ParseValues(r, s, v, Strict)
}
