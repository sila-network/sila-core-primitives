// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

// Side-channel blinding for the secret-dependent computations (finding
// S-8 in docs/SECP256K1-SECURITY-REVIEW.md).
//
// The constant-time code has no secret-dependent branch or memory access
// (checked on the compiled code), but processors may still take slightly
// different time depending on the operand VALUES (data-dependent
// instruction timing, which Arm only rules out under PSTATE.DIT and x86
// only under DOIT). Blinding makes the operands that reach the arithmetic
// statistically independent of the secret, whatever the processor does:
//
//   - k·G (and d·G) is computed as (k + b)·G + (−b·G) for a secret,
//     uniformly random b: the digits processed by the fixed-base
//     multiplication are those of k + b, which is uniform for every k.
//     b and −b·G are generated once from crypto/rand (lazily, like a
//     randomized context in other libraries) and can be refreshed with
//     RefreshBlinding.
//   - the nonce is created as shares k = k1 + k2 (canonical domain, no
//     multiplication); k⁻¹·e is computed as (k1·ρ + k2·ρ)⁻¹·(ρ·e) for a
//     per-signature secret ρ derived from the RFC 6979 state, so neither k
//     nor k⁻¹ is ever a multiplication operand;
//   - the private key is stored as shares d = d1 + d2 (privatekey.go).
//
// Neither changes any result: (k + b)·G − b·G = k·G and (k·ρ)⁻¹·ρ = k⁻¹,
// so signatures stay byte-identical to deterministic RFC 6979.

import (
	cryptorand "crypto/rand"
	"errors"
	"io"
	"sync/atomic"
)

// baseBlinding holds a secret scalar b and the point −b·G.
type baseBlinding struct {
	b    scalar
	negB point
}

var blindingState atomic.Pointer[baseBlinding]

// randomSource is the randomness used for the process-wide blinding and
// for private-key masks. It is crypto/rand.Reader; tests replace it to
// exercise the failure paths.
var randomSource io.Reader = cryptorand.Reader

// maxBlindingDraws bounds the rejection sampling in newBaseBlinding: a
// healthy source needs more than one draw with probability about 2^-128,
// so hitting the bound means the source is broken (for example it returns
// only zeros) and an error is better than looping forever.
const maxBlindingDraws = 64

// newBaseBlinding draws b uniformly from [1, n-1] by rejection sampling
// and computes −b·G (constant time).
func newBaseBlinding(rand io.Reader) (*baseBlinding, error) {
	var buf [32]byte
	defer clear(buf[:])
	bl := new(baseBlinding)
	for i := 0; ; i++ {
		if i == maxBlindingDraws {
			return nil, errBadRandomness
		}
		if _, err := io.ReadFull(rand, buf[:]); err != nil {
			return nil, err
		}
		if bl.b.setBytesCanonical(&buf)&(1^bl.b.isZero()) == 1 {
			break
		}
	}
	var bG point
	bG.scalarBaseMult(&bl.b)
	bl.negB.neg(&bG)
	return bl, nil
}

var errBadRandomness = errors.New("sila/secp256k1: random source produced no valid blinding value")

// RefreshBlinding replaces the secret blinding value used by signing and
// public-key derivation with a fresh one read from rand
// (crypto/rand.Reader when rand is nil). It never changes any result.
// Long-running signers may call it periodically (it costs one fixed-base
// multiplication); it is safe for concurrent use. rand must be a
// cryptographically secure source: a predictable value would void the
// protection (never correctness). On error the current blinding is kept.
func RefreshBlinding(rand io.Reader) error {
	if rand == nil {
		rand = randomSource
	}
	bl, err := newBaseBlinding(rand)
	if err != nil {
		return err
	}
	blindingState.Store(bl)
	return nil
}

// currentBlinding returns the process-wide blinding, creating it from the
// random source on first use. If the source fails, it returns nil and the
// caller uses a per-call blinding derived from its own secret (never an
// unblinded computation); creation is attempted again on the next call,
// so a transient failure does not disable the process-wide blinding.
func currentBlinding() *baseBlinding {
	if bl := blindingState.Load(); bl != nil {
		return bl
	}
	if bl, err := newBaseBlinding(randomSource); err == nil {
		blindingState.CompareAndSwap(nil, bl)
	}
	return blindingState.Load()
}

// scalarBaseMultBlinded sets r = k·G, computing (k + b)·G + (−b·G) with
// the process-wide blinding, or with fallback (b, −b·G) when no
// process-wide blinding exists. Constant time with respect to k and b.
func (r *point) scalarBaseMultBlinded(k *scalar, fallback func() (scalar, point)) *point {
	var b scalar
	var negB point
	if bl := currentBlinding(); bl != nil {
		b, negB = bl.b, bl.negB
	} else {
		b, negB = fallback()
	}
	r.scalarBaseMultWith(k, &b, &negB)
	b.zero()
	return r
}

// scalarBaseMultShares sets r = (s1 + s2)·G for a secret given as two
// shares, computing ((s1 + b) + s2)·G + (−b·G): no intermediate value
// equals the secret (constant time).
func (r *point) scalarBaseMultShares(s1, s2 *scalar, fallback func() (scalar, point)) *point {
	var b scalar
	var negB point
	if bl := currentBlinding(); bl != nil {
		b, negB = bl.b, bl.negB
	} else {
		b, negB = fallback()
	}
	var t scalar
	t.add(s1, &b)
	r.scalarBaseMultWith(s2, &t, &negB)
	t.zero()
	b.zero()
	return r
}

// scalarBaseMultWith sets r = (k + b)·G + negB, which is k·G when
// negB = −b·G (constant time; complete formulas, so k + b = 0 is fine).
func (r *point) scalarBaseMultWith(k, b *scalar, negB *point) *point {
	var kb scalar
	kb.add(k, b)
	r.scalarBaseMult(&kb)
	r.add(r, negB)
	kb.zero()
	return r
}

// invMaskedShares sets z = (k·rho)⁻¹ for a secret k given as shares
// k = k1 + k2 and a secret, non-zero rho: it computes t = k1·rho + k2·rho
// (multiplications of pseudo-random shares) and inverts t, which is
// uniformly distributed for every k. k itself is never a multiplication
// operand. Multiplying the result by rho gives k⁻¹ (constant time).
func (z *scalar) invMaskedShares(k1, k2, rho *scalar) *scalar {
	var t, u scalar
	t.mul(k1, rho)
	u.mul(k2, rho)
	t.add(&t, &u)
	z.inv(&t)
	t.zero()
	u.zero()
	return z
}

// derivedMaskLimbs returns a secret mask in [0, n), canonical limbs,
// derived from a 32-byte secret seed with a domain-separated HMAC-SHA-256
// (no multiplication).
func derivedMaskLimbs(seed *[32]byte, label byte) limbs {
	in := [1]byte{label}
	h := hmacSHA256(seed, []byte("SILA-secp256k1-mask"), in[:])
	m := limbsFromBytes(&h)
	scalarN.reduceOnce(&m, &m, 0) // any 256-bit value is < 2n
	clear(h[:])
	return m
}

// derivedBlinding returns a secret scalar in [1, n-1] and, if withPoint,
// −scalar·G, derived from a 32-byte secret seed with a domain-separated
// HMAC-SHA-256. It is the fallback when crypto/rand is unavailable and the
// source of the per-signature inversion blinding.
func derivedBlinding(seed *[32]byte, label byte, withPoint bool) (scalar, point) {
	var s scalar
	var negP point
	in := [1]byte{label}
	h := hmacSHA256(seed, []byte("SILA-secp256k1-blinding"), in[:])
	for ctr := byte(0); ; ctr++ {
		if s.setBytesCanonical(&h)&(1^s.isZero()) == 1 {
			break
		}
		// Probability about 2^-128: derive again.
		c := [1]byte{ctr}
		h = hmacSHA256(seed, h[:], c[:])
	}
	clear(h[:])
	if withPoint {
		var p point
		p.scalarBaseMult(&s)
		negP.neg(&p)
	}
	return s, negP
}
