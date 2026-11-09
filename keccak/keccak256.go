// SPDX-License-Identifier: Apache-2.0

// Package keccak implements the Keccak-256 sponge for SILA Core Primitives.
//
// This package uses the original Keccak domain suffix (0x01), not the
// standardized SHA3-256 suffix (0x06), so its output is identical to the
// Keccak-256 used by Ethereum. It has no external dependencies.
//
// It is a reference implementation. Production adoption requires an
// independent cryptographic review.
package keccak

import (
	"encoding/binary"
	"hash"
)

const (
	// Size is the number of bytes in a Keccak-256 digest.
	Size = 32
	// Rate is the Keccak-256 absorption block size in bytes.
	Rate = 136
)

// Digest implements hash.Hash with Keccak-256 padding and 24-round Keccak-f[1600].
// A Digest should not be used concurrently by multiple goroutines.
//
// Invariant: 0 <= used < Rate and pending[used:] is all zero.
type Digest struct {
	lanes   [25]uint64
	pending [Rate]byte
	used    int
}

var _ hash.Hash = (*Digest)(nil)

// New returns a streaming Keccak-256 hasher.
func New() hash.Hash { return &Digest{} }

// Sum256 computes Keccak-256 for the supplied bytes without retaining state.
// It does not allocate and does not modify data.
func Sum256(data []byte) (out [Size]byte) {
	var a [25]uint64
	full := len(data) - len(data)%Rate
	absorb(&a, data[:full])
	data = data[full:]
	var last [Rate]byte
	n := copy(last[:], data)
	pad(&last, n)
	absorb(&a, last[:])
	squeeze(&out, &a)
	return out
}

// Write absorbs data in order. It never returns a non-nil error.
func (d *Digest) Write(data []byte) (int, error) {
	total := len(data)

	// Complete any partial block first.
	if d.used != 0 {
		n := copy(d.pending[d.used:], data)
		d.used += n
		data = data[n:]
		if d.used < Rate {
			return total, nil
		}
		absorb(&d.lanes, d.pending[:])
		d.used = 0
		clear(d.pending[:])
	}

	// Full blocks are absorbed directly from the caller's slice.
	full := len(data) - len(data)%Rate
	absorb(&d.lanes, data[:full])
	data = data[full:]
	d.used = copy(d.pending[:], data)
	return total, nil
}

// Sum appends the digest to b without changing the running hash state.
func (d *Digest) Sum(b []byte) []byte {
	var out [Size]byte
	d.sum(&out)
	return append(b, out[:]...)
}

// sum finalizes a copy of the state; d itself is not modified.
func (d *Digest) sum(out *[Size]byte) {
	a := d.lanes
	last := d.pending
	pad(&last, d.used)
	absorb(&a, last[:])
	squeeze(out, &a)
}

// Reset clears the entire state so a Digest can be reused.
func (d *Digest) Reset() { *d = Digest{} }

// Size returns the digest length in bytes.
func (d *Digest) Size() int { return Size }

// BlockSize returns the Keccak-256 absorption rate in bytes.
func (d *Digest) BlockSize() int { return Rate }

// pad applies pad10*1 with Keccak's legacy 0x01 domain suffix to a block
// holding n < Rate message bytes followed by zeros. When n == Rate-1 both
// markers land in the same byte (0x81).
func pad(b *[Rate]byte, n int) {
	b[n] ^= 0x01
	b[Rate-1] ^= 0x80
}

// xorBlock XORs one rate-sized block into the first 17 lanes (little-endian).
func xorBlock(a *[25]uint64, b *[Rate]byte) {
	a[0] ^= binary.LittleEndian.Uint64(b[0:])
	a[1] ^= binary.LittleEndian.Uint64(b[8:])
	a[2] ^= binary.LittleEndian.Uint64(b[16:])
	a[3] ^= binary.LittleEndian.Uint64(b[24:])
	a[4] ^= binary.LittleEndian.Uint64(b[32:])
	a[5] ^= binary.LittleEndian.Uint64(b[40:])
	a[6] ^= binary.LittleEndian.Uint64(b[48:])
	a[7] ^= binary.LittleEndian.Uint64(b[56:])
	a[8] ^= binary.LittleEndian.Uint64(b[64:])
	a[9] ^= binary.LittleEndian.Uint64(b[72:])
	a[10] ^= binary.LittleEndian.Uint64(b[80:])
	a[11] ^= binary.LittleEndian.Uint64(b[88:])
	a[12] ^= binary.LittleEndian.Uint64(b[96:])
	a[13] ^= binary.LittleEndian.Uint64(b[104:])
	a[14] ^= binary.LittleEndian.Uint64(b[112:])
	a[15] ^= binary.LittleEndian.Uint64(b[120:])
	a[16] ^= binary.LittleEndian.Uint64(b[128:])
}

// absorbGeneric is the portable absorb loop.
func absorbGeneric(a *[25]uint64, data []byte) {
	for len(data) >= Rate {
		xorBlock(a, (*[Rate]byte)(data))
		permuteGeneric(a)
		data = data[Rate:]
	}
}

// squeeze writes the first 32 bytes of the state (little-endian lanes).
func squeeze(out *[Size]byte, a *[25]uint64) {
	binary.LittleEndian.PutUint64(out[0:], a[0])
	binary.LittleEndian.PutUint64(out[8:], a[1])
	binary.LittleEndian.PutUint64(out[16:], a[2])
	binary.LittleEndian.PutUint64(out[24:], a[3])
}
