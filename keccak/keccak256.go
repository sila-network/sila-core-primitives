// Package keccak implements the Keccak-256 sponge for SILA Core Primitives.
//
// This package uses the original Keccak domain suffix (0x01), not the
// standardized SHA3-256 suffix (0x06). It has no external dependencies.
//
// It is a reference implementation. Production adoption requires an
// independent cryptographic review and implementation hardening.
package keccak

import (
	"encoding/binary"
	"hash"
	"math/bits"
)

const (
	// Size is the number of bytes in a Keccak-256 digest.
	Size = 32
	// Rate is the Keccak-256 absorption block size in bytes.
	Rate = 136
)

// Digest implements hash.Hash with Keccak-256 padding and 24-round Keccak-f[1600].
// A Digest should not be used concurrently by multiple goroutines.
type Digest struct {
	lanes   [25]uint64
	pending [Rate]byte
	used    int
}

var _ hash.Hash = (*Digest)(nil)

// New returns a streaming Keccak-256 hasher.
func New() hash.Hash { return &Digest{} }

// Sum256 computes Keccak-256 for the supplied bytes without retaining state.
func Sum256(data []byte) [Size]byte {
	var d Digest
	_, _ = d.Write(data)
	return d.finalize()
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
		if d.used == Rate {
			absorb(&d.lanes, d.pending[:])
			d.used = 0
			clear(d.pending[:])
		}
	}

	// Full blocks can be absorbed directly from the input.
	for len(data) >= Rate {
		absorb(&d.lanes, data[:Rate])
		data = data[Rate:]
	}
	d.used = copy(d.pending[:], data)
	return total, nil
}

// Sum appends the digest to b without changing the running hash state.
func (d *Digest) Sum(b []byte) []byte {
	copyOfDigest := *d
	result := copyOfDigest.finalize()
	return append(b, result[:]...)
}

// Reset clears the entire state so a Digest can be reused.
func (d *Digest) Reset() { *d = Digest{} }

// Size returns the digest length in bytes.
func (d *Digest) Size() int { return Size }

// BlockSize returns the Keccak-256 absorption rate in bytes.
func (d *Digest) BlockSize() int { return Rate }

func (d *Digest) finalize() [Size]byte {
	// pad10*1 with Keccak's legacy 0x01 suffix.
	// A full tail is already absorbed by Write, leaving used < Rate.
	d.pending[d.used] ^= 0x01
	d.pending[Rate-1] ^= 0x80
	absorb(&d.lanes, d.pending[:])
	var out [Size]byte
	for i := 0; i < Size/8; i++ {
		binary.LittleEndian.PutUint64(out[i*8:], d.lanes[i])
	}
	return out
}

func absorb(a *[25]uint64, block []byte) {
	for lane := 0; lane < Rate/8; lane++ {
		a[lane] ^= binary.LittleEndian.Uint64(block[lane*8:])
	}
	permute(a)
}

var rotation = [25]int{
	0, 1, 62, 28, 27,
	36, 44, 6, 55, 20,
	3, 10, 43, 25, 39,
	41, 45, 15, 21, 8,
	18, 2, 61, 56, 14,
}

var roundConstant = [24]uint64{
	0x0000000000000001, 0x0000000000008082,
	0x800000000000808a, 0x8000000080008000,
	0x000000000000808b, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009,
	0x000000000000008a, 0x0000000000000088,
	0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b,
	0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080,
	0x000000000000800a, 0x800000008000000a,
	0x8000000080008081, 0x8000000000008080,
	0x0000000080000001, 0x8000000080008008,
}

// permute applies all 24 rounds of Keccak-f[1600].
// State lane index is x + 5*y; each lane is little-endian.
func permute(a *[25]uint64) {
	var c, d [5]uint64
	var b [25]uint64
	for _, rc := range roundConstant {
		// Theta: mix neighboring columns.
		for x := 0; x < 5; x++ {
			c[x] = a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20]
		}
		for x := 0; x < 5; x++ {
			d[x] = c[(x+4)%5] ^ bits.RotateLeft64(c[(x+1)%5], 1)
		}
		for y := 0; y < 5; y++ {
			for x := 0; x < 5; x++ {
				a[x+5*y] ^= d[x]
			}
		}

		// Rho and Pi: rotate lanes and permute their coordinates.
		for y := 0; y < 5; y++ {
			for x := 0; x < 5; x++ {
				src := x + 5*y
				dst := y + 5*((2*x+3*y)%5)
				b[dst] = bits.RotateLeft64(a[src], rotation[src])
			}
		}

		// Chi: non-linear row substitution.
		for y := 0; y < 5; y++ {
			for x := 0; x < 5; x++ {
				a[x+5*y] = b[x+5*y] ^ (^b[(x+1)%5+5*y] & b[(x+2)%5+5*y])
			}
		}

		// Iota: inject the round constant into the first lane.
		a[0] ^= rc
	}
}
