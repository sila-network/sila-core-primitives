// SPDX-License-Identifier: Apache-2.0

package keccak

import "math/bits"

// permuteReference is the original V1 loop-based Keccak-f[1600]. It is kept
// only as an independent oracle for the optimized permutations.
// State lane index is x + 5*y; each lane is little-endian.
var referenceRotation = [25]int{
	0, 1, 62, 28, 27,
	36, 44, 6, 55, 20,
	3, 10, 43, 25, 39,
	41, 45, 15, 21, 8,
	18, 2, 61, 56, 14,
}

func permuteReference(a *[25]uint64) {
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
				b[dst] = bits.RotateLeft64(a[src], referenceRotation[src])
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

// referenceSum is a deliberately naive Keccak-256 sponge built only from
// permuteReference: it pads a copy of the whole message byte by byte and
// shares no code with the optimized sponge (xorBlock, absorb, pad, squeeze).
func referenceSum(msg []byte) [32]byte {
	m := append([]byte(nil), msg...)
	m = append(m, 0x01)
	for len(m)%Rate != 0 {
		m = append(m, 0x00)
	}
	m[len(m)-1] |= 0x80
	var a [25]uint64
	for off := 0; off < len(m); off += Rate {
		for i := 0; i < Rate; i++ {
			a[i/8] ^= uint64(m[off+i]) << (8 * (i % 8))
		}
		permuteReference(&a)
	}
	var out [32]byte
	for i := range out {
		out[i] = byte(a[i/8] >> (8 * (i % 8)))
	}
	return out
}
