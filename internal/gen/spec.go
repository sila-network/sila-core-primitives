// SPDX-License-Identifier: Apache-2.0

// Command gen derives the Keccak-f[1600] step constants from the published
// mathematical specification (FIPS 202 §3.2, Keccak reference §1.2) and emits
// the SILA permutation code. Nothing here is taken from another
// implementation: every constant is recomputed from its defining formula.
package main

// laneIndex maps coordinates (x, y) to the flat lane index used by SILA.
func laneIndex(x, y int) int { return mod5(x) + 5*mod5(y) }

func mod5(v int) int { return ((v % 5) + 5) % 5 }

// rhoOffsets computes the ρ rotation amounts with the specification's
// walk: start at (1,0), offset (t+1)(t+2)/2 mod 64, step (x,y)->(y,2x+3y).
func rhoOffsets() [25]int {
	var r [25]int
	x, y := 1, 0
	for t := 0; t < 24; t++ {
		r[laneIndex(x, y)] = ((t + 1) * (t + 2) / 2) % 64
		x, y = y, mod5(2*x+3*y)
	}
	return r
}

// rcBit is the degree-8 LFSR rc(t) from the specification
// (polynomial x^8 + x^6 + x^5 + x^4 + 1).
func rcBit(t int) uint64 {
	if t%255 == 0 {
		return 1
	}
	r := uint16(1)
	for i := 1; i <= t%255; i++ {
		r <<= 1
		if r&0x100 != 0 {
			r ^= 0x171
		}
	}
	return uint64(r & 1)
}

// roundConstants computes RC[i] for the 24 rounds of Keccak-f[1600].
func roundConstants() [24]uint64 {
	var rc [24]uint64
	for i := 0; i < 24; i++ {
		for j := 0; j <= 6; j++ {
			rc[i] |= rcBit(j+7*i) << ((1 << j) - 1)
		}
	}
	return rc
}

// piSource returns, for the lane at output position (X, Y) after ρ∘π,
// the input lane (x, y) it came from. π moves (x,y) to (y, 2x+3y), so the
// inverse is x = X+3Y, y = X (mod 5).
func piSource(X, Y int) (x, y int) { return mod5(X + 3*Y), X }
