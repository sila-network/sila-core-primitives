// SPDX-License-Identifier: Apache-2.0

package main

import "fmt"

// Lane complementing (Bertoni et al., "Keccak implementation overview",
// §2.2) stores a fixed subset of lanes inverted so that most χ NOT
// operations disappear. Instead of transcribing formulas, SILA's generator
// searches for each output lane the cheapest boolean form that is exactly
// equivalent to χ under the current complement masks, verified on the full
// truth table.

// complemented is the set of lanes stored inverted between rounds.
var complemented = map[int]bool{
	laneIndex(1, 0): true, laneIndex(2, 0): true, laneIndex(3, 1): true,
	laneIndex(2, 2): true, laneIndex(2, 3): true, laneIndex(0, 4): true,
}

// chiForm describes  out = s0 ^ OP(n1?~s1:s1, n2?~s2:s2), optionally inverted.
type chiForm struct {
	or       bool // OP is OR instead of AND
	n1, n2   bool // invert operand
	notOut   bool // invert the result
	notCount int
}

// findChi returns the cheapest form computing the stored output lane
// (true value e = b0 ^ (^b1 & b2), stored as e ^ mOut) from stored inputs
// s_i = b_i ^ m_i.
func findChi(m0, m1, m2, mOut bool) chiForm {
	best := chiForm{notCount: 99}
	for _, or := range []bool{false, true} {
		for _, n1 := range []bool{false, true} {
			for _, n2 := range []bool{false, true} {
				for _, notOut := range []bool{false, true} {
					f := chiForm{or, n1, n2, notOut, b2i(n1) + b2i(n2) + b2i(notOut)}
					if f.notCount < best.notCount && f.matches(m0, m1, m2, mOut) {
						best = f
					}
				}
			}
		}
	}
	if best.notCount == 99 {
		panic("no χ form found")
	}
	return best
}

func (f chiForm) matches(m0, m1, m2, mOut bool) bool {
	for v := 0; v < 8; v++ {
		b0, b1, b2 := v&1 != 0, v&2 != 0, v&4 != 0
		want := (b0 != (!b1 && b2)) != mOut
		s0, s1, s2 := b0 != m0, b1 != m1, b2 != m2
		l1, l2 := s1 != f.n1, s2 != f.n2
		var op bool
		if f.or {
			op = l1 || l2
		} else {
			op = l1 && l2
		}
		if got := (s0 != op) != f.notOut; got != want {
			return false
		}
	}
	return true
}

// expr renders the form in Go syntax over operand expressions.
func (f chiForm) expr(s0, s1, s2 string) string {
	neg := func(n bool, s string) string {
		if n {
			return "^" + s
		}
		return s
	}
	op := "&"
	if f.or {
		op = "|"
	}
	e := fmt.Sprintf("%s ^ (%s %s %s)", s0, neg(f.n1, s1), op, neg(f.n2, s2))
	if f.notOut {
		e = "^(" + e + ")"
	}
	return e
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// roundMasks computes, for a state stored with mask `complemented`,
// the complement mask of every ρ∘π output lane B[X,Y] after θ.
func roundMasks() (bMask [25]bool) {
	var cMask, dMask [5]bool
	for x := 0; x < 5; x++ {
		for y := 0; y < 5; y++ {
			cMask[x] = cMask[x] != complemented[laneIndex(x, y)]
		}
	}
	for x := 0; x < 5; x++ {
		dMask[x] = cMask[mod5(x-1)] != cMask[mod5(x+1)]
	}
	for X := 0; X < 5; X++ {
		for Y := 0; Y < 5; Y++ {
			x, y := piSource(X, Y)
			bMask[laneIndex(X, Y)] = complemented[laneIndex(x, y)] != dMask[x]
		}
	}
	return bMask
}
