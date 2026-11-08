// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"testing"
)

// FIPS 202 Table 2 (ρ offsets), indexed x + 5y.
var fips202Rho = [25]int{
	0, 1, 62, 28, 27,
	36, 44, 6, 55, 20,
	3, 10, 43, 25, 39,
	41, 45, 15, 21, 8,
	18, 2, 61, 56, 14,
}

func TestRhoMatchesFIPS202(t *testing.T) {
	if got := rhoOffsets(); got != fips202Rho {
		t.Fatalf("rho offsets %v", got)
	}
}

func TestRoundConstantsSpotCheck(t *testing.T) {
	rc := roundConstants()
	// RC[0], RC[1], RC[23] as printed in the Keccak reference.
	if rc[0] != 0x0000000000000001 || rc[1] != 0x0000000000008082 || rc[23] != 0x8000000080008008 {
		t.Fatalf("round constants %x", rc)
	}
}

// The χ forms chosen under lane complementing must be exact on every input.
func TestChiFormsExact(t *testing.T) {
	m := roundMasks()
	for Y := 0; Y < 5; Y++ {
		for X := 0; X < 5; X++ {
			f := findChi(m[laneIndex(X, Y)], m[laneIndex(X+1, Y)], m[laneIndex(X+2, Y)], complemented[laneIndex(X, Y)])
			if !f.matches(m[laneIndex(X, Y)], m[laneIndex(X+1, Y)], m[laneIndex(X+2, Y)], complemented[laneIndex(X, Y)]) {
				t.Fatal("inexact χ form")
			}
		}
	}
}

// Generated sources in ../../keccak must match the generator exactly.
func TestGeneratedFilesUpToDate(t *testing.T) {
	for file, gen := range map[string]func() []byte{
		"../../keccak/keccakf_generic.go":     genGo,
		"../../keccak/keccakf_avx512_amd64.s": genAsm,
	} {
		disk, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(disk, gen()) {
			t.Errorf("%s is stale: run go generate ./keccak", file)
		}
	}
}
