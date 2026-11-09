// SPDX-License-Identifier: Apache-2.0

//go:build amd64 && !purego

package keccak

import (
	"math/rand"
	"testing"
)

// The AVX-512 code must be exercised directly, and the portable fallback
// must be exercised on the same machine by temporarily disabling dispatch.
func TestAVX512Kernels(t *testing.T) {
	if !useAVX512 {
		t.Skip("CPU/OS lacks AVX-512F+VL; generic path is used and tested")
	}
	rng := rand.New(rand.NewSource(5))
	for i := 0; i < 5000; i++ {
		var s [25]uint64
		for j := range s {
			s[j] = rng.Uint64()
		}
		ref, got := s, s
		permuteReference(&ref)
		permuteAVX512(&got)
		if got != ref {
			t.Fatalf("permuteAVX512 differs at %d", i)
		}
		// Multi-block absorb vs generic loop.
		n := rng.Intn(5)
		data := make([]byte, n*Rate)
		rng.Read(data)
		a1, a2 := s, s
		if n > 0 {
			absorbAVX512(&a1, &data[0], n)
		}
		absorbGeneric(&a2, data)
		if a1 != a2 {
			t.Fatalf("absorbAVX512 differs at %d (n=%d)", i, n)
		}
	}
}

func TestGenericFallbackOnThisMachine(t *testing.T) {
	saved := useAVX512
	useAVX512 = false
	defer func() { useAVX512 = saved }()
	data := make([]byte, 6*Rate+9)
	rand.New(rand.NewSource(6)).Read(data)
	for n := 0; n <= len(data); n++ {
		if Sum256(data[:n]) != referenceSum(data[:n]) {
			t.Fatalf("fallback mismatch len=%d", n)
		}
	}
}
