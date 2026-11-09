// SPDX-License-Identifier: Apache-2.0

// Head-to-head benchmark: SILA keccak vs go-ethereum crypto/keccak (v1.17.10).
// Both are driven through equivalent call patterns on identical inputs.
package gethcompare

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"

	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	gethkeccak "github.com/ethereum/go-ethereum/crypto/keccak"
	sila "github.com/sila-network/sila-core-primitives/keccak"
)

var sizes = []int{32, 64, 128, 136, 256, 512, 1024, 4096, 16384, 65536, 1 << 20}

func input(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*131 + 7)
	}
	return b
}

var sink [32]byte

// One-shot API: sila.Sum256 vs geth crypto.Keccak256Hash (geth's production entry point).
func BenchmarkOneShot(b *testing.B) {
	for _, n := range sizes {
		data := input(n)
		b.Run(fmt.Sprintf("impl=sila/size=%d", n), func(b *testing.B) {
			b.SetBytes(int64(n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sink = sila.Sum256(data)
			}
		})
		b.Run(fmt.Sprintf("impl=geth/size=%d", n), func(b *testing.B) {
			b.SetBytes(int64(n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sink = gethcrypto.Keccak256Hash(data)
			}
		})
	}
}

// Streaming API with a reused hasher: Reset/Write/Sum on both sides.
func BenchmarkStreaming(b *testing.B) {
	for _, n := range sizes {
		data := input(n)
		out := make([]byte, 0, 32)
		b.Run(fmt.Sprintf("impl=sila/size=%d", n), func(b *testing.B) {
			h := sila.New()
			b.SetBytes(int64(n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				h.Reset()
				h.Write(data)
				out = h.Sum(out[:0])
			}
		})
		b.Run(fmt.Sprintf("impl=geth/size=%d", n), func(b *testing.B) {
			h := gethkeccak.NewLegacyKeccak256()
			b.SetBytes(int64(n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				h.Reset()
				h.Write(data)
				out = h.Sum(out[:0])
			}
		})
	}
}

// Equivalence guard: benchmarks are meaningless if outputs differ.
func TestSameOutput(t *testing.T) {
	for n := 0; n <= 2048; n++ {
		d := input(n)
		s := sila.Sum256(d)
		g := gethcrypto.Keccak256(d)
		if !bytes.Equal(s[:], g) {
			t.Fatalf("mismatch at len %d", n)
		}
	}
}

// Randomized equivalence against go-ethereum, one-shot and streaming with
// random chunking, up to ~70 KB per message.
func TestRandomAgainstGeth(t *testing.T) {
	rng := rand.New(rand.NewSource(20261108))
	for iter := 0; iter < 2000; iter++ {
		n := rng.Intn(70000)
		if iter%2 == 0 {
			n = rng.Intn(4 * 136)
		}
		d := make([]byte, n)
		rng.Read(d)
		g := gethcrypto.Keccak256(d)
		s := sila.Sum256(d)
		if !bytes.Equal(s[:], g) {
			t.Fatalf("one-shot mismatch len=%d", n)
		}
		h := sila.New()
		for rest := d; len(rest) > 0; {
			k := 1 + rng.Intn(len(rest))
			h.Write(rest[:k])
			rest = rest[k:]
		}
		if !bytes.Equal(h.Sum(nil), g) {
			t.Fatalf("streaming mismatch len=%d", n)
		}
	}
}
