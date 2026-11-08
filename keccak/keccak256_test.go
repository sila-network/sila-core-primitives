// SPDX-License-Identifier: Apache-2.0

package keccak

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"
)

func TestKnownVectors(t *testing.T) {
	vectors := []struct{ input, want string }{
		{"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},
		{"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"},
		{"The quick brown fox jumps over the lazy dog", "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"},
	}
	for _, tc := range vectors {
		t.Run(fmt.Sprintf("len=%d", len(tc.input)), func(t *testing.T) {
			got := Sum256([]byte(tc.input))
			if hex.EncodeToString(got[:]) != tc.want {
				t.Fatalf("got %x, want %s", got, tc.want)
			}
		})
	}
}

func TestStreamingSplits(t *testing.T) {
	rng := rand.New(rand.NewSource(20261108))
	for _, length := range []int{0, 1, 31, 32, 63, 64, 135, 136, 137, 271, 272, 273, 512, 1000, 4096, 65536} {
		input := make([]byte, length)
		_, _ = rng.Read(input)
		expected := Sum256(input)
		for chunk := 1; chunk <= 139; chunk += 7 {
			h := New()
			for i := 0; i < len(input); i += chunk {
				end := i + chunk
				if end > len(input) {
					end = len(input)
				}
				n, err := h.Write(input[i:end])
				if err != nil || n != end-i {
					t.Fatalf("write: n=%d err=%v", n, err)
				}
			}
			if got := h.Sum(nil); !bytes.Equal(got, expected[:]) {
				t.Fatalf("length=%d chunk=%d got=%x want=%x", length, chunk, got, expected)
			}
		}
	}
}

func TestWriteBoundaryAndSumNonDestructive(t *testing.T) {
	h := New()
	_, _ = h.Write(bytes.Repeat([]byte{0xff}, 135))
	first := h.Sum([]byte("pre"))
	if !bytes.Equal(first[:3], []byte("pre")) {
		t.Fatal("sum changed prefix")
	}
	if got := h.Sum(nil); !bytes.Equal(got, first[3:]) {
		t.Fatal("sum mutated state")
	}
	_, _ = h.Write([]byte{0x02})
	if got, want := h.Sum(nil), Sum256(append(bytes.Repeat([]byte{0xff}, 135), 0x02)); !bytes.Equal(got, want[:]) {
		t.Fatal("write after sum failed")
	}
	h.Reset()
	if got, want := h.Sum(nil), Sum256(nil); !bytes.Equal(got, want[:]) {
		t.Fatal("reset failed")
	}
}

func TestDifferentFromSHA3(t *testing.T) {
	input := []byte("abc")
	keccak := Sum256(input)
	sha3sum, err := hex.DecodeString("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(keccak[:], sha3sum) {
		t.Fatal("wrong domain separation: Keccak-256 is not SHA3-256")
	}
}

func TestInterface(t *testing.T) {
	h := New()
	if h.Size() != 32 || h.BlockSize() != 136 {
		t.Fatalf("unexpected hash interface size/rate")
	}
}

func BenchmarkSum256_32Bytes(b *testing.B)   { benchmarkSize(b, 32) }
func BenchmarkSum256_1024Bytes(b *testing.B) { benchmarkSize(b, 1024) }
func BenchmarkSum256_1MiB(b *testing.B)      { benchmarkSize(b, 1024*1024) }

func benchmarkSize(b *testing.B, n int) {
	data := bytes.Repeat([]byte{0x5a}, n)
	b.SetBytes(int64(n))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Sum256(data)
	}
}
