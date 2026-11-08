// SPDX-License-Identifier: Apache-2.0

package keccak

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"testing"
)

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

// Vectors with independent provenance:
//   - 0xCC: Keccak team KAT (ShortMsgKAT_256, Len=8).
//   - pattern(n) and "a"*10^6: PyCryptodome 4.4.0 keccak (XKCP-based C code),
//     re-confirmed against go-ethereum v1.17.10 in ../bench.
func TestExtendedVectors(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"kat-cc", []byte{0xcc}, "eead6dbfc7340a56caedc044696a168870549a6a7f6f56961e84a54bd9970b8a"},
		{"p1", pattern(1), "bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a"},
		{"p135", pattern(135), "cbdfd9dee5faad3818d6b06f95a219fd290b0e1706f6a82e5a595b9ce9faca62"},
		{"p136", pattern(136), "7ce759f1ab7f9ce437719970c26b0a66ff11fe3e38e17df89cf5d29c7d7f807e"},
		{"p137", pattern(137), "ac73d4fae68b8453f764007c1a20ce95994187861f0c3227a3a8e99a73a3b1db"},
		{"p271", pattern(271), "27eceb59ebc3dc8a04a5b135be641591a7278540e4556a2ba9f408194e666ec3"},
		{"p272", pattern(272), "8e2476e65823b24d96ebe239f2c1534cdf763e689e2410c3b1cb0c74e6177bfc"},
		{"p273", pattern(273), "3f02f134370e4debb95140ef49ddd3aed8c65ff1ed83a43f1b269421f179c5f9"},
		{"p1000", pattern(1000), "af692982e84a5a9688359025660a7857cd28ee7c8d867cfa1677baf2e6d1f63b"},
		{"a*1e6", bytes.Repeat([]byte("a"), 1000000), "fadae6b49f129bbb812be8407b7b2894f34aecf6dbd1f9b0f0c7e9853098fc96"},
	}
	for _, tc := range cases {
		got := Sum256(tc.in)
		if hex.EncodeToString(got[:]) != tc.want {
			t.Errorf("%s: got %x want %s", tc.name, got, tc.want)
		}
		h := New()
		h.Write(tc.in)
		if hex.EncodeToString(h.Sum(nil)) != tc.want {
			t.Errorf("%s: streaming mismatch", tc.name)
		}
	}
}

// Every permutation implementation available on this machine must agree
// with the original V1 loop on random states.
func TestPermutationsAgree(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 20000; i++ {
		var s [25]uint64
		for j := range s {
			s[j] = rng.Uint64()
		}
		ref := s
		permuteReference(&ref)
		g := s
		permuteGeneric(&g)
		if g != ref {
			t.Fatalf("generic permutation differs at iteration %d", i)
		}
		d := s
		permute(&d)
		if d != ref {
			t.Fatalf("dispatched permutation differs at iteration %d", i)
		}
	}
	// Fixed points worth checking explicitly.
	for _, v := range []uint64{0, ^uint64(0)} {
		var s [25]uint64
		for j := range s {
			s[j] = v
		}
		ref, g, d := s, s, s
		permuteReference(&ref)
		permuteGeneric(&g)
		permute(&d)
		if g != ref || d != ref {
			t.Fatalf("permutation mismatch on constant state %x", v)
		}
	}
}

// All lengths across eight absorption blocks, one-shot and streaming,
// against the naive reference sponge.
func TestAllLengthsAgainstReference(t *testing.T) {
	data := make([]byte, 8*Rate+3)
	rand.New(rand.NewSource(2)).Read(data)
	for n := 0; n <= len(data); n++ {
		want := referenceSum(data[:n])
		if got := Sum256(data[:n]); got != want {
			t.Fatalf("Sum256 len=%d", n)
		}
		h := New()
		h.Write(data[:n])
		if !bytes.Equal(h.Sum(nil), want[:]) {
			t.Fatalf("stream len=%d", n)
		}
	}
}

// Every two-way split of messages around one and two block boundaries.
func TestEverySplitPoint(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	for _, n := range []int{Rate - 1, Rate, Rate + 1, 2*Rate - 1, 2 * Rate, 2*Rate + 1, 3 * Rate} {
		data := make([]byte, n)
		rng.Read(data)
		want := referenceSum(data)
		for cut := 0; cut <= n; cut++ {
			h := New()
			h.Write(data[:cut])
			h.Write(data[cut:])
			if !bytes.Equal(h.Sum(nil), want[:]) {
				t.Fatalf("n=%d cut=%d", n, cut)
			}
		}
	}
}

// Random messages with random chunking, compared with the reference.
func TestRandomChunking(t *testing.T) {
	rng := rand.New(rand.NewSource(4))
	for iter := 0; iter < 3000; iter++ {
		n := rng.Intn(5 * Rate)
		data := make([]byte, n)
		rng.Read(data)
		want := referenceSum(data)
		h := New()
		for rest := data; len(rest) > 0; {
			k := 1 + rng.Intn(len(rest))
			if rng.Intn(4) == 0 {
				k = 0 // zero-length writes must be harmless
			}
			h.Write(rest[:k])
			rest = rest[k:]
		}
		if !bytes.Equal(h.Sum(nil), want[:]) {
			t.Fatalf("iter %d n=%d", iter, n)
		}
	}
}

func TestInputNotModified(t *testing.T) {
	data := pattern(3*Rate + 5)
	orig := append([]byte(nil), data...)
	Sum256(data)
	h := New()
	h.Write(data)
	h.Sum(nil)
	if !bytes.Equal(data, orig) {
		t.Fatal("input modified")
	}
}

// Sum must not alias or retain the caller's buffer and must append.
func TestSumAppendsWithoutAliasing(t *testing.T) {
	h := New()
	h.Write([]byte("abc"))
	buf := make([]byte, 2, 64)
	out := h.Sum(buf)
	if len(out) != 34 || &out[0] != &buf[0] {
		t.Fatal("Sum did not append in place")
	}
	want := Sum256([]byte("abc"))
	if !bytes.Equal(out[2:], want[:]) {
		t.Fatal("wrong digest")
	}
}

func TestZeroAllocations(t *testing.T) {
	data := pattern(1000)
	if n := testing.AllocsPerRun(100, func() { Sum256(data) }); n != 0 {
		t.Fatalf("Sum256 allocates %v", n)
	}
	h := New()
	buf := make([]byte, 0, 32)
	if n := testing.AllocsPerRun(100, func() {
		h.Reset()
		h.Write(data)
		buf = h.Sum(buf[:0])
	}); n != 0 {
		t.Fatalf("streaming allocates %v", n)
	}
}

func FuzzSum256(f *testing.F) {
	f.Add([]byte{}, uint8(1))
	f.Add(pattern(Rate), uint8(7))
	f.Add(pattern(2*Rate+1), uint8(135))
	f.Fuzz(func(t *testing.T, data []byte, chunk uint8) {
		want := referenceSum(data)
		if got := Sum256(data); got != want {
			t.Fatalf("Sum256 mismatch len=%d", len(data))
		}
		c := int(chunk) + 1
		h := New()
		for i := 0; i < len(data); i += c {
			h.Write(data[i:min(i+c, len(data))])
		}
		if !bytes.Equal(h.Sum(nil), want[:]) {
			t.Fatalf("stream mismatch len=%d chunk=%d", len(data), c)
		}
	})
}

func BenchmarkPermuteGeneric(b *testing.B) {
	var s [25]uint64
	b.SetBytes(Rate)
	for i := 0; i < b.N; i++ {
		permuteGeneric(&s)
	}
}

func BenchmarkPermute(b *testing.B) {
	var s [25]uint64
	b.SetBytes(Rate)
	for i := 0; i < b.N; i++ {
		permute(&s)
	}
}
