// SPDX-License-Identifier: Apache-2.0

package keccak

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"sync"
	"testing"
)

// Well-known Ethereum identifiers: ERC-20 event topics and function
// selectors (the selector is the first 4 bytes of the digest). Values were
// re-checked against PyCryptodome before being recorded here.
func TestEthereumWellKnownDigests(t *testing.T) {
	cases := []struct{ sig, digest string }{
		{"Transfer(address,address,uint256)", "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"},
		{"Approval(address,address,uint256)", "8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"},
		{"transfer(address,uint256)", "a9059cbb2ab09eb219583f4a59a5d0623ade346d962bcd4e46b11da047c9049b"},
		{"balanceOf(address)", "70a08231b98ef4ca268c9cc3f6b4590e4bfec28280db06bb5d45e689f2a360be"},
		{"approve(address,uint256)", "095ea7b334ae44009aa867bfb386f5c3b4b443ac6f0ee573fa91c4608fbadfba"},
	}
	selectors := map[string]string{
		"transfer(address,uint256)": "a9059cbb",
		"balanceOf(address)":        "70a08231",
		"approve(address,uint256)":  "095ea7b3",
	}
	for _, c := range cases {
		d := Sum256([]byte(c.sig))
		if hex.EncodeToString(d[:]) != c.digest {
			t.Errorf("%s: got %x", c.sig, d)
		}
		if sel, ok := selectors[c.sig]; ok && hex.EncodeToString(d[:4]) != sel {
			t.Errorf("%s: selector %x, want %s", c.sig, d[:4], sel)
		}
	}
}

// Inputs that start at every byte offset within a word must hash the same
// as an aligned copy (the kernels use unaligned 8-byte loads).
func TestUnalignedInputs(t *testing.T) {
	rng := rand.New(rand.NewSource(21))
	buf := make([]byte, 8+5*Rate+8)
	rng.Read(buf)
	for _, n := range []int{0, 1, 8, Rate - 1, Rate, Rate + 1, 3*Rate + 5, 5 * Rate} {
		ref := Sum256(append([]byte(nil), buf[:n]...))
		for off := 0; off < 8; off++ {
			if Sum256(buf[off:off+n]) != Sum256(append([]byte(nil), buf[off:off+n]...)) {
				t.Fatalf("n=%d off=%d: unaligned result differs from aligned copy", n, off)
			}
		}
		if Sum256(buf[:n]) != ref {
			t.Fatal("aliasing changed result")
		}
	}
}

// Many goroutines hashing concurrently (one-shot and separate Digests)
// must each get the reference answer; run with -race in CI.
func TestConcurrentUse(t *testing.T) {
	rng := rand.New(rand.NewSource(22))
	msgs := make([][]byte, 64)
	want := make([][32]byte, len(msgs))
	for i := range msgs {
		msgs[i] = make([]byte, rng.Intn(4*Rate))
		rng.Read(msgs[i])
		want[i] = referenceSum(msgs[i])
	}
	var wg sync.WaitGroup
	errs := make(chan string, 16)
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			h := New()
			for iter := 0; iter < 200; iter++ {
				i := (g*31 + iter) % len(msgs)
				if Sum256(msgs[i]) != want[i] {
					errs <- "Sum256"
					return
				}
				h.Reset()
				h.Write(msgs[i])
				if !bytes.Equal(h.Sum(nil), want[i][:]) {
					errs <- "Digest"
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatalf("concurrent %s mismatch", e)
	}
}
