// SPDX-License-Identifier: Apache-2.0

package keccak

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"
)

type katEntry struct {
	bits    int
	msg, md []byte
	lineNo  int
}

func readKAT(t *testing.T, path string) []katEntry {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []katEntry
	var cur katEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for n := 1; sc.Scan(); n++ {
		k, v, ok := strings.Cut(sc.Text(), " = ")
		if !ok {
			continue
		}
		switch k {
		case "Len":
			cur = katEntry{lineNo: n}
			if cur.bits, err = strconv.Atoi(v); err != nil {
				t.Fatalf("%s:%d: %v", path, n, err)
			}
		case "Msg":
			if cur.msg, err = hex.DecodeString(v); err != nil {
				t.Fatalf("%s:%d: %v", path, n, err)
			}
		case "MD":
			if cur.md, err = hex.DecodeString(v); err != nil {
				t.Fatalf("%s:%d: %v", path, n, err)
			}
			if cur.bits%8 != 0 || len(cur.md) != Size {
				t.Fatalf("%s:%d: unexpected entry", path, cur.lineNo)
			}
			cur.msg = cur.msg[:cur.bits/8] // Len = 0 is written as Msg = 00
			out = append(out, cur)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func checkKAT(t *testing.T, path string, wantCount int) {
	entries := readKAT(t, path)
	if len(entries) != wantCount {
		t.Fatalf("%s: %d entries, want %d", path, len(entries), wantCount)
	}
	for _, e := range entries {
		got := Sum256(e.msg)
		if !bytes.Equal(got[:], e.md) {
			t.Fatalf("%s line %d (Len=%d): Sum256 = %x, want %x", path, e.lineNo, e.bits, got, e.md)
		}
		// Streaming, one byte at a time and in odd-sized chunks.
		for _, chunk := range []int{1, 7, 135, 137} {
			h := New()
			for i := 0; i < len(e.msg); i += chunk {
				h.Write(e.msg[i:min(i+chunk, len(e.msg))])
			}
			if !bytes.Equal(h.Sum(nil), e.md) {
				t.Fatalf("%s line %d: streaming (chunk %d) mismatch", path, e.lineNo, chunk)
			}
		}
	}
}

func TestOfficialShortMsgKAT(t *testing.T) {
	checkKAT(t, "testdata/kat/ShortMsgKAT_256_bytes.txt", 256)
}

func TestOfficialLongMsgKAT(t *testing.T) {
	checkKAT(t, "testdata/kat/LongMsgKAT_256_bytes.txt", 65)
}

// SHA-3 competition Monte Carlo test: Msg (128 bytes) starts as Seed; each
// step hashes Msg and sets Msg = MD || Msg[:96]; a checkpoint is printed
// every 1000 steps.
func TestOfficialMonteCarlo(t *testing.T) {
	data, err := os.ReadFile("testdata/kat/MonteCarlo_256.txt")
	if err != nil {
		t.Fatal(err)
	}
	var seed []byte
	var checkpoints [][]byte
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), " = ")
		if !ok {
			continue
		}
		b, err := hex.DecodeString(v)
		if k == "Seed" || k == "MD" {
			if err != nil {
				t.Fatal(err)
			}
		}
		switch k {
		case "Seed":
			seed = b
		case "MD":
			checkpoints = append(checkpoints, b)
		}
	}
	if len(seed) != 128 || len(checkpoints) != 100 {
		t.Fatalf("bad Monte Carlo file: seed %d bytes, %d checkpoints", len(seed), len(checkpoints))
	}
	msg := append([]byte(nil), seed...)
	var md [32]byte
	for j, want := range checkpoints {
		for i := 0; i < 1000; i++ {
			md = Sum256(msg)
			copy(msg[32:], msg[:96])
			copy(msg, md[:])
		}
		if !bytes.Equal(md[:], want) {
			t.Fatalf("Monte Carlo checkpoint j=%d: got %x want %x", j, md, want)
		}
	}
}

// 1 GiB through the streaming API in 64-byte writes.
func TestOfficialExtremelyLongMsg(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("1 GiB message; skipped with -short or -race")
	}
	data, err := os.ReadFile("testdata/kat/ExtremelyLongMsgKAT_256.txt")
	if err != nil {
		t.Fatal(err)
	}
	var repeat int
	var text string
	var want []byte
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), " = ")
		if !ok {
			continue
		}
		switch k {
		case "Repeat":
			repeat, _ = strconv.Atoi(v)
		case "Text":
			text = v
		case "MD":
			want, _ = hex.DecodeString(v)
		}
	}
	if repeat != 16777216 || len(text) != 64 || len(want) != 32 {
		t.Fatal("unexpected ExtremelyLongMsgKAT file")
	}
	h := New()
	chunk := []byte(text)
	for i := 0; i < repeat; i++ {
		h.Write(chunk)
	}
	if !bytes.Equal(h.Sum(nil), want) {
		t.Fatalf("1 GiB message: got %x want %x", h.Sum(nil), want)
	}
}
