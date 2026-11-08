// SPDX-License-Identifier: Apache-2.0

//go:build amd64 && !purego

package keccak

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestAVX512DecisionRule(t *testing.T) {
	const okECX = cpuidOSXSAVE
	const okXCR0 = xcr0ZMMEnabled
	const okEBX = cpuidAVX512F | cpuidAVX512VL
	cases := []struct {
		name                     string
		maxLeaf, ecx, xcr0, ebx7 uint32
		want                     bool
	}{
		{"all present", 7, okECX, okXCR0, okEBX, true},
		{"higher max leaf", 0x20, okECX, okXCR0 | 1<<9, okEBX, true},
		{"max leaf < 7", 6, okECX, okXCR0, okEBX, false},
		{"no OSXSAVE", 7, 0, okXCR0, okEBX, false},
		{"OS lacks SSE state", 7, okECX, okXCR0 &^ (1 << 1), okEBX, false},
		{"OS lacks AVX state", 7, okECX, okXCR0 &^ (1 << 2), okEBX, false},
		{"OS lacks opmask state", 7, okECX, okXCR0 &^ (1 << 5), okEBX, false},
		{"OS lacks ZMM_Hi256", 7, okECX, okXCR0 &^ (1 << 6), okEBX, false},
		{"OS lacks Hi16_ZMM", 7, okECX, okXCR0 &^ (1 << 7), okEBX, false},
		{"no AVX512F", 7, okECX, okXCR0, cpuidAVX512VL, false},
		{"no AVX512VL", 7, okECX, okXCR0, cpuidAVX512F, false},
		{"nothing", 0, 0, 0, 0, false},
	}
	for _, c := range cases {
		if got := avx512Usable(c.maxLeaf, c.ecx, c.xcr0, c.ebx7); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestGODEBUGSwitches(t *testing.T) {
	cases := map[string]bool{
		"":                               false,
		"cpu.avx512=off":                 true,
		"cpu.avx512f=off":                true,
		"cpu.avx512vl=off":               true,
		"cpu.all=off":                    true,
		"gctrace=1, cpu.avx512=off":      true,
		"cpu.avx512=off,cpu.avx512=on":   false,
		"cpu.avx2=off":                   false,
		"cpu.avx512":                     false,
		"madvdontneed=1,cpu.avx512f=off": true,
	}
	for in, want := range cases {
		if got := godebugDisablesAVX512(in); got != want {
			t.Errorf("GODEBUG=%q: got %v want %v", in, got, want)
		}
	}
}

// absorb splits long inputs into bounded assembly calls; every split point
// around the chunk size must give the same state as the portable loop.
func TestChunkedAbsorbMatchesGeneric(t *testing.T) {
	if !useAVX512 {
		t.Skip("AVX-512 kernel not in use")
	}
	rng := rand.New(rand.NewSource(7))
	for _, blocks := range []int{1, maxBlocksPerAsmCall - 1, maxBlocksPerAsmCall, maxBlocksPerAsmCall + 1,
		2 * maxBlocksPerAsmCall, 2*maxBlocksPerAsmCall + 3, 5*maxBlocksPerAsmCall - 1} {
		data := make([]byte, blocks*Rate+rng.Intn(Rate))
		rng.Read(data)
		var s [25]uint64
		for i := range s {
			s[i] = rng.Uint64()
		}
		a, g := s, s
		absorb(&a, data)
		absorbGeneric(&g, data[:blocks*Rate])
		if a != g {
			t.Fatalf("blocks=%d: chunked absorb differs", blocks)
		}
	}
}

// End to end: GODEBUG=cpu.avx512=off in the environment of a fresh process
// must select the portable kernel, and the results must stay correct.
func TestGODEBUGEndToEnd(t *testing.T) {
	if os.Getenv("SILA_CHILD") == "1" {
		fmt.Printf("useAVX512=%v\n", useAVX512)
		if Sum256([]byte("abc")) != referenceSum([]byte("abc")) {
			fmt.Println("WRONG DIGEST")
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestGODEBUGEndToEnd$", "-test.count=1")
	cmd.Env = append(os.Environ(), "SILA_CHILD=1", "GODEBUG=cpu.avx512=off")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "useAVX512=false") || strings.Contains(string(out), "WRONG") {
		t.Fatalf("GODEBUG=cpu.avx512=off not honoured:\n%s", out)
	}
}
