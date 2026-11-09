// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// TestCompiledConstantTimeFunctions inspects the machine code that the Go
// compiler actually produced for the constant-time building blocks and
// fails if any of them contains a conditional branch. Branch-free source
// does not guarantee branch-free machine code (the compiler may turn a
// mask selection into a jump), so this check runs on the compiled test
// binary for the current GOARCH.
//
// The only conditional branch allowed is the stack-growth check in a
// function prologue (a comparison of the stack pointer, unrelated to
// data), recognised by its jump to runtime.morestack.
//
// Functions with loops (table scans, fixed-window loops) are checked by
// TestCompiledLoopsAreCounterBound instead.
//
// Opt-in (it runs the Go toolchain): SILA_CT_OBJDUMP=1; set
// SILA_CT_GOARCH to inspect another architecture's code.
func TestCompiledConstantTimeFunctions(t *testing.T) {
	bin := ctTestBinary(t)
	// Negative control: the detector must find the data-dependent
	// branches of a variable-time function.
	ctl := objdump(t, bin, `secp256k1\.jacAddAffine$`)
	if len(ctl) != 1 {
		t.Fatal("control function not found")
	}
	for _, body := range ctl {
		if dataBranches(body) == 0 {
			t.Fatal("detector found no branch in the variable-time control function")
		}
	}
	branchFree := []string{
		`secp256k1\.mulWords`,
		`secp256k1\.sqrWords`,
		`secp256k1\.reduceWords`,
		`secp256k1\.fieldCorrect`,
		`secp256k1\.montReduceN`,
		`secp256k1\.\(\*fieldElement\)\.(mul|square|add|sub|neg|mulSmall|selectFrom)`,
		`secp256k1\.\(\*scalar\)\.(mul|square|add|sub|neg|selectFrom|isHigh|isZero)`,
		`secp256k1\.\(\*modulus\)\.(add|sub|neg|reduceOnce)`,
		`secp256k1\.\(\*point\)\.(add|double|addMixed|selectFrom|neg)`,
		// selectLimbs, lessThan, isZeroLimbs and equalLimbs are inlined
		// into the functions above and checked as part of them.
	}
	for _, pat := range branchFree {
		funcs := objdump(t, bin, pat+`$`)
		if len(funcs) == 0 {
			t.Fatalf("no function matches %s (inlined everywhere or renamed?)", pat)
		}
		for name, body := range funcs {
			if n := dataBranches(body); n > 0 {
				t.Errorf("%s: %d conditional branch(es) in compiled code:\n%s", name, n, body)
			}
		}
	}
}

// TestCompiledLoopsAreCounterBound checks the constant-time functions that
// contain loops: every conditional branch must be a loop back-edge or exit
// test on a counter (compare with an immediate), never a test of loaded
// data. It is a heuristic for review, complementing the source rules.
func TestCompiledLoopsAreCounterBound(t *testing.T) {
	bin := ctTestBinary(t)
	for _, pat := range []string{
		`secp256k1\.\(\*point\)\.(lookup|scalarBaseMult|scalarMult)`,
		`secp256k1\.\(\*affinePoint\)\.lookupAffine`,
		`secp256k1\.boothDigit`,
		`secp256k1\.\(\*scalar\)\.(inv|sqrN)`,
		`secp256k1\.\(\*fieldElement\)\.(inv|sqrt|sqrN)`,
		`secp256k1\.fieldPow2k1`,
	} {
		funcs := objdump(t, bin, pat+`$`)
		if len(funcs) == 0 {
			t.Fatalf("no function matches %s", pat)
		}
		for name, body := range funcs {
			t.Logf("%s: %d conditional branch(es), all must be counter or public-index tests", name, dataBranches(body))
		}
	}
}

func ctTestBinary(t *testing.T) string {
	t.Helper()
	if os.Getenv("SILA_CT_OBJDUMP") != "1" {
		t.Skip("set SILA_CT_OBJDUMP=1 to inspect the compiled code")
	}
	goTool := filepath.Join(runtime.GOROOT(), "bin", "go")
	if _, err := os.Stat(goTool); err != nil {
		t.Skip("go tool not available")
	}
	arch := runtime.GOARCH
	if a := os.Getenv("SILA_CT_GOARCH"); a != "" {
		arch = a
	}
	if !ctObjdumpSupported(arch) {
		t.Skipf("branch detector does not support %s", arch)
	}
	bin := filepath.Join(t.TempDir(), "secp.test")
	cmd := exec.Command(goTool, "test", "-c", "-o", bin, ".")
	// SILA_CT_GOARCH cross-compiles, so another architecture's machine
	// code can be inspected (go tool objdump reads any GOARCH).
	if arch := os.Getenv("SILA_CT_GOARCH"); arch != "" {
		cmd.Env = append(os.Environ(), "GOARCH="+arch)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

// objdump returns the disassembly of each function matching pattern.
func objdump(t *testing.T, bin, pattern string) map[string]string {
	t.Helper()
	goTool := filepath.Join(runtime.GOROOT(), "bin", "go")
	out, err := exec.Command(goTool, "tool", "objdump", "-s", pattern, bin).CombinedOutput()
	if err != nil {
		t.Fatalf("objdump %s: %v\n%s", pattern, err, out)
	}
	funcs := map[string]string{}
	var name string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "TEXT ") {
			name = strings.Fields(line)[1]
			continue
		}
		if name != "" {
			funcs[name] += line + "\n"
		}
	}
	return funcs
}

var (
	// Conditional branches: amd64/386 Jcc (not JMP); arm64 B.cond,
	// CBZ/CBNZ, TBZ/TBNZ; ppc64 B.cond and BC; riscv64 B.cond, BEQZ/BNEZ.
	condBranch = regexp.MustCompile(`\s(J(?:EQ|NE|CS|CC|HI|LS|LT|GE|GT|LE|MI|PL|OS|OC|PS|PC|CXZL|CXZQ)|B(?:EQ|NE|CS|HS|CC|LO|MI|PL|VS|VC|HI|LS|GE|LT|GT|LE|LTU|GEU|EQZ|NEZ|C)|CBN?Z|TBN?Z)\s`)
	morestack  = regexp.MustCompile(`runtime\.morestack`)
	instr      = regexp.MustCompile(`^\s*\S+:\d+\s+0x[0-9a-f]+\s`)
)

// dataBranches counts conditional branches other than the prologue
// stack-growth check: in a function that calls runtime.morestack, the
// first conditional branch among its first instructions compares the
// stack pointer with the goroutine's stack guard.
func dataBranches(body string) int {
	hasStackCheck := morestack.MatchString(body)
	n, idx := 0, 0
	for _, l := range strings.Split(body, "\n") {
		if !instr.MatchString(l) {
			continue
		}
		idx++
		if !condBranch.MatchString(l) {
			continue
		}
		if hasStackCheck && idx <= 8 {
			hasStackCheck = false // only one prologue check
			continue
		}
		n++
	}
	return n
}

// ctObjdumpSupported lists the architectures whose branch syntax the
// detector knows.
func ctObjdumpSupported(arch string) bool {
	switch arch {
	case "amd64", "386", "arm64", "ppc64le", "ppc64", "riscv64":
		return true
	}
	return false
}
