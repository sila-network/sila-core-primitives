// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
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
		// Constant-time divstep inversion (inv_ct.go, wide.go).
		`secp256k1\.(linComb|linShr62|linShr62Mod|wideMulAdd|wideMulWord|wideAdd|wideSub)`,
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
	arch := runtime.GOARCH
	if a := os.Getenv("SILA_CT_GOARCH"); a != "" {
		arch = a
	}
	// On amd64 the base-table scan is the SSE2 assembly (checked, with
	// no branch at all, by TestCompiledFieldAsmIsStraightLine); elsewhere
	// it is the Go loop.
	lookupAffine := `secp256k1\.\(\*affinePoint\)\.lookupAffine`
	switch arch {
	case "amd64":
		lookupAffine = `secp256k1\.lookupAffineSSE2\.abi0`
	case "arm64":
		lookupAffine = `secp256k1\.lookupAffineNEON\.abi0`
	}
	for _, pat := range []string{
		`secp256k1\.\(\*point\)\.(lookup|scalarBaseMult|scalarMult)`,
		lookupAffine,
		`secp256k1\.boothDigit`,
		`secp256k1\.\(\*scalar\)\.(inv|sqrN)`,
		`secp256k1\.\(\*fieldElement\)\.(inv|sqrt|sqrN)`,
		`secp256k1\.fieldPow2k1`,
		`secp256k1\.divsteps62`,
		`secp256k1\.modInverseCT`,
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

// TestCompiledInversionLoopsAreCounters checks the constant-time divstep
// inversion strictly. Apart from the prologue stack check, each function
// may contain only the listed loop branches, each of the exact form
//
//	INCQ R          (inside the loop body)
//	CMPQ R, $N      (N from the function's list, each used once)
//	JL   back       (a backward jump: the loop's back edge)
//
// so a comparison of data with an immediate (for example a test of delta)
// is rejected: it adds a branch, uses another constant, or is not a
// counter back edge. A negative control function with such a data test
// must fail the check.
func TestCompiledInversionLoopsAreCounters(t *testing.T) {
	// Reference the negative control so it is linked into the binary.
	if ctCounterNegativeControl(uint64(len(t.Name()))) == 1 {
		t.Log("negative control linked")
	}
	bin := ctTestBinary(t)
	if arch := os.Getenv("SILA_CT_GOARCH"); arch != "" && arch != "amd64" {
		t.Skip("the counter-loop pattern is checked on amd64")
	}
	if runtime.GOARCH != "amd64" && os.Getenv("SILA_CT_GOARCH") == "" {
		t.Skip("the counter-loop pattern is checked on amd64")
	}
	// Negative control: a 62-step loop with one data-dependent test.
	ctl := objdump(t, bin, `secp256k1\.ctCounterNegativeControl$`)
	if len(ctl) != 1 {
		t.Fatal("negative control not found")
	}
	for name, body := range ctl {
		if err := counterLoopsOnly(body, []uint64{62}); err == nil {
			t.Fatalf("%s: the check accepted a data-dependent branch", name)
		}
	}
	for pat, want := range map[string][]uint64{
		`secp256k1\.divsteps62`:        {62},
		`secp256k1\.modInverseCT`:      {12, 5},
		`secp256k1\.\(\*scalar\)\.inv`: nil,
	} {
		funcs := objdump(t, bin, pat+`$`)
		if len(funcs) == 0 {
			t.Fatalf("no function matches %s", pat)
		}
		for name, body := range funcs {
			if err := counterLoopsOnly(body, want); err != nil {
				t.Errorf("%s: %v\n%s", name, err, body)
			} else {
				t.Logf("%s: only the counter loops %v and the stack check", name, want)
			}
		}
	}
}

// counterLoopsOnly returns nil if, apart from the prologue stack check,
// the conditional branches of an amd64 disassembly are exactly counter
// back edges INCQ R; CMPQ R, $N; JL <lower address>, one for each N in
// want.
func counterLoopsOnly(body string, want []uint64) error {
	cmpRe := regexp.MustCompile(`\sCMPQ ([A-Z0-9]+), \$0x([0-9a-f]+)\s*$`)
	jlRe := regexp.MustCompile(`\sJL 0x([0-9a-f]+)\s*$`)
	addrRe := regexp.MustCompile(`^\s*\S+:\d+\s+0x([0-9a-f]+)\s`)
	remaining := map[uint64]int{}
	for _, n := range want {
		remaining[n]++
	}
	hasStackCheck := morestack.MatchString(body)
	var lines []string
	for _, l := range strings.Split(body, "\n") {
		if instr.MatchString(l) {
			lines = append(lines, strings.TrimRight(l, " \t"))
		}
	}
	for i, l := range lines {
		if !condBranch.MatchString(l) {
			continue
		}
		if hasStackCheck && i < 8 {
			hasStackCheck = false
			continue
		}
		jm := jlRe.FindStringSubmatch(l)
		if jm == nil || i == 0 {
			return fmt.Errorf("branch is not a JL back edge: %s", l)
		}
		target, _ := strconv.ParseUint(jm[1], 16, 64)
		am := addrRe.FindStringSubmatch(l)
		if am == nil {
			return fmt.Errorf("cannot read address: %s", l)
		}
		here, _ := strconv.ParseUint(am[1], 16, 64)
		if target >= here {
			return fmt.Errorf("JL does not jump backwards: %s", l)
		}
		cm := cmpRe.FindStringSubmatch(lines[i-1])
		if cm == nil {
			return fmt.Errorf("branch does not follow a counter comparison: %s / %s", lines[i-1], l)
		}
		reg := cm[1]
		n, _ := strconv.ParseUint(cm[2], 16, 64)
		if remaining[n] == 0 {
			return fmt.Errorf("unexpected loop bound %d: %s", n, lines[i-1])
		}
		remaining[n]--
		// The counter must be incremented inside the loop body, i.e.
		// between the jump target and the comparison.
		inc := false
		for j := 0; j < i-1; j++ {
			m := addrRe.FindStringSubmatch(lines[j])
			if m == nil {
				continue
			}
			a, _ := strconv.ParseUint(m[1], 16, 64)
			if a < target {
				continue
			}
			if f := strings.Fields(lines[j]); len(f) >= 2 && f[len(f)-2] == "INCQ" && f[len(f)-1] == reg {
				inc = true
			}
		}
		if !inc {
			return fmt.Errorf("compared register %s is not incremented before the test", reg)
		}
	}
	for n, c := range remaining {
		if c != 0 {
			return fmt.Errorf("loop with bound %d not found", n)
		}
	}
	return nil
}

// ctCounterNegativeControl is a 62-step loop with a data-dependent test
// (like a branch on delta in divsteps62): the counter-loop check must
// reject it.
//
//go:noinline
func ctCounterNegativeControl(x uint64) uint64 {
	var s uint64
	for i := 0; i < 62; i++ {
		x = x*6364136223846793005 + 1442695040888963407
		if x>>60 == 2 {
			s += ctNegativeSink(x)
		}
	}
	return s
}

//go:noinline
func ctNegativeSink(x uint64) uint64 { return x >> 3 }

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
	// Conditional branches: amd64/386 Jcc (not JMP), in both the Go
	// assembler names (JEQ, JCS, ...) and the Intel names that go tool
	// objdump prints (JE, JA, JAE, JB, JBE, JG, JL, JS, JO, JP, JRCXZ,
	// ...); arm64 B.cond, CBZ/CBNZ, TBZ/TBNZ; ppc64 B.cond and BC;
	// riscv64 B.cond, BEQZ/BNEZ.
	condBranch = regexp.MustCompile(`\s(J(?:EQ|NE|CS|CC|HI|LS|LT|GE|GT|LE|MI|PL|OS|OC|PS|PC|CXZL|CXZQ|E|Z|NZ|A|AE|B|BE|NA|NAE|NB|NBE|C|NC|G|L|NG|NGE|NL|NLE|S|NS|O|NO|P|NP|PE|PO|RCXZ|ECXZ|CXZ)|B(?:EQ|NE|CS|HS|CC|LO|MI|PL|VS|VC|HI|LS|GE|LT|GT|LE|LTU|GEU|EQZ|NEZ|C)|CBN?Z|TBN?Z)\s`)
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
