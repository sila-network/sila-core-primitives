// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// The amd64 field assembly (field_amd64.s) is checked separately from the
// compiled Go code (ctasm_test.go): go tool objdump does not decode
// MULX/ADCX/ADOX, so the Go-code detector cannot read it.

// asmAllowed lists every instruction field_amd64.s may use. None of them
// has a data-dependent execution time on processors that guarantee data
// operand independent timing for them (Intel DOIT list, AMD equivalent);
// none transfers control or computes an address from data.
var asmAllowed = map[string]bool{
	"MOVQ": true, "MOVL": true, "MULQ": true, "MULXQ": true,
	"ADDQ": true, "ADCQ": true, "ADCXQ": true, "ADOXQ": true,
	"SBBQ": true, "ANDQ": true, "XORQ": true, "CMOVQCS": true,
	"RET": true,
	// CPUID only in ·cpuid; the dispatch only in ·fieldMul/·fieldSqr
	// (checked below).
	"CPUID": true, "CMPB": true, "JEQ": true, "JMP": true,
}

// TestFieldAsmSourceIsStraightLine reads field_amd64.s (on every
// platform) and checks that:
//   - every instruction is in asmAllowed (no other branch, no CALL, LOOP,
//     division, or table instruction);
//   - the only conditional jump in the file is the CPU dispatch "JEQ
//     portable", immediately after "CMPB ·useADX(SB), $0", and only in
//     ·fieldMul and ·fieldSqr; JMP only tail-jumps to the two
//     implementations there;
//   - memory operands are only base+offset through the argument pointers
//     (SI, DI), the argument frame (FP) or the symbol useADX — never an
//     indexed address, so no address depends on data;
//   - CPUID appears only in ·cpuid.
func TestFieldAsmSourceIsStraightLine(t *testing.T) {
	src, err := os.ReadFile("field_amd64.s")
	if err != nil {
		t.Fatal(err)
	}
	memOperand := regexp.MustCompile(`\(([^)]*)\)`)
	fn := ""
	prev := ""
	condJumps := 0
	for i, raw := range strings.Split(string(src), "\n") {
		line := raw
		if j := strings.Index(line, "//"); j >= 0 {
			line = line[:j]
		}
		line = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), `\`))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "TEXT ") {
			fn = strings.Fields(line)[1]
			prev = ""
			continue
		}
		if strings.HasSuffix(line, ":") {
			continue // label
		}
		for _, stmt := range strings.Split(line, ";") {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}
			op := strings.Fields(stmt)[0]
			if op == "REDUCE_ADX" {
				continue // macro, its body is checked where it is defined
			}
			where := "field_amd64.s:" + strconv.Itoa(i+1) + ": " + stmt
			if !asmAllowed[op] {
				t.Errorf("%s: instruction %s not allowed", where, op)
			}
			for _, m := range memOperand.FindAllStringSubmatch(stmt, -1) {
				switch m[1] {
				case "SI", "DI", "FP", "SB":
				default:
					t.Errorf("%s: memory operand (%s) not allowed", where, m[1])
				}
			}
			// The index form (SI)(CX*8) would appear as two groups.
			if strings.Contains(stmt, ")(") {
				t.Errorf("%s: indexed memory operand", where)
			}
			switch op {
			case "CPUID":
				if fn != "·cpuid(SB)," {
					t.Errorf("%s: CPUID outside ·cpuid", where)
				}
			case "CMPB":
				if stmt != "CMPB ·useADX(SB), $0" {
					t.Errorf("%s: unexpected comparison", where)
				}
			case "JEQ":
				condJumps++
				if stmt != "JEQ  portable" && stmt != "JEQ portable" ||
					prev != "CMPB ·useADX(SB), $0" ||
					(fn != "·fieldMul(SB)," && fn != "·fieldSqr(SB),") {
					t.Errorf("%s: conditional jump other than the CPU dispatch", where)
				}
			case "JMP":
				target := strings.Fields(stmt)[1]
				ok := map[string]map[string]bool{
					"·fieldMul(SB),": {"·fieldMulADX(SB)": true, "·fieldMulMULQ(SB)": true},
					"·fieldSqr(SB),": {"·fieldSqrADX(SB)": true, "·fieldSqrMULQ(SB)": true},
				}[fn][target]
				if !ok {
					t.Errorf("%s: jump other than the dispatch tail jump", where)
				}
			}
			prev = stmt
		}
	}
	if condJumps != 2 {
		t.Fatalf("expected exactly 2 dispatch jumps, found %d", condJumps)
	}
}

// TestCompiledFieldAsmIsStraightLine disassembles the amd64 test binary
// with GNU objdump (which decodes MULX/ADCX/ADOX) and checks that the
// field functions contain no jump other than the dispatch: no conditional
// jump at all in the four implementations, exactly one in each of the two
// dispatch stubs (which also serves as the detector's positive control).
// Opt-in like the other compiled-code checks (SILA_CT_OBJDUMP=1); skipped
// where GNU objdump is not installed.
func TestCompiledFieldAsmIsStraightLine(t *testing.T) {
	if os.Getenv("SILA_CT_OBJDUMP") != "1" {
		t.Skip("set SILA_CT_OBJDUMP=1 to inspect the compiled code")
	}
	if runtime.GOARCH != "amd64" && os.Getenv("SILA_CT_GOARCH") != "amd64" {
		t.Skip("amd64 only")
	}
	gnu, err := exec.LookPath("objdump")
	if err != nil {
		t.Skip("GNU objdump not installed")
	}
	goTool := filepath.Join(runtime.GOROOT(), "bin", "go")
	bin := filepath.Join(t.TempDir(), "secp.test")
	cmd := exec.Command(goTool, "test", "-c", "-o", bin, ".")
	cmd.Env = append(os.Environ(), "GOARCH=amd64")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	nm, err := exec.Command(goTool, "tool", "nm", "-size", "-sort", "address", bin).CombinedOutput()
	if err != nil {
		t.Fatalf("nm: %v\n%s", err, nm)
	}
	want := map[string]int{ // function -> allowed conditional jumps
		"fieldMulADX": 0, "fieldSqrADX": 0, "fieldMulMULQ": 0, "fieldSqrMULQ": 0,
		"fieldMul": 1, "fieldSqr": 1,
	}
	jump := regexp.MustCompile(`\tj([a-z]+)\s`)
	found := 0
	for _, l := range strings.Split(string(nm), "\n") {
		f := strings.Fields(l)
		if len(f) < 4 || !strings.HasSuffix(f[3], ".abi0") {
			continue
		}
		name := strings.TrimSuffix(f[3], ".abi0")
		name = name[strings.LastIndex(name, ".")+1:]
		allowed, ok := want[name]
		if !ok {
			continue
		}
		found++
		addr, _ := strconv.ParseUint(f[0], 16, 64)
		size, _ := strconv.ParseUint(f[1], 10, 64)
		out, err := exec.Command(gnu, "-d", "--no-show-raw-insn",
			"--start-address=0x"+strconv.FormatUint(addr, 16),
			"--stop-address=0x"+strconv.FormatUint(addr+size, 16), bin).CombinedOutput()
		if err != nil {
			t.Fatalf("objdump %s: %v\n%s", name, err, out)
		}
		body := string(out)
		if !strings.Contains(body, "ret") && allowed == 0 {
			t.Fatalf("%s: disassembly looks empty:\n%s", name, body)
		}
		cond := 0
		for _, m := range jump.FindAllStringSubmatch(body, -1) {
			if m[1] != "mp" {
				cond++
			}
		}
		if cond != allowed {
			t.Errorf("%s: %d conditional jump(s), want %d:\n%s", name, cond, allowed, body)
		}
		if allowed == 0 && strings.Contains(body, "\tjmp") {
			t.Errorf("%s: unexpected jump:\n%s", name, body)
		}
	}
	if found != len(want) {
		t.Fatalf("found %d of %d assembly functions", found, len(want))
	}
}
