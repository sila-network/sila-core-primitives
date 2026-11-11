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
	"SBBQ": true, "SUBQ": true, "ANDQ": true, "XORQ": true, "IMULQ": true,
	"CMOVQCS": true, "CMOVQCC": true,
	// SSE2 (amd64 baseline) for the table scan: 128-bit loads/stores,
	// logic, lane comparison and broadcast; no data-dependent timing.
	"MOVOU": true, "PXOR": true, "PAND": true, "POR": true,
	"PCMPEQL": true, "PSHUFD": true,
	"RET": true,
	// CPUID only in ·cpuid; the dispatch only in ·fieldMul/·fieldSqr
	// (checked below).
	"CPUID": true, "CMPB": true, "JEQ": true, "JMP": true,
}

// dispatchStub lists the functions that select the implementation.
var dispatchStub = map[string]bool{
	"·fieldMul(SB),": true, "·fieldSqr(SB),": true,
	"·scalarMul(SB),": true, "·scalarSqr(SB),": true,
}

// TestFieldAsmSourceIsStraightLine reads field_amd64.s (on every
// platform) and checks that:
//   - every instruction is in asmAllowed (no other branch, no CALL, LOOP,
//     division, or table instruction);
//   - the only conditional jump in the file is the CPU dispatch "JEQ
//     portable", immediately after "CMPB ·useADX(SB), $0", and only in
//     the dispatch stubs (·fieldMul, ·fieldSqr, ·scalarMul, ·scalarSqr);
//     JMP only tail-jumps to the two implementations there;
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
					!dispatchStub[fn] {
					t.Errorf("%s: conditional jump other than the CPU dispatch", where)
				}
			case "JMP":
				target := strings.Fields(stmt)[1]
				ok := map[string]map[string]bool{
					"·fieldMul(SB),":  {"·fieldMulADX(SB)": true, "·fieldMulMULQ(SB)": true},
					"·fieldSqr(SB),":  {"·fieldSqrADX(SB)": true, "·fieldSqrMULQ(SB)": true},
					"·scalarMul(SB),": {"·scalarMulADX(SB)": true, "·scalarMulMULQ(SB)": true},
					"·scalarSqr(SB),": {"·scalarSqrADX(SB)": true, "·scalarSqrMULQ(SB)": true},
				}[fn][target]
				if !ok {
					t.Errorf("%s: jump other than the dispatch tail jump", where)
				}
			}
			prev = stmt
		}
	}
	if condJumps != len(dispatchStub) {
		t.Fatalf("expected exactly %d dispatch jumps, found %d", len(dispatchStub), condJumps)
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
		"scalarMulADX": 0, "scalarSqrADX": 0, "scalarMulMULQ": 0, "scalarSqrMULQ": 0,
		"fieldMul": 1, "fieldSqr": 1, "scalarMul": 1, "scalarSqr": 1,
		"lookupAffineSSE2": 0,
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

// arm64Allowed lists every instruction field_arm64.s may use: data-
// independent under PSTATE.DIT (Arm's DIT instruction list), no control
// transfer other than RET, no data-dependent address.
var arm64Allowed = map[string]bool{
	"MOVD": true, "MOVK": true, "LDP": true, "STP": true,
	"MUL": true, "UMULH": true,
	"ADD": true, "ADDS": true, "ADCS": true, "ADC": true, "SUBS": true, "SBCS": true,
	"CSEL": true, "RET": true,
	// NEON for the table scan: loads/stores (post-increment by a constant),
	// broadcast, lane comparison and logic.
	"VLD1.P": true, "VST1": true, "VDUP": true, "VCMEQ": true,
	"VAND": true, "VORR": true, "VEOR": true,
}

// TestArm64AsmSourceIsStraightLine reads field_arm64.s (on every platform)
// and checks that every instruction is in arm64Allowed (so there is no
// branch at all) and that every memory operand is a fixed offset from an
// argument pointer (R0, R1, R2) or the argument frame (FP).
func TestArm64AsmSourceIsStraightLine(t *testing.T) {
	src, err := os.ReadFile("field_arm64.s")
	if err != nil {
		t.Fatal(err)
	}
	memOperand := regexp.MustCompile(`\(([^)]*)\)`)
	n := 0
	for i, raw := range strings.Split(string(src), "\n") {
		line := raw
		if j := strings.Index(line, "//"); j >= 0 {
			line = line[:j]
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "TEXT ") {
			continue
		}
		op := strings.Fields(line)[0]
		where := "field_arm64.s:" + strconv.Itoa(i+1) + ": " + line
		if !arm64Allowed[op] {
			t.Errorf("%s: instruction %s not allowed", where, op)
		}
		for _, m := range memOperand.FindAllStringSubmatch(line, -1) {
			switch m[1] {
			case "R0", "R1", "R2", "FP":
			default:
				// Register lists of LDP/STP, e.g. (R3, R4).
				if op != "LDP" && op != "STP" || !strings.Contains(m[1], ",") {
					t.Errorf("%s: memory operand (%s) not allowed", where, m[1])
				}
			}
		}
		n++
	}
	if n < 400 {
		t.Fatalf("only %d instructions read", n)
	}
}

// TestCompiledArm64AsmIsStraightLine disassembles the arm64 build (go tool
// objdump decodes arm64 fully) and checks that the four assembly
// functions contain no branch of any kind, only straight-line code ending
// in RET. Runs where the compiled-code checks run with SILA_CT_GOARCH=arm64
// (or natively on arm64).
func TestCompiledArm64AsmIsStraightLine(t *testing.T) {
	arch := runtime.GOARCH
	if a := os.Getenv("SILA_CT_GOARCH"); a != "" {
		arch = a
	}
	if arch != "arm64" {
		t.Skip("arm64 only (set SILA_CT_GOARCH=arm64)")
	}
	bin := ctTestBinary(t)
	branch := regexp.MustCompile(`\s(B|BL|BR|BLR|B\.[A-Z]+|CBN?Z|TBN?Z|RET)\s`)
	for _, name := range []string{"fieldMul", "fieldSqr", "scalarMul", "scalarSqr", "lookupAffineNEON"} {
		funcs := objdump(t, bin, `secp256k1\.`+name+`\.abi0$`)
		if len(funcs) != 1 {
			t.Fatalf("%s: assembly function not found", name)
		}
		for fn, body := range funcs {
			rets := 0
			for _, l := range strings.Split(body, "\n") {
				if !instr.MatchString(l) {
					continue
				}
				if m := branch.FindStringSubmatch(l); m != nil {
					if m[1] == "RET" {
						rets++
						continue
					}
					t.Errorf("%s: branch in assembly: %s", fn, l)
				}
			}
			if rets != 1 {
				t.Errorf("%s: %d RET instructions, want exactly 1", fn, rets)
			}
		}
	}
}
