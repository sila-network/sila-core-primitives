// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"math/bits"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// This file checks the generated AVX-512 assembly without needing an
// AVX-512 CPU. It parses the exact text genAsm emits and executes it with
// a small emulator that accepts only the instructions the generator is
// meant to use. Any other instruction, register or memory access fails the
// test. The emulated result is compared with a straightforward
// implementation of Keccak-f[1600] written from the specification below.

// specPermute is a plain, loop-based Keccak-f[1600] used only as an oracle
// here (it shares only rhoOffsets/roundConstants/piSource, which have their
// own tests against FIPS 202).
func specPermute(a *[25]uint64) {
	rho := rhoOffsets()
	rc := roundConstants()
	for r := 0; r < 24; r++ {
		var c [5]uint64
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				c[x] ^= a[laneIndex(x, y)]
			}
		}
		for x := 0; x < 5; x++ {
			d := c[mod5(x-1)] ^ bits.RotateLeft64(c[mod5(x+1)], 1)
			for y := 0; y < 5; y++ {
				a[laneIndex(x, y)] ^= d
			}
		}
		var b [25]uint64
		for X := 0; X < 5; X++ {
			for Y := 0; Y < 5; Y++ {
				x, y := piSource(X, Y)
				b[laneIndex(X, Y)] = bits.RotateLeft64(a[laneIndex(x, y)], rho[laneIndex(x, y)])
			}
		}
		for Y := 0; Y < 5; Y++ {
			for X := 0; X < 5; X++ {
				a[laneIndex(X, Y)] = b[laneIndex(X, Y)] ^ (^b[laneIndex(X+1, Y)] & b[laneIndex(X+2, Y)])
			}
		}
		a[0] ^= rc[r]
	}
}

type xmm struct {
	q       [2]uint64
	defined bool
}

type emulator struct {
	t      *testing.T
	x      map[string]*xmm
	gpr    map[string]int64 // DI, SI, CX only
	state  *[25]uint64      // memory at DI
	input  []byte           // memory at the initial SI
	siBase int64
	args   map[string]int64
	rc     [24]uint64
	used   map[string]bool
}

var (
	reXReg = regexp.MustCompile(`^X([0-9]|[12][0-9]|3[01])$`)
	reMem  = regexp.MustCompile(`^(?:(-?\d+)\((DI|SI)\)|·roundConstant\+(\d+)\(SB\))$`)
)

func (e *emulator) reg(name string) *xmm {
	if !reXReg.MatchString(name) {
		e.t.Fatalf("operand %q is not an XMM register", name)
	}
	if name == "X15" {
		e.t.Fatalf("X15 is reserved by the Go ABI and must not be used")
	}
	e.used[name] = true
	r, ok := e.x[name]
	if !ok {
		r = &xmm{}
		e.x[name] = r
	}
	return r
}

func (e *emulator) read(name string) *xmm {
	r := e.reg(name)
	if !r.defined {
		e.t.Fatalf("register %s read before it was written", name)
	}
	return r
}

// load64 returns the 8 bytes at a memory operand, enforcing bounds.
func (e *emulator) load64(op string) uint64 {
	m := reMem.FindStringSubmatch(op)
	if m == nil {
		e.t.Fatalf("unsupported memory operand %q", op)
	}
	if m[3] != "" {
		off, _ := strconv.Atoi(m[3])
		if off%8 != 0 || off < 0 || off >= 8*24 {
			e.t.Fatalf("round-constant access out of range: %s", op)
		}
		return e.rc[off/8]
	}
	off, _ := strconv.ParseInt(m[1], 10, 64)
	switch m[2] {
	case "DI":
		if off%8 != 0 || off < 0 || off >= 200 {
			e.t.Fatalf("state access out of range: %s", op)
		}
		return e.state[off/8]
	}
	// SI: the caller's input.
	pos := e.gpr["SI"] - e.siBase + off
	if off%8 != 0 || off < 0 || off >= 136 || pos < 0 || pos+8 > int64(len(e.input)) {
		e.t.Fatalf("input read out of range: %s at position %d of %d", op, pos, len(e.input))
	}
	var v uint64
	for i := 0; i < 8; i++ {
		v |= uint64(e.input[pos+int64(i)]) << (8 * i)
	}
	return v
}

func (e *emulator) store64(op string, v uint64) {
	m := reMem.FindStringSubmatch(op)
	if m == nil || m[2] != "DI" {
		e.t.Fatalf("store to %q: only the state (DI) may be written", op)
	}
	off, _ := strconv.ParseInt(m[1], 10, 64)
	if off%8 != 0 || off < 0 || off >= 200 {
		e.t.Fatalf("state store out of range: %s", op)
	}
	e.state[off/8] = v
}

func ternary(imm uint64, a, b, c uint64) uint64 {
	var r uint64
	for i := 0; i < 8; i++ {
		if imm>>i&1 == 0 {
			continue
		}
		ta, tb, tc := a, b, c
		if i&4 == 0 {
			ta = ^a
		}
		if i&2 == 0 {
			tb = ^b
		}
		if i&1 == 0 {
			tc = ^c
		}
		r |= ta & tb & tc
	}
	return r
}

func immediate(t *testing.T, s string) uint64 {
	if !strings.HasPrefix(s, "$") {
		t.Fatalf("expected immediate, got %q", s)
	}
	v, err := strconv.ParseUint(strings.TrimPrefix(s, "$"), 0, 64)
	if err != nil {
		t.Fatalf("bad immediate %q", s)
	}
	return v
}

type insn struct {
	op   string
	args []string
	line int
}

// parseFunc returns the instructions of one TEXT symbol and its labels.
func parseFunc(t *testing.T, src, name string) ([]insn, map[string]int) {
	var out []insn
	labels := map[string]int{}
	in := false
	for n, raw := range strings.Split(src, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "TEXT ") {
			in = strings.HasPrefix(line, "TEXT ·"+name+"(SB)")
			continue
		}
		if !in || line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasSuffix(line, ":") {
			labels[strings.TrimSuffix(line, ":")] = len(out)
			continue
		}
		f := strings.Fields(line)
		var args []string
		if len(f) > 1 {
			for _, a := range strings.Split(strings.Join(f[1:], " "), ",") {
				args = append(args, strings.TrimSpace(a))
			}
		}
		out = append(out, insn{f[0], args, n + 1})
	}
	if len(out) == 0 {
		t.Fatalf("function %s not found", name)
	}
	return out, labels
}

func (e *emulator) run(prog []insn, labels map[string]int) {
	steps := 0
	for pc := 0; pc < len(prog); pc++ {
		if steps++; steps > 1_000_000 {
			e.t.Fatal("emulation did not terminate")
		}
		in := prog[pc]
		a := in.args
		fail := func() { e.t.Fatalf("line %d: unexpected %s %v", in.line, in.op, a) }
		switch in.op {
		case "MOVQ":
			// Only argument loads are allowed: MOVQ name+off(FP), REG.
			v, ok := e.args[a[0]]
			if len(a) != 2 || !ok || (a[1] != "DI" && a[1] != "SI" && a[1] != "CX") {
				fail()
			}
			e.gpr[a[1]] = v
		case "VMOVQ":
			if reXReg.MatchString(a[1]) { // load: VMOVQ mem, X (zeroes the upper qword)
				r := e.reg(a[1])
				*r = xmm{q: [2]uint64{e.load64(a[0]), 0}, defined: true}
			} else { // store: VMOVQ X, mem (low qword)
				e.store64(a[1], e.read(a[0]).q[0])
			}
		case "VMOVDQA64":
			src := *e.read(a[0])
			*e.reg(a[1]) = src
		case "VPTERNLOGQ":
			imm := immediate(e.t, a[0])
			c, b, d := e.read(a[1]), e.read(a[2]), e.read(a[3])
			for i := 0; i < 2; i++ {
				d.q[i] = ternary(imm, d.q[i], b.q[i], c.q[i])
			}
		case "VPROLQ":
			n := int(immediate(e.t, a[0]))
			src := *e.read(a[1])
			dst := e.reg(a[2])
			*dst = xmm{q: [2]uint64{bits.RotateLeft64(src.q[0], n), bits.RotateLeft64(src.q[1], n)}, defined: true}
		case "VPXORQ.BCST":
			m := e.load64(a[0])
			src := *e.read(a[1])
			*e.reg(a[2]) = xmm{q: [2]uint64{src.q[0] ^ m, src.q[1] ^ m}, defined: true}
		case "VPXORQ":
			if len(a) != 3 || a[0] != a[1] || a[1] != a[2] {
				fail() // only the zeroing idiom is expected
			}
			*e.reg(a[2]) = xmm{defined: true}
		case "VZEROALL":
			for i := 0; i < 16; i++ {
				name := fmt.Sprintf("X%d", i)
				if r, ok := e.x[name]; ok {
					*r = xmm{defined: true}
				}
			}
		case "TESTQ":
			if len(a) != 2 || a[0] != "CX" || a[1] != "CX" {
				fail()
			}
		case "JZ":
			if e.gpr["CX"] == 0 {
				pc = labels[a[0]] - 1
			}
		case "ADDQ":
			if len(a) != 2 || a[0] != "$136" || a[1] != "SI" {
				fail()
			}
			e.gpr["SI"] += 136
		case "DECQ":
			if len(a) != 1 || a[0] != "CX" {
				fail()
			}
			e.gpr["CX"]--
		case "JNZ":
			if e.gpr["CX"] != 0 {
				pc = labels[a[0]] - 1
			}
		case "RET":
			for name, r := range e.x {
				if r.q != [2]uint64{} {
					e.t.Fatalf("register %s not cleared before RET", name)
				}
			}
			return
		default:
			fail()
		}
	}
	e.t.Fatal("function fell off the end without RET")
}

func newEmulator(t *testing.T, state *[25]uint64, input []byte, nblocks int) *emulator {
	return &emulator{
		t: t, x: map[string]*xmm{}, gpr: map[string]int64{},
		state: state, input: input, siBase: 1 << 20,
		args: map[string]int64{"a+0(FP)": 1 << 30, "p+8(FP)": 1 << 20, "n+16(FP)": int64(nblocks)},
		rc:   roundConstants(), used: map[string]bool{},
	}
}

func TestEmulatedPermuteAVX512(t *testing.T) {
	prog, labels := parseFunc(t, string(genAsm()), "permuteAVX512")
	rng := rand.New(rand.NewSource(11))
	for i := 0; i < 300; i++ {
		var s [25]uint64
		for j := range s {
			s[j] = rng.Uint64()
		}
		want := s
		specPermute(&want)
		got := s
		e := newEmulator(t, &got, nil, 0)
		e.run(prog, labels)
		if got != want {
			t.Fatalf("emulated permuteAVX512 differs from the specification (iteration %d)", i)
		}
		if i == 0 && len(e.used) != 31 {
			t.Fatalf("expected 31 vector registers (all but X15), used %d", len(e.used))
		}
	}
}

func TestEmulatedAbsorbAVX512(t *testing.T) {
	prog, labels := parseFunc(t, string(genAsm()), "absorbAVX512")
	rng := rand.New(rand.NewSource(12))
	for _, n := range []int{0, 1, 2, 3, 7} {
		input := make([]byte, n*136) // exact size: any over-read fails
		rng.Read(input)
		var s [25]uint64
		for j := range s {
			s[j] = rng.Uint64()
		}
		want := s
		for b := 0; b < n; b++ {
			for l := 0; l < 17; l++ {
				var v uint64
				for k := 0; k < 8; k++ {
					v |= uint64(input[b*136+8*l+k]) << (8 * k)
				}
				want[l] ^= v
			}
			specPermute(&want)
		}
		got := s
		newEmulator(t, &got, input, n).run(prog, labels)
		if got != want {
			t.Fatalf("emulated absorbAVX512 differs from the specification (n=%d)", n)
		}
	}
}

// The ternary-logic immediates must encode exactly the intended functions.
func TestTernaryImmediates(t *testing.T) {
	xor3 := ternImm(func(a, b, c bool) bool { return a != b != c })
	chi := ternImm(func(a, b, c bool) bool { return a != (!b && c) })
	if xor3 != 0x96 || chi != 0xd2 {
		t.Fatalf("xor3=%#x chi=%#x, want 0x96 and 0xd2", xor3, chi)
	}
	rng := rand.New(rand.NewSource(13))
	for i := 0; i < 1000; i++ {
		a, b, c := rng.Uint64(), rng.Uint64(), rng.Uint64()
		if ternary(uint64(xor3), a, b, c) != a^b^c || ternary(uint64(chi), a, b, c) != a^(^b&c) {
			t.Fatal("ternary emulation mismatch")
		}
	}
}
