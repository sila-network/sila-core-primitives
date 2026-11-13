// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package codec

import (
	"bytes"
	"testing"
)

func addSeeds(f *testing.F) {
	for _, s := range []string{
		"", "00", "7f", "80", "8180", "8100", "83646f67", "c0", "c7c0c1c0c3c0c1c0",
		"b838", "b800", "f838", "c28161", "c88363617483646f67", "bf0000000000000038",
		"820001", "88ffffffffffffffff", "89010000000000000000",
	} {
		b := make([]byte, len(s)/2)
		for i := range b {
			var v byte
			for _, c := range s[2*i : 2*i+2] {
				v <<= 4
				if c <= '9' {
					v |= byte(c - '0')
				} else {
					v |= byte(c-'a') + 10
				}
			}
			b[i] = v
		}
		f.Add(b)
	}
}

// Validate accepts exactly the inputs that decode to a value whose unique
// encoding is the input; accepted inputs round-trip through the Builder.
func FuzzValidate(f *testing.F) {
	addSeeds(f)
	f.Fuzz(func(t *testing.T, in []byte) {
		err := Validate(in)
		if want := isCanonical(in); (err == nil) != want {
			t.Fatalf("Validate(%x) = %v, model accepts = %v", in, err, want)
		}
		if err != nil {
			return
		}
		var b Builder
		build(&b, decodeStrict(t, in))
		out, err := b.Bytes()
		if err != nil || !bytes.Equal(out, in) {
			t.Fatalf("round trip %x -> %x", in, out)
		}
		if n, err := Count(in); err != nil || n != 1 {
			t.Fatalf("Count(one value) = %d, %v", n, err)
		}
	})
}

// Integers: an accepted encoding re-encodes to itself; every uint64
// round-trips.
func FuzzIntegers(f *testing.F) {
	addSeeds(f)
	f.Fuzz(func(t *testing.T, in []byte) {
		if v, rest, err := SplitUint64(in); err == nil {
			if got := AppendUint64(nil, v); !bytes.Equal(got, in[:len(in)-len(rest)]) {
				t.Fatalf("SplitUint64(%x) = %d re-encodes to %x", in, v, got)
			}
		}
		if v, rest, err := SplitUint256(in); err == nil {
			if got := AppendUint256(nil, &v); !bytes.Equal(got, in[:len(in)-len(rest)]) {
				t.Fatalf("SplitUint256(%x) re-encodes to %x", in, got)
			}
		}
		var x uint64
		for i := 0; i < 8 && i < len(in); i++ {
			x = x<<8 | uint64(in[i])
		}
		enc := AppendUint64(nil, x)
		if v, rest, err := SplitUint64(enc); err != nil || v != x || len(rest) != 0 {
			t.Fatalf("uint64 %d: %x -> %d, %v", x, enc, v, err)
		}
	})
}

// A random program of Builder operations produces the same bytes as the
// reference encoder applied to the same value.
func FuzzBuilder(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 0, 4, 1, 1})
	f.Fuzz(func(t *testing.T, prog []byte) {
		var b Builder
		type frame struct{ items []node }
		stack := []frame{{}}
		for i := 0; i < len(prog); i++ {
			switch op := prog[i] % 4; op {
			case 0:
				b.StartList()
				stack = append(stack, frame{items: []node{}})
			case 1:
				if len(stack) == 1 {
					continue
				}
				b.EndList()
				top := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				stack[len(stack)-1].items = append(stack[len(stack)-1].items, node{list: true, items: top.items})
			default:
				n := 0
				if i+1 < len(prog) {
					i++
					n = int(prog[i]) % 70
				}
				s := bytes.Repeat([]byte{byte(n * 7)}, n)
				b.String(s)
				stack[len(stack)-1].items = append(stack[len(stack)-1].items, node{str: s})
			}
		}
		for len(stack) > 1 {
			b.EndList()
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			stack[len(stack)-1].items = append(stack[len(stack)-1].items, node{list: true, items: top.items})
		}
		var want []byte
		for _, it := range stack[0].items {
			want = append(want, refEncode(it)...)
		}
		got, err := b.Bytes()
		if err != nil || !bytes.Equal(got, want) || b.Len() != len(want) {
			t.Fatalf("Builder %x, reference %x", got, want)
		}
	})
}
