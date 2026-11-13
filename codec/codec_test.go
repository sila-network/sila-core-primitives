// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package codec

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"math/rand"
	"strings"
	"testing"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// node is a decoded value for the tests.
type node struct {
	list  bool
	str   []byte
	items []node
}

func str(s string) node       { return node{str: []byte(s)} }
func list(items ...node) node { return node{list: true, items: items} }

// refEncode is an independent recursive encoder written from the format
// table in the package documentation; it does not call package code.
func refEncode(n node) []byte {
	var content []byte
	var short byte = 0x80
	if n.list {
		short = 0xc0
		for _, it := range n.items {
			content = append(content, refEncode(it)...)
		}
	} else {
		if len(n.str) == 1 && n.str[0] <= 0x7f {
			return []byte{n.str[0]}
		}
		content = n.str
	}
	var hdr []byte
	if len(content) < 56 {
		hdr = []byte{short + byte(len(content))}
	} else {
		var lb []byte
		for l := uint64(len(content)); l > 0; l >>= 8 {
			lb = append([]byte{byte(l)}, lb...)
		}
		hdr = append([]byte{short + 55 + byte(len(lb))}, lb...)
	}
	return append(hdr, content...)
}

// lenientParse decodes one value and accepts non-canonical sizes (it only
// checks bounds). It is the test model of "structurally decodable".
func lenientParse(b []byte) (n node, rest []byte, ok bool) {
	if len(b) == 0 {
		return n, nil, false
	}
	p := b[0]
	var hdr int
	var size uint64
	isList := p >= 0xc0
	base := byte(0x80)
	if isList {
		base = 0xc0
	}
	switch {
	case p < 0x80:
		return node{str: b[:1]}, b[1:], true
	case p-base <= 55:
		hdr, size = 1, uint64(p-base)
	default:
		ll := int(p - base - 55)
		if len(b) < 1+ll {
			return n, nil, false
		}
		for _, c := range b[1 : 1+ll] {
			size = size<<8 | uint64(c)
		}
		hdr = 1 + ll
	}
	if size > uint64(len(b)-hdr) {
		return n, nil, false
	}
	content := b[hdr : hdr+int(size)]
	rest = b[hdr+int(size):]
	if !isList {
		return node{str: content}, rest, true
	}
	n.list = true
	n.items = []node{}
	for len(content) > 0 {
		it, r, ok := lenientParse(content)
		if !ok {
			return n, nil, false
		}
		n.items = append(n.items, it)
		content = r
	}
	return n, rest, true
}

// isCanonical is the model of Validate: b is one structurally decodable
// value and is the unique encoding of that value.
func isCanonical(b []byte) bool {
	n, rest, ok := lenientParse(b)
	return ok && len(rest) == 0 && bytes.Equal(refEncode(n), b)
}

// build encodes n with the Builder.
func build(b *Builder, n node) {
	if !n.list {
		b.String(n.str)
		return
	}
	b.StartList()
	for _, it := range n.items {
		build(b, it)
	}
	b.EndList()
}

// decodeStrict decodes n with Split only (strict path).
func decodeStrict(t testing.TB, b []byte) node {
	t.Helper()
	k, content, rest, err := Split(b)
	if err != nil || len(rest) != 0 {
		t.Fatalf("Split(%x): %v, rest %d", b, err, len(rest))
	}
	if k == KindString {
		return node{str: content}
	}
	n := node{list: true, items: []node{}}
	for len(content) > 0 {
		_, _, r, err := Split(content)
		if err != nil {
			t.Fatalf("Split item: %v", err)
		}
		n.items = append(n.items, decodeStrict(t, content[:len(content)-len(r)]))
		content = r
	}
	return n
}

func equalNode(a, b node) bool {
	if a.list != b.list {
		return false
	}
	if !a.list {
		return bytes.Equal(a.str, b.str)
	}
	if len(a.items) != len(b.items) {
		return false
	}
	for i := range a.items {
		if !equalNode(a.items[i], b.items[i]) {
			return false
		}
	}
	return true
}

// Published examples of the format, plus the size boundaries.
func TestVectors(t *testing.T) {
	lorem := "Lorem ipsum dolor sit amet, consectetur adipisicing elit" // 56 bytes
	cases := []struct {
		name string
		v    node
		enc  string
	}{
		{"empty string", str(""), "80"},
		{"byte 0x00", node{str: []byte{0}}, "00"},
		{"byte 0x0f", node{str: []byte{0x0f}}, "0f"},
		{"byte 0x7f", node{str: []byte{0x7f}}, "7f"},
		{"byte 0x80", node{str: []byte{0x80}}, "8180"},
		{"byte 0xff", node{str: []byte{0xff}}, "81ff"},
		{"dog", str("dog"), "83646f67"},
		{"cat dog", list(str("cat"), str("dog")), "c88363617483646f67"},
		{"empty list", list(), "c0"},
		{"nested empty lists", list(list(), list(list()), list(list(), list(list()))), "c7c0c1c0c3c0c1c0"},
		{"56-byte string", str(lorem), "b838" + hex.EncodeToString([]byte(lorem))},
		{"55-byte string", str(strings.Repeat("a", 55)), "b7" + strings.Repeat("61", 55)},
		{"255-byte string", str(strings.Repeat("a", 255)), "b8ff" + strings.Repeat("61", 255)},
		{"256-byte string", str(strings.Repeat("a", 256)), "b90100" + strings.Repeat("61", 256)},
		{"list content 55", list(str(strings.Repeat("a", 53))), "f6b5" + strings.Repeat("61", 53)},
		{"list content 55 exactly", list(str(strings.Repeat("a", 54))), "f7b6" + strings.Repeat("61", 54)},
		{"list content 56", list(str(strings.Repeat("a", 55))), "f838b7" + strings.Repeat("61", 55)},
		{"list content 58", list(str(lorem)), "f83ab838" + hex.EncodeToString([]byte(lorem))},
	}
	for _, c := range cases {
		want := unhex(t, c.enc)
		if got := refEncode(c.v); !bytes.Equal(got, want) {
			t.Fatalf("%s: reference encoder %x, want %x", c.name, got, want)
		}
		var b Builder
		build(&b, c.v)
		got, err := b.Bytes()
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s: Builder %x (%v), want %x", c.name, got, err, want)
		}
		if !c.v.list {
			if got := AppendString(nil, c.v.str); !bytes.Equal(got, want) {
				t.Errorf("%s: AppendString %x, want %x", c.name, got, want)
			}
			if StringSize(len(c.v.str), append(c.v.str, 0)[0]) != len(want) {
				t.Errorf("%s: StringSize", c.name)
			}
		}
		if err := Validate(want); err != nil {
			t.Errorf("%s: Validate: %v", c.name, err)
		}
		if got := decodeStrict(t, want); !equalNode(got, c.v) {
			t.Errorf("%s: decoded value differs", c.name)
		}
	}
}

func TestIntegers(t *testing.T) {
	u64 := []struct {
		v   uint64
		enc string
	}{
		{0, "80"}, {1, "01"}, {0x0f, "0f"}, {0x7f, "7f"}, {0x80, "8180"}, {0xff, "81ff"},
		{0x100, "820100"}, {1024, "820400"}, {0xffffff, "83ffffff"}, {1 << 24, "8401000000"},
		{1 << 56, "880100000000000000"}, {math.MaxUint64, "88ffffffffffffffff"},
	}
	for _, c := range u64 {
		want := unhex(t, c.enc)
		if got := AppendUint64(nil, c.v); !bytes.Equal(got, want) {
			t.Errorf("AppendUint64(%d) = %x, want %x", c.v, got, want)
		}
		v, rest, err := SplitUint64(append(want, 0xaa))
		if err != nil || v != c.v || !bytes.Equal(rest, []byte{0xaa}) {
			t.Errorf("SplitUint64(%x) = %d, %x, %v", want, v, rest, err)
		}
		var w [32]byte
		for i := 0; i < 8; i++ {
			w[31-i] = byte(c.v >> (8 * i))
		}
		if got := AppendUint256(nil, &w); !bytes.Equal(got, want) {
			t.Errorf("AppendUint256(%d) = %x, want %x", c.v, got, want)
		}
		v256, _, err := SplitUint256(want)
		if err != nil || v256 != w {
			t.Errorf("SplitUint256(%x) = %x, %v", want, v256, err)
		}
	}
	var max, top [32]byte
	for i := range max {
		max[i] = 0xff
	}
	top[0] = 0x80
	for _, w := range [][32]byte{max, top} {
		enc := AppendUint256(nil, &w)
		if len(enc) != 33 || enc[0] != 0xa0 || !bytes.Equal(enc[1:], w[:]) {
			t.Errorf("AppendUint256(%x) = %x", w, enc)
		}
		got, rest, err := SplitUint256(enc)
		if err != nil || got != w || len(rest) != 0 {
			t.Errorf("SplitUint256: %x %v", got, err)
		}
	}

	bad := []struct {
		enc     string
		err64   error
		err256  error
		comment string
	}{
		{"00", ErrNonCanonicalInteger, ErrNonCanonicalInteger, "zero written as the byte 0x00"},
		{"820001", ErrNonCanonicalInteger, ErrNonCanonicalInteger, "leading zero"},
		{"8100", ErrNonCanonicalSize, ErrNonCanonicalSize, "single byte with a header"},
		{"89010000000000000000", ErrIntegerTooLarge, nil, "65 bits"},
		{"a1" + strings.Repeat("01", 33), ErrIntegerTooLarge, ErrIntegerTooLarge, "264 bits"},
		{"c0", ErrExpectedString, ErrExpectedString, "list"},
		{"", ErrUnexpectedEnd, ErrUnexpectedEnd, "empty input"},
		{"8201", ErrUnexpectedEnd, ErrUnexpectedEnd, "truncated"},
	}
	for _, c := range bad {
		in := unhex(t, c.enc)
		if _, rest, err := SplitUint64(in); !errors.Is(err, c.err64) || !bytes.Equal(rest, in) {
			t.Errorf("SplitUint64(%s) [%s]: %v, want %v", c.enc, c.comment, err, c.err64)
		}
		_, _, err := SplitUint256(in)
		if c.err256 == nil {
			if err != nil {
				t.Errorf("SplitUint256(%s) [%s]: %v", c.enc, c.comment, err)
			}
		} else if !errors.Is(err, c.err256) {
			t.Errorf("SplitUint256(%s) [%s]: %v, want %v", c.enc, c.comment, err, c.err256)
		}
	}
}

func TestRejects(t *testing.T) {
	cases := []struct {
		enc string
		err error
	}{
		{"", ErrUnexpectedEnd},
		{"81", ErrUnexpectedEnd},
		{"8100", ErrNonCanonicalSize},
		{"817f", ErrNonCanonicalSize},
		{"8161", ErrNonCanonicalSize},
		{"82", ErrUnexpectedEnd},
		{"8261", ErrUnexpectedEnd},
		{"b7" + strings.Repeat("61", 54), ErrUnexpectedEnd},
		{"b8", ErrUnexpectedEnd},
		{"b800", ErrNonCanonicalSize},
		{"b801" + "61", ErrNonCanonicalSize},
		{"b837" + strings.Repeat("61", 55), ErrNonCanonicalSize},
		{"b838" + strings.Repeat("61", 55), ErrUnexpectedEnd},
		{"b90038" + strings.Repeat("61", 56), ErrNonCanonicalSize},
		{"b9" + "0100", ErrUnexpectedEnd},
		{"bf" + "ffffffffffffffff", ErrUnexpectedEnd},
		{"bf" + "7fffffffffffffff" + "00", ErrUnexpectedEnd},
		{"bf" + "0000000000000038", ErrNonCanonicalSize},
		{"bf" + "ffffffff", ErrUnexpectedEnd},
		{"c1", ErrUnexpectedEnd},
		{"f800", ErrNonCanonicalSize},
		{"f837" + strings.Repeat("01", 55), ErrNonCanonicalSize},
		{"f838", ErrUnexpectedEnd},
		{"ff" + "ffffffffffffffff", ErrUnexpectedEnd},
		// Items that are invalid inside a valid list header.
		{"c28161", ErrNonCanonicalSize},
		{"c28261", ErrUnexpectedEnd},
		{"c3c28261", ErrUnexpectedEnd},
		{"c2c182", ErrUnexpectedEnd}, // inner list holds 1 byte, item 0x82 needs 3
		{"c4c3b80161", ErrNonCanonicalSize},
		// Trailing data.
		{"8000", ErrTrailingData},
		{"c0c0", ErrTrailingData},
		{"0101", ErrTrailingData},
	}
	for _, c := range cases {
		in := unhex(t, c.enc)
		if err := Validate(in); !errors.Is(err, c.err) {
			t.Errorf("Validate(%s) = %v, want %v", c.enc, err, c.err)
		}
		if isCanonical(in) {
			t.Errorf("model accepts %s", c.enc)
		}
	}
}

func TestSplitKinds(t *testing.T) {
	in := unhex(t, "c88363617483646f67"+"83646f67")
	content, rest, err := SplitList(in)
	if err != nil || hex.EncodeToString(content) != "8363617483646f67" || hex.EncodeToString(rest) != "83646f67" {
		t.Fatalf("SplitList: %x %x %v", content, rest, err)
	}
	if n, err := Count(content); n != 2 || err != nil {
		t.Fatalf("Count = %d, %v", n, err)
	}
	if n, err := Count(nil); n != 0 || err != nil {
		t.Fatalf("Count(nil) = %d, %v", n, err)
	}
	if _, err := Count(unhex(t, "8363617483")); !errors.Is(err, ErrUnexpectedEnd) {
		t.Fatalf("Count truncated: %v", err)
	}
	if _, _, err := SplitString(in); !errors.Is(err, ErrExpectedString) {
		t.Fatalf("SplitString on list: %v", err)
	}
	if _, _, err := SplitList(unhex(t, "c1")); !errors.Is(err, ErrUnexpectedEnd) {
		t.Fatalf("SplitList truncated: %v", err)
	}
	if _, _, err := SplitList(rest); !errors.Is(err, ErrExpectedList) {
		t.Fatalf("SplitList on string: %v", err)
	}
	s, r, err := SplitString(rest)
	if err != nil || string(s) != "dog" || len(r) != 0 {
		t.Fatalf("SplitString: %q %x %v", s, r, err)
	}
	if KindString.String() != "string" || KindList.String() != "list" || Kind(9).String() != "invalid kind" {
		t.Fatal("Kind.String")
	}
	// On error, rest is the unchanged input.
	bad := unhex(t, "8100")
	if _, _, r, err := Split(bad); err == nil || !bytes.Equal(r, bad) {
		t.Fatal("Split error must return the input as rest")
	}
}

func randomNode(r *rand.Rand, depth int) node {
	if depth > 0 && r.Intn(3) == 0 {
		n := node{list: true, items: []node{}}
		for i := r.Intn(6); i > 0; i-- {
			n.items = append(n.items, randomNode(r, depth-1))
		}
		return n
	}
	var size int
	switch r.Intn(10) {
	case 0:
		size = 0
	case 1:
		size = 1
	case 2:
		size = 54 + r.Intn(4) // 54..57 around the short/long boundary
	case 3:
		size = 250 + r.Intn(10) // one/two length bytes
	case 4:
		if r.Intn(20) == 0 {
			size = 65530 + r.Intn(12) // two/three length bytes
		}
	default:
		size = r.Intn(40)
	}
	s := make([]byte, size)
	r.Read(s)
	if size == 1 && r.Intn(2) == 0 {
		s[0] &= 0x7f
	}
	return node{str: s}
}

// Builder, reference encoder, strict decoder and Validate agree on random
// values; the strict decoder recovers the value.
func TestRandomRoundTrip(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	n := 3000
	if testing.Short() {
		n = 300
	}
	var b Builder
	for i := 0; i < n; i++ {
		v := randomNode(r, 5)
		want := refEncode(v)
		b.Reset()
		build(&b, v)
		if b.Len() != len(want) {
			t.Fatalf("Len = %d, want %d", b.Len(), len(want))
		}
		got, err := b.Bytes()
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("Builder differs from reference encoder for %x", want)
		}
		if err := Validate(got); err != nil {
			t.Fatalf("Validate: %v", err)
		}
		if !equalNode(decodeStrict(t, got), v) {
			t.Fatal("decoded value differs")
		}
		if v.list {
			var content []byte
			for _, it := range v.items {
				content = append(content, refEncode(it)...)
			}
			if h := AppendListHeader(nil, len(content)); !bytes.Equal(append(h, content...), want) {
				t.Fatal("AppendListHeader")
			}
			if ListSize(len(content)) != len(want) {
				t.Fatal("ListSize")
			}
		}
		// Raw re-adds a complete value.
		var b2 Builder
		b2.StartList()
		if err := b2.Raw(got); err != nil {
			t.Fatal(err)
		}
		b2.EndList()
		wrapped, _ := b2.Bytes()
		if !bytes.Equal(wrapped, refEncode(list(v))) {
			t.Fatal("Raw inside a list")
		}
	}
}

// Every input of one or two bytes, and three-byte inputs whose last byte is
// a boundary value: Validate accepts exactly the canonical encodings.
func TestExhaustiveShortInputs(t *testing.T) {
	check := func(in []byte) {
		got := Validate(in) == nil
		if want := isCanonical(in); got != want {
			t.Fatalf("Validate(%x) accepts = %v, model %v", in, got, want)
		}
	}
	third := []byte{0x00, 0x01, 0x37, 0x38, 0x7f, 0x80, 0x81, 0xb7, 0xb8, 0xbf, 0xc0, 0xc1, 0xf7, 0xf8, 0xff}
	if testing.Short() {
		third = third[:4]
	}
	accepted := 0
	for x := 0; x < 256; x++ {
		check([]byte{byte(x)})
		for y := 0; y < 256; y++ {
			check([]byte{byte(x), byte(y)})
			for _, z := range third {
				in := []byte{byte(x), byte(y), z}
				check(in)
				if Validate(in) == nil {
					accepted++
				}
			}
		}
	}
	if accepted == 0 {
		t.Fatal("no three-byte input accepted")
	}
}

func TestBuilderMisuse(t *testing.T) {
	var b Builder
	b.StartList()
	b.Uint64(1)
	if _, err := b.Bytes(); !errors.Is(err, ErrOpenList) {
		t.Fatalf("Bytes with an open list: %v", err)
	}
	dst := []byte{1, 2}
	if out, err := b.AppendTo(dst); !errors.Is(err, ErrOpenList) || !bytes.Equal(out, dst) {
		t.Fatal("AppendTo with an open list")
	}
	b.EndList()
	out, err := b.AppendTo(dst)
	if err != nil || hex.EncodeToString(out) != "0102c101" {
		t.Fatalf("AppendTo = %x, %v", out, err)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("EndList without StartList did not panic")
			}
		}()
		b.EndList()
	}()
	func() {
		defer func() {
			if recover() == nil {
				t.Error("negative list size did not panic")
			}
		}()
		AppendListHeader(nil, -1)
	}()
	if err := b.Raw(unhex(t, "8100")); err == nil {
		t.Error("Raw accepted a non-canonical value")
	}
	if err := b.Raw(unhex(t, "8080")); !errors.Is(err, ErrTrailingData) {
		t.Error("Raw accepted two values")
	}
	if got, _ := b.Bytes(); hex.EncodeToString(got) != "c101" {
		t.Errorf("failed Raw changed the output: %x", got)
	}
	b.Reset()
	if got, err := b.Bytes(); err != nil || len(got) != 0 || b.Len() != 0 {
		t.Errorf("after Reset: %x %v", got, err)
	}
	// Several top-level values are concatenated.
	b.Uint64(0)
	b.StartList()
	b.EndList()
	var w [32]byte
	w[31] = 0x80
	b.Uint256(&w)
	if got, _ := b.Bytes(); hex.EncodeToString(got) != "80c08180" {
		t.Errorf("top-level values: %x", got)
	}
}

// Deep nesting: the Builder is linear and Validate does not recurse.
func TestDeepNesting(t *testing.T) {
	const depth = 200000
	var b Builder
	for i := 0; i < depth; i++ {
		b.StartList()
	}
	b.String([]byte("x"))
	for i := 0; i < depth; i++ {
		b.EndList()
	}
	enc, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(enc); err != nil {
		t.Fatal(err)
	}
	// Corrupt the innermost item: the error is found at the bottom.
	enc[len(enc)-1] = 0x81
	if err := Validate(enc); err == nil {
		t.Fatal("corrupted deep value accepted")
	}
}

// Large sizes on 32- and 64-bit platforms: sizes above the input are
// rejected before any conversion to int.
func TestLargeSizes(t *testing.T) {
	big := make([]byte, 1<<17)
	enc := AppendString(nil, big)
	if hex.EncodeToString(enc[:4]) != "ba020000" {
		t.Fatalf("header %x", enc[:4])
	}
	if err := Validate(enc); err != nil {
		t.Fatal(err)
	}
	if err := Validate(enc[:len(enc)-1]); !errors.Is(err, ErrUnexpectedEnd) {
		t.Fatal(err)
	}
	for n := 1; n <= 8; n++ {
		for _, first := range []byte{0x80, 0xff} {
			h := []byte{0xb7 + byte(n), first}
			for i := 1; i < n; i++ {
				h = append(h, 0xff)
			}
			if _, _, _, err := Split(h); !errors.Is(err, ErrUnexpectedEnd) {
				t.Errorf("Split(%x) = %v", h, err)
			}
		}
	}
}

func TestNoAllocations(t *testing.T) {
	enc := unhex(t, "f86c"+"01"+"8504a817c800"+"825208"+"94"+strings.Repeat("aa", 20)+"880de0b6b3a7640000"+"80"+"25"+"a0"+strings.Repeat("11", 32)+"a0"+strings.Repeat("22", 32))
	if testing.Short() {
		t.Skip("allocation counts")
	}
	if err := Validate(enc); err != nil {
		t.Fatal(err)
	}
	if n := testing.AllocsPerRun(100, func() {
		content, _, _ := SplitList(enc)
		for len(content) > 0 {
			_, _, content, _ = Split(content)
		}
		_, _ = Count(content)
		_ = Validate(enc)
		_, _, _ = SplitUint64(enc[2:])
		_, _, _ = SplitUint256(enc[2:])
	}); n != 0 {
		t.Errorf("decoding allocates %v times", n)
	}
	dst := make([]byte, 0, 256)
	var w [32]byte
	if n := testing.AllocsPerRun(100, func() {
		d := AppendListHeader(dst, 75)
		d = AppendUint64(d, 1)
		d = AppendString(d, enc[:20])
		_ = AppendUint256(d, &w)
	}); n != 0 {
		t.Errorf("encoding allocates %v times", n)
	}
	var b Builder
	build(&b, list(str("a"), list(str("bc"))))
	out := make([]byte, 0, 64)
	if n := testing.AllocsPerRun(100, func() {
		b.Reset()
		b.StartList()
		b.Uint64(7)
		b.String(enc[:30])
		b.StartList()
		b.EndList()
		b.EndList()
		_, _ = b.AppendTo(out)
	}); n != 0 {
		t.Errorf("a reused Builder allocates %v times", n)
	}
}
