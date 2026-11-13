// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

// Differential tests and benchmarks: SILA codec vs the go-ethereum v1.17.10
// rlp package, which implements the same public byte format. go-ethereum is
// a test oracle only; the SILA module does not depend on it.
package gethcompare

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
	"github.com/sila-network/sila-core-primitives/codec"
)

// value is either []byte or []any (nested), the shape go-ethereum encodes
// as a string or a list.
func randomValue(r *rand.Rand, depth int) any {
	if depth > 0 && r.Intn(3) == 0 {
		items := []any{}
		for i := r.Intn(6); i > 0; i-- {
			items = append(items, randomValue(r, depth-1))
		}
		return items
	}
	var n int
	switch r.Intn(10) {
	case 0:
		n = 0
	case 1:
		n = 1
	case 2:
		n = 54 + r.Intn(4)
	case 3:
		n = 250 + r.Intn(10)
	case 4:
		if r.Intn(20) == 0 {
			n = 65530 + r.Intn(12)
		}
	default:
		n = r.Intn(40)
	}
	s := make([]byte, n)
	r.Read(s)
	if n == 1 && r.Intn(2) == 0 {
		s[0] &= 0x7f
	}
	return s
}

func silaBuild(b *codec.Builder, v any) {
	switch v := v.(type) {
	case []byte:
		b.String(v)
	case []any:
		b.StartList()
		for _, it := range v {
			silaBuild(b, it)
		}
		b.EndList()
	}
}

// gethValidate: one value, all nested items decodable by go-ethereum's
// strict raw reader (canonical sizes), nothing after it.
func gethValidate(b []byte) error {
	k, content, rest, err := rlp.Split(b)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return errors.New("trailing data")
	}
	if k != rlp.List {
		return nil
	}
	for len(content) > 0 {
		_, _, r, err := rlp.Split(content)
		if err != nil {
			return err
		}
		if err := gethValidate(content[:len(content)-len(r)]); err != nil {
			return err
		}
		content = r
	}
	return nil
}

func TestCodecEncodingMatchesGeth(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	var b codec.Builder
	const n = 5000
	for i := 0; i < n; i++ {
		v := randomValue(r, 5)
		want, err := rlp.EncodeToBytes(v)
		if err != nil {
			t.Fatal(err)
		}
		b.Reset()
		silaBuild(&b, v)
		got, err := b.Bytes()
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("value %d: SILA %x, go-ethereum %x", i, got, want)
		}
	}
	// Integers: uint64 and 256-bit values, including boundaries.
	u64 := []uint64{0, 1, 0x7f, 0x80, 0xff, 0x100, 1<<56 - 1, 1 << 56, ^uint64(0)}
	for i := 0; i < 20000; i++ {
		u64 = append(u64, r.Uint64()>>(r.Intn(64)))
	}
	for _, x := range u64 {
		want, _ := rlp.EncodeToBytes(x)
		if got := codec.AppendUint64(nil, x); !bytes.Equal(got, want) {
			t.Fatalf("uint64 %d: SILA %x, go-ethereum %x", x, got, want)
		}
	}
	for i := 0; i < 20000; i++ {
		var w [32]byte
		r.Read(w[r.Intn(33):])
		want, _ := rlp.EncodeToBytes(new(big.Int).SetBytes(w[:]))
		if got := codec.AppendUint256(nil, &w); !bytes.Equal(got, want) {
			t.Fatalf("uint256 %x: SILA %x, go-ethereum %x", w, got, want)
		}
		u := new(uint256.Int).SetBytes32(w[:])
		want2, _ := rlp.EncodeToBytes(u)
		if !bytes.Equal(want, want2) {
			t.Fatal("go-ethereum big.Int and uint256 encodings differ")
		}
	}
	t.Logf("%d random values, %d uint64, 20000 uint256: identical bytes", n, len(u64))
}

// mutate returns a variant of enc with random byte edits, truncation or
// extension, the inputs most likely to reach decoder edge cases.
func mutate(r *rand.Rand, enc []byte) []byte {
	m := append([]byte(nil), enc...)
	switch r.Intn(5) {
	case 0:
		if len(m) > 0 {
			m[r.Intn(len(m))] = byte(r.Intn(256))
		}
	case 1:
		if len(m) > 0 {
			m = m[:r.Intn(len(m))]
		}
	case 2:
		m = append(m, byte(r.Intn(256)))
	case 3:
		for i := r.Intn(4); i >= 0 && len(m) > 0; i-- {
			m[r.Intn(len(m))] ^= 1 << r.Intn(8)
		}
	case 4:
		if len(m) > 0 {
			// Replace a header byte with one of the boundary headers.
			hdrs := []byte{0x00, 0x7f, 0x80, 0x81, 0xb7, 0xb8, 0xb9, 0xbf, 0xc0, 0xc1, 0xf7, 0xf8, 0xf9, 0xff}
			m[r.Intn(len(m))] = hdrs[r.Intn(len(hdrs))]
		}
	}
	return m
}

// Accept/reject verdicts of SILA codec.Validate and SplitUint64 equal those
// of go-ethereum's strict raw reader on exhaustive short inputs and on
// random mutations of valid encodings.
func TestCodecDecodingVerdictsMatchGeth(t *testing.T) {
	check := func(in []byte) (accepted bool) {
		sErr, gErr := codec.Validate(in), gethValidate(in)
		if (sErr == nil) != (gErr == nil) {
			t.Fatalf("Validate(%x): SILA %v, go-ethereum %v", in, sErr, gErr)
		}
		sv, sr, sErr := codec.SplitUint64(in)
		gv, gr, gErr := rlp.SplitUint64(in)
		if (sErr == nil) != (gErr == nil) || (sErr == nil && (sv != gv || !bytes.Equal(sr, gr))) {
			t.Fatalf("SplitUint64(%x): SILA %d %v, go-ethereum %d %v", in, sv, sErr, gv, gErr)
		}
		sk, sc, sr, sErr := codec.Split(in)
		gk, gc, gr, gErr := rlp.Split(in)
		if (sErr == nil) != (gErr == nil) {
			t.Fatalf("Split(%x): SILA %v, go-ethereum %v", in, sErr, gErr)
		}
		if sErr == nil && (!bytes.Equal(sc, gc) || !bytes.Equal(sr, gr) || (sk == codec.KindList) != (gk == rlp.List)) {
			t.Fatalf("Split(%x): different result", in)
		}
		if sErr == nil && sk == codec.KindList {
			sn, sErr := codec.Count(sc)
			gn, gErr := rlp.CountValues(gc)
			if (sErr == nil) != (gErr == nil) || (sErr == nil && sn != gn) {
				t.Fatalf("Count(%x): SILA %d %v, go-ethereum %d %v", sc, sn, sErr, gn, gErr)
			}
		}
		return codec.Validate(in) == nil
	}
	total, accepted := 0, 0
	for x := 0; x < 256; x++ {
		for y := -1; y < 256; y++ {
			in := []byte{byte(x)}
			if y >= 0 {
				in = append(in, byte(y))
			}
			for z := -1; z < 256; z++ {
				if z >= 0 {
					if y < 0 {
						continue
					}
					in = append(in[:2], byte(z))
				}
				total++
				if check(in) {
					accepted++
				}
			}
		}
	}
	r := rand.New(rand.NewSource(11))
	var b codec.Builder
	for i := 0; i < 200000; i++ {
		b.Reset()
		silaBuild(&b, randomValue(r, 4))
		enc, _ := b.Bytes()
		if len(enc) > 4096 {
			continue
		}
		total++
		if check(mutate(r, enc)) {
			accepted++
		}
	}
	t.Logf("%d inputs (all of 1 to 3 bytes, and mutated encodings): identical verdicts, %d accepted by both", total, accepted)
}

// FuzzCodecAgainstGeth compares verdicts on arbitrary inputs (run locally
// with -fuzz).
func FuzzCodecAgainstGeth(f *testing.F) {
	f.Add([]byte{0xc8, 0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g'})
	f.Add([]byte{0xb8, 0x38})
	f.Fuzz(func(t *testing.T, in []byte) {
		sErr, gErr := codec.Validate(in), gethValidate(in)
		if (sErr == nil) != (gErr == nil) {
			t.Fatalf("Validate(%x): SILA %v, go-ethereum %v", in, sErr, gErr)
		}
		_, _, sErr = codec.SplitUint64(in)
		_, _, gErr = rlp.SplitUint64(in)
		if (sErr == nil) != (gErr == nil) {
			t.Fatalf("SplitUint64(%x): SILA %v, go-ethereum %v", in, sErr, gErr)
		}
	})
}

// A transaction-shaped list (nine fields: three integers, a 20-byte
// string, a 256-bit integer, data, and three signature integers), as an
// example workload. It is not a SILA transaction format.
type txShape struct {
	Nonce    uint64
	GasPrice uint64
	Gas      uint64
	To       []byte
	Value    [32]byte
	Data     []byte
	V        uint64
	R, S     [32]byte
}

type gethTxShape struct {
	Nonce    uint64
	GasPrice uint64
	Gas      uint64
	To       []byte
	Value    *uint256.Int
	Data     []byte
	V        uint64
	R, S     *uint256.Int
}

func sampleTx() (txShape, gethTxShape) {
	var tx txShape
	tx.Nonce, tx.GasPrice, tx.Gas, tx.V = 42, 20_000_000_000, 21000, 37
	tx.To = bytes.Repeat([]byte{0xaa}, 20)
	tx.Value[24] = 0x0d
	tx.Value[25] = 0xe0
	tx.Data = bytes.Repeat([]byte{0x5a}, 100)
	for i := range tx.R {
		tx.R[i], tx.S[i] = byte(i+1), byte(0x40+i)
	}
	g := gethTxShape{
		Nonce: tx.Nonce, GasPrice: tx.GasPrice, Gas: tx.Gas, To: tx.To, Data: tx.Data, V: tx.V,
		Value: new(uint256.Int).SetBytes32(tx.Value[:]),
		R:     new(uint256.Int).SetBytes32(tx.R[:]),
		S:     new(uint256.Int).SetBytes32(tx.S[:]),
	}
	return tx, g
}

func silaEncodeTx(b *codec.Builder, tx *txShape) {
	b.StartList()
	b.Uint64(tx.Nonce)
	b.Uint64(tx.GasPrice)
	b.Uint64(tx.Gas)
	b.String(tx.To)
	b.Uint256(&tx.Value)
	b.String(tx.Data)
	b.Uint64(tx.V)
	b.Uint256(&tx.R)
	b.Uint256(&tx.S)
	b.EndList()
}

func gethEncodeTx(w rlp.EncoderBuffer, tx *gethTxShape) {
	l := w.List()
	w.WriteUint64(tx.Nonce)
	w.WriteUint64(tx.GasPrice)
	w.WriteUint64(tx.Gas)
	w.WriteBytes(tx.To)
	w.WriteUint256(tx.Value)
	w.WriteBytes(tx.Data)
	w.WriteUint64(tx.V)
	w.WriteUint256(tx.R)
	w.WriteUint256(tx.S)
	w.ListEnd(l)
}

func silaDecodeTx(enc []byte, tx *txShape) error {
	c, _, err := codec.SplitList(enc)
	if err != nil {
		return err
	}
	if tx.Nonce, c, err = codec.SplitUint64(c); err != nil {
		return err
	}
	if tx.GasPrice, c, err = codec.SplitUint64(c); err != nil {
		return err
	}
	if tx.Gas, c, err = codec.SplitUint64(c); err != nil {
		return err
	}
	if tx.To, c, err = codec.SplitString(c); err != nil {
		return err
	}
	if tx.Value, c, err = codec.SplitUint256(c); err != nil {
		return err
	}
	if tx.Data, c, err = codec.SplitString(c); err != nil {
		return err
	}
	if tx.V, c, err = codec.SplitUint64(c); err != nil {
		return err
	}
	if tx.R, c, err = codec.SplitUint256(c); err != nil {
		return err
	}
	if tx.S, c, err = codec.SplitUint256(c); err != nil {
		return err
	}
	if len(c) != 0 {
		return errors.New("extra fields")
	}
	return nil
}

func gethSplitUint256(b []byte, z *uint256.Int) ([]byte, error) {
	s, rest, err := rlp.SplitString(b)
	if err != nil {
		return nil, err
	}
	if len(s) > 32 {
		return nil, errors.New("too large")
	}
	if len(s) > 0 && s[0] == 0 {
		return nil, errors.New("leading zero")
	}
	z.SetBytes(s)
	return rest, nil
}

func gethDecodeTx(enc []byte, tx *gethTxShape) error {
	c, _, err := rlp.SplitList(enc)
	if err != nil {
		return err
	}
	if tx.Nonce, c, err = rlp.SplitUint64(c); err != nil {
		return err
	}
	if tx.GasPrice, c, err = rlp.SplitUint64(c); err != nil {
		return err
	}
	if tx.Gas, c, err = rlp.SplitUint64(c); err != nil {
		return err
	}
	if tx.To, c, err = rlp.SplitString(c); err != nil {
		return err
	}
	if c, err = gethSplitUint256(c, tx.Value); err != nil {
		return err
	}
	if tx.Data, c, err = rlp.SplitString(c); err != nil {
		return err
	}
	if tx.V, c, err = rlp.SplitUint64(c); err != nil {
		return err
	}
	if c, err = gethSplitUint256(c, tx.R); err != nil {
		return err
	}
	if c, err = gethSplitUint256(c, tx.S); err != nil {
		return err
	}
	if len(c) != 0 {
		return errors.New("extra fields")
	}
	return nil
}

func TestCodecTxShapeMatchesGeth(t *testing.T) {
	tx, g := sampleTx()
	var b codec.Builder
	silaEncodeTx(&b, &tx)
	enc, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	w := rlp.NewEncoderBuffer(nil)
	gethEncodeTx(w, &g)
	if want := w.ToBytes(); !bytes.Equal(enc, want) {
		t.Fatalf("SILA %x, go-ethereum %x", enc, want)
	}
	if want, _ := rlp.EncodeToBytes(&g); !bytes.Equal(enc, want) {
		t.Fatalf("SILA %x, go-ethereum reflection %x", enc, want)
	}
	var back txShape
	if err := silaDecodeTx(enc, &back); err != nil || back.Nonce != tx.Nonce || back.Value != tx.Value || back.S != tx.S || !bytes.Equal(back.Data, tx.Data) {
		t.Fatalf("SILA decode: %v", err)
	}
}

var benchSink []byte

func BenchmarkCodec(b *testing.B) {
	tx, g := sampleTx()
	var sb codec.Builder
	silaEncodeTx(&sb, &tx)
	enc, _ := sb.Bytes()

	b.Run("op=encode-tx/impl=sila", func(b *testing.B) {
		b.ReportAllocs()
		var bld codec.Builder
		out := make([]byte, 0, 512)
		for i := 0; i < b.N; i++ {
			bld.Reset()
			silaEncodeTx(&bld, &tx)
			benchSink, _ = bld.AppendTo(out[:0])
		}
	})
	b.Run("op=encode-tx/impl=geth", func(b *testing.B) {
		b.ReportAllocs()
		out := make([]byte, 0, 512)
		for i := 0; i < b.N; i++ {
			w := rlp.NewEncoderBuffer(nil)
			gethEncodeTx(w, &g)
			benchSink = w.AppendToBytes(out[:0])
			w.Flush()
		}
	})
	b.Run("op=encode-tx-reflect/impl=geth", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchSink, _ = rlp.EncodeToBytes(&g)
		}
	})
	b.Run("op=decode-tx/impl=sila", func(b *testing.B) {
		b.ReportAllocs()
		var t txShape
		for i := 0; i < b.N; i++ {
			if err := silaDecodeTx(enc, &t); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("op=decode-tx/impl=geth", func(b *testing.B) {
		b.ReportAllocs()
		t := gethTxShape{Value: new(uint256.Int), R: new(uint256.Int), S: new(uint256.Int)}
		for i := 0; i < b.N; i++ {
			if err := gethDecodeTx(enc, &t); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("op=decode-tx-reflect/impl=geth", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var t gethTxShape
			if err := rlp.DecodeBytes(enc, &t); err != nil {
				b.Fatal(err)
			}
		}
	})

	// A list of 1000 32-byte strings and a nested value: full validation.
	var big codec.Builder
	big.StartList()
	for i := 0; i < 1000; i++ {
		big.String(bytes.Repeat([]byte{byte(i)}, 32))
	}
	big.EndList()
	flat, _ := big.Bytes()
	// Nested lists of short strings (no long string dominating the size).
	var nb codec.Builder
	var fill func(depth int)
	fill = func(depth int) {
		nb.StartList()
		for i := 0; i < 4; i++ {
			if depth > 0 {
				fill(depth - 1)
			} else {
				nb.String(bytes.Repeat([]byte{0x41}, 8+i))
			}
		}
		nb.EndList()
	}
	fill(5)
	nested, _ := nb.Bytes()
	for _, in := range []struct {
		name string
		enc  []byte
	}{{"flat-1000x32", flat}, {fmt.Sprintf("nested-%dB", len(nested)), nested}} {
		in := in
		b.Run("op=validate-"+in.name+"/impl=sila", func(b *testing.B) {
			b.SetBytes(int64(len(in.enc)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if err := codec.Validate(in.enc); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("op=validate-"+in.name+"/impl=geth", func(b *testing.B) {
			b.SetBytes(int64(len(in.enc)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if err := gethValidate(in.enc); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
