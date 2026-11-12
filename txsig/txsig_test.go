// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package txsig

import (
	"encoding/hex"
	"math/big"
	"math/rand"
	"strconv"
	"testing"

	"github.com/sila-network/sila-core-primitives/keccak"
	"github.com/sila-network/sila-core-primitives/secp256k1"
)

var (
	bigN, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	halfN   = new(big.Int).Rsh(bigN, 1)
)

func b32(v *big.Int) [32]byte {
	var out [32]byte
	v.FillBytes(out[:])
	return out
}

func key(t *testing.T, hexKey string) *secp256k1.PrivateKey {
	t.Helper()
	b, _ := hex.DecodeString(hexKey)
	k, err := secp256k1.ParsePrivateKey(b)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// The rules mirror go-ethereum's crypto.ValidateSignatureValues
// (homestead=true for Strict, false for RecoveryCompatible).
func TestParseValuesRules(t *testing.T) {
	one := big.NewInt(1)
	vals := []*big.Int{
		big.NewInt(0), one, halfN, new(big.Int).Add(halfN, one),
		new(big.Int).Sub(bigN, one), bigN, new(big.Int).Add(bigN, one),
		new(big.Int).Sub(new(big.Int).Lsh(one, 256), one),
	}
	ref := func(v byte, r, s *big.Int, homestead bool) bool {
		if r.Cmp(one) < 0 || s.Cmp(one) < 0 {
			return false
		}
		if homestead && s.Cmp(halfN) > 0 {
			return false
		}
		return r.Cmp(bigN) < 0 && s.Cmp(bigN) < 0 && (v == 0 || v == 1)
	}
	for _, r := range vals {
		for _, s := range vals {
			for _, v := range []byte{0, 1, 2, 3, 4, 27, 28, 255} {
				_, e1 := ParseValues(b32(r), b32(s), v, Strict)
				_, e2 := ParseValues(b32(r), b32(s), v, RecoveryCompatible)
				if (e1 == nil) != ref(v, r, s, true) || (e2 == nil) != ref(v, r, s, false) {
					t.Fatalf("r=%x s=%x v=%d strict=%v relax=%v", r, s, v, e1 == nil, e2 == nil)
				}
			}
		}
	}
	if _, err := ParseValues(b32(one), b32(one), 0, Rule(7)); err == nil {
		t.Fatal("unknown rule accepted")
	}
	if _, err := Parse(make([]byte, 64), Strict); err == nil {
		t.Fatal("wrong length accepted")
	}
}

func TestRecoverUnderBothRules(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 30; i++ {
		priv, _ := secp256k1.GeneratePrivateKey(rng)
		pub, _ := priv.PublicKey()
		var d [32]byte
		rng.Read(d[:])
		sig, _ := secp256k1.Sign(priv, d)
		v, _ := sig.RecoveryID()
		if v > 1 {
			continue
		}
		r, s := sig.R(), sig.S()
		for _, rule := range []Rule{Strict, RecoveryCompatible} {
			got, err := Recover(d, r, s, v, rule)
			if err != nil || !got.Equal(pub) {
				t.Fatal("recovery failed")
			}
		}
		hs := b32(new(big.Int).Sub(bigN, new(big.Int).SetBytes(s[:])))
		if _, err := Recover(d, r, hs, v^1, Strict); err == nil {
			t.Fatal("Strict accepted high-S")
		}
		got, err := Recover(d, r, hs, v^1, RecoveryCompatible)
		if err != nil || !got.Equal(pub) {
			t.Fatal("RecoveryCompatible did not recover high-S")
		}
		if _, err := Recover(d, r, s, v|2, RecoveryCompatible); err == nil {
			t.Fatal("v >= 2 accepted at the transaction layer")
		}
	}
}

func TestLegacyV(t *testing.T) {
	for v := 0; v < 256; v++ {
		e, err := LegacyV(byte(v))
		if (err == nil) != (v <= 1) || (err == nil && e != byte(v)+27) {
			t.Fatalf("LegacyV(%d)", v)
		}
		d, err := FromLegacyV(byte(v))
		if (err == nil) != (v == 27 || v == 28) || (err == nil && d != byte(v-27)) {
			t.Fatalf("FromLegacyV(%d)", v)
		}
	}
}

func TestChainV(t *testing.T) {
	cases := []struct {
		v     byte
		chain uint64
		want  uint64
		ok    bool
	}{
		{0, 1, 37, true}, {1, 1, 38, true},
		{0, 1337, 2709, true}, {1, 1337, 2710, true},
		{0, maxChainID, 1<<64 - 3, true}, {1, maxChainID, 1<<64 - 2, true},
		{0, maxChainID + 1, 0, false}, {0, 0, 0, false}, {2, 1, 0, false},
	}
	for _, c := range cases {
		got, err := ChainV(c.v, c.chain)
		if (err == nil) != c.ok || got != c.want {
			t.Fatalf("ChainV(%d, %d) = %d, %v", c.v, c.chain, got, err)
		}
		if c.ok {
			back, err := FromChainV(got, c.chain)
			if err != nil || back != c.v {
				t.Fatalf("FromChainV(%d, %d)", got, c.chain)
			}
		}
	}
	for _, bad := range []uint64{0, 27, 28, 35, 36, 39, 1<<64 - 1} {
		if _, err := FromChainV(bad, 1); err == nil {
			t.Fatalf("FromChainV(%d, 1) accepted", bad)
		}
	}
	if _, err := FromChainV(37, 0); err == nil {
		t.Fatal("chain 0 accepted")
	}
	if _, err := FromChainV(2709, 1); err == nil {
		t.Fatal("value for another chain accepted")
	}
}

// personalDigest is the "signed message" digest used by the ERC-2098 test
// vectors: Keccak-256("\x19Ethereum Signed Message:\n" + len + message).
func personalDigest(msg string) [32]byte {
	return keccak.Sum256([]byte("\x19Ethereum Signed Message:\n" + strconv.Itoa(len(msg)) + msg))
}

// Test vectors from ERC-2098 (https://eips.ethereum.org/EIPS/eip-2098,
// CC0). They are produced by deterministic RFC 6979 signing, so SILA's
// Sign must reproduce r, s and v exactly.
func TestCompactYParityVectors(t *testing.T) {
	priv := key(t, "1234567890123456789012345678901234567890123456789012345678901234")
	vectors := []struct {
		msg, r, s   string
		v           byte
		yParityAndS string
	}{
		{"Hello World",
			"68a020a209d3d56c46f38cc50a33f704f4a9a10a59377f8dd762ac66910e9b90",
			"7e865ad05c4035ab5792787d4a0297a43617ae897930a6fe4d822b8faea52064", 27,
			"7e865ad05c4035ab5792787d4a0297a43617ae897930a6fe4d822b8faea52064"},
		{"It's a small(er) world",
			"9328da16089fcba9bececa81663203989f2df5fe1faa6291a45381c81bd17f76",
			"139c6d6b623b42da56557e5e734a43dc83345ddfadec52cbe24d0cc64f550793", 28,
			"939c6d6b623b42da56557e5e734a43dc83345ddfadec52cbe24d0cc64f550793"},
	}
	pub, _ := priv.PublicKey()
	for _, vec := range vectors {
		d := personalDigest(vec.msg)
		sig, err := secp256k1.Sign(priv, d)
		if err != nil {
			t.Fatal(err)
		}
		r, s := sig.R(), sig.S()
		v, _ := sig.RecoveryID()
		lv, _ := LegacyV(v)
		if hex.EncodeToString(r[:]) != vec.r || hex.EncodeToString(s[:]) != vec.s || lv != vec.v {
			t.Fatalf("%q: signature differs from the ERC-2098 vector", vec.msg)
		}
		c, err := CompactYParity(sig)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(c[:32]) != vec.r || hex.EncodeToString(c[32:]) != vec.yParityAndS {
			t.Fatalf("%q: compact form differs", vec.msg)
		}
		back, err := ParseCompactYParity(c[:])
		if err != nil {
			t.Fatal(err)
		}
		bb, _ := back.Recoverable()
		sb, _ := sig.Recoverable()
		if bb != sb {
			t.Fatal("compact round trip")
		}
		if rec, err := secp256k1.RecoverPublicKey(d, back); err != nil || !rec.Equal(pub) {
			t.Fatal("compact form does not recover the signer")
		}
	}
}

// The ERC-2098 form and the generic r || s form are different formats.
// They coincide only when yParity is 0; with yParity 1 the generic strict
// parser rejects the ERC-2098 bytes (the top bit makes s high or >= n).
func TestCompactFormsAreDistinct(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	seen := [2]bool{}
	for i := 0; i < 200 && !(seen[0] && seen[1]); i++ {
		priv, _ := secp256k1.GeneratePrivateKey(rng)
		var d [32]byte
		rng.Read(d[:])
		sig, _ := secp256k1.Sign(priv, d)
		v, _ := sig.RecoveryID()
		if v > 1 {
			continue
		}
		seen[v] = true
		c, _ := CompactYParity(sig)
		generic, _ := sig.Compact()
		if v == 0 {
			if c != generic {
				t.Fatal("yParity 0 must leave r || s unchanged")
			}
			continue
		}
		if c == generic {
			t.Fatal("yParity 1 must set the top bit")
		}
		if _, err := secp256k1.ParseSignature(c[:]); err == nil {
			t.Fatal("generic strict parser accepted ERC-2098 bytes with yParity 1")
		}
	}
	if !seen[0] || !seen[1] {
		t.Fatal("test did not cover both parities")
	}
}

func TestCompactYParityRejects(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	priv, _ := secp256k1.GeneratePrivateKey(rng)
	d := [32]byte{9}
	sig, _ := secp256k1.Sign(priv, d)
	// No recovery identifier.
	cmp, _ := sig.Compact()
	noV, _ := secp256k1.ParseSignature(cmp[:])
	if _, err := CompactYParity(noV); err == nil {
		t.Fatal("signature without recovery identifier encoded")
	}
	// High-S.
	rb, _ := sig.Recoverable()
	s := new(big.Int).SetBytes(rb[32:64])
	hs := b32(new(big.Int).Sub(bigN, s))
	copy(rb[32:64], hs[:])
	rb[64] ^= 1
	high, err := secp256k1.ParseRecoverableSignatureAllowHighS(rb[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CompactYParity(high); err == nil {
		t.Fatal("high-S encoded")
	}
	// Zero value.
	if _, err := CompactYParity(secp256k1.Signature{}); err == nil {
		t.Fatal("zero signature encoded")
	}
	// Parsing: wrong length, r = 0, s = 0 after clearing the parity bit,
	// s high after clearing it.
	if _, err := ParseCompactYParity(make([]byte, 65)); err == nil {
		t.Fatal("wrong length")
	}
	bad := make([]byte, 64)
	bad[31], bad[32] = 1, 0x80
	if _, err := ParseCompactYParity(bad); err == nil {
		t.Fatal("s = 0 accepted")
	}
	hb := b32(new(big.Int).Add(halfN, big.NewInt(1)))
	copy(bad[32:], hb[:])
	if _, err := ParseCompactYParity(bad); err == nil {
		t.Fatal("high s accepted")
	}
}

func FuzzParseCompactYParity(f *testing.F) {
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, b []byte) {
		sig, err := ParseCompactYParity(b)
		if err != nil {
			return
		}
		c, err := CompactYParity(sig)
		if err != nil || string(c[:]) != string(b) {
			t.Fatal("accepted input does not round-trip")
		}
	})
}
