// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

// Project Wycheproof vectors (Apache-2.0, see testdata/wycheproof/README.md).

type wpFile struct {
	NumberOfTests int `json:"numberOfTests"`
	TestGroups    []struct {
		PublicKey struct {
			Uncompressed string `json:"uncompressed"`
		} `json:"publicKey"`
		Sha   string `json:"sha"`
		Tests []struct {
			TcID    int      `json:"tcId"`
			Comment string   `json:"comment"`
			Msg     string   `json:"msg"`
			Sig     string   `json:"sig"`
			Result  string   `json:"result"`
			Flags   []string `json:"flags"`
		} `json:"tests"`
	} `json:"testGroups"`
}

func loadWycheproof(t *testing.T, name string) *wpFile {
	t.Helper()
	b, err := os.ReadFile("testdata/wycheproof/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var f wpFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return &f
}

// parseStrictDER decodes SEQUENCE { INTEGER r, INTEGER s } in strict DER
// (test helper; SILA itself uses fixed-size encodings). It returns r and s
// as 32-byte values, or false for any non-DER or out-of-range input.
func parseStrictDER(b []byte) (r, s [32]byte, ok bool) {
	if len(b) < 2 || b[0] != 0x30 || int(b[1]) != len(b)-2 || b[1] >= 0x80 {
		return r, s, false
	}
	rest := b[2:]
	readInt := func(out *[32]byte) bool {
		if len(rest) < 2 || rest[0] != 0x02 || rest[1] >= 0x80 || int(rest[1]) > len(rest)-2 {
			return false
		}
		n := int(rest[1])
		v := rest[2 : 2+n]
		rest = rest[2+n:]
		if n == 0 || v[0]&0x80 != 0 { // empty or negative
			return false
		}
		if n > 1 && v[0] == 0 && v[1]&0x80 == 0 { // non-minimal
			return false
		}
		if v[0] == 0 {
			v = v[1:]
		}
		if len(v) > 32 {
			return false
		}
		copy(out[32-len(v):], v)
		return true
	}
	if !readInt(&r) || !readInt(&s) || len(rest) != 0 {
		return r, s, false
	}
	return r, s, true
}

func runWycheproof(t *testing.T, name string, der bool, allowHighS bool) {
	f := loadWycheproof(t, name)
	count, highSRejected := 0, 0
	for _, g := range f.TestGroups {
		if g.Sha != "SHA-256" {
			t.Fatalf("unexpected hash %s", g.Sha)
		}
		pub, err := ParsePublicKey(mustHex(g.PublicKey.Uncompressed))
		if err != nil {
			t.Fatalf("group public key rejected: %v", err)
		}
		for _, tc := range g.Tests {
			count++
			msg, _ := hex.DecodeString(tc.Msg)
			raw, _ := hex.DecodeString(tc.Sig)
			digest := sha256.Sum256(msg)

			var compact []byte
			if der {
				r, s, ok := parseStrictDER(raw)
				if ok {
					compact = append(r[:], s[:]...)
				}
			} else if len(raw) == 64 {
				compact = raw
			}
			got := false
			if compact != nil {
				if sig, err := ParseSignature(compact); err == nil {
					got = Verify(pub, digest, sig)
				}
			}

			want := tc.Result == "valid"
			if tc.Result == "acceptable" {
				t.Logf("tc %d (%s): acceptable, SILA=%v", tc.TcID, tc.Comment, got)
				continue
			}
			if allowHighS && want && compact != nil {
				// The vector set permits high-S; the SILA contract does not.
				if new(big.Int).SetBytes(compact[32:]).Cmp(new(big.Int).Rsh(bigN, 1)) > 0 {
					if got {
						t.Fatalf("tc %d: high-S accepted", tc.TcID)
					}
					highSRejected++
					continue
				}
			}
			if got != want {
				t.Errorf("tc %d (%s, %v): SILA=%v, expected %s", tc.TcID, tc.Comment, tc.Flags, got, tc.Result)
			}
		}
	}
	if count != f.NumberOfTests {
		t.Fatalf("ran %d of %d vectors", count, f.NumberOfTests)
	}
	t.Logf("%s: %d vectors, %d valid-but-high-S rejected by the SILA contract", name, count, highSRejected)
}

func TestWycheproofBitcoin(t *testing.T) {
	runWycheproof(t, "ecdsa_secp256k1_sha256_bitcoin_test.json", true, false)
}

func TestWycheproofP1363(t *testing.T) {
	runWycheproof(t, "ecdsa_secp256k1_sha256_p1363_test.json", false, true)
}
