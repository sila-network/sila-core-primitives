// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

import (
	"bytes"
	"go/parser"
	"go/token"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The production code of this package must not import variable-time
// arbitrary-precision arithmetic (math/big), nor any package outside this
// allow-list. math/big may appear only in _test.go files as an oracle.
func TestNoVariableTimeImports(t *testing.T) {
	allowed := map[string]bool{
		"crypto/hmac": true, "crypto/rand": true, "crypto/sha256": true,
		"errors": true, "hash": true, "io": true, "math/bits": true,
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range af.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if !allowed[path] {
				t.Errorf("%s imports %q, which is not on the allow-list", f, path)
			}
		}
		checked++
	}
	if checked < 6 {
		t.Fatalf("only %d source files checked", checked)
	}
	src, _ := os.ReadFile("scalar.go")
	if bytes.Contains(src, []byte("math/big")) {
		t.Fatal("scalar.go mentions math/big")
	}
}

func FuzzParseAndVerifySignature(f *testing.F) {
	rng := rand.New(rand.NewSource(10))
	priv, _ := GeneratePrivateKey(rng)
	pub, _ := priv.PublicKey()
	pubC, _ := pub.Compressed()
	digest := [32]byte{1, 2, 3}
	sig, _ := Sign(priv, digest)
	rc, _ := sig.Recoverable()
	f.Add(rc[:], digest[:], pubC[:])
	f.Add(make([]byte, 65), make([]byte, 32), pubC[:])
	f.Add(bytes.Repeat([]byte{0xFF}, 65), bytes.Repeat([]byte{0xFF}, 32), pubC[:])
	f.Fuzz(func(t *testing.T, sigBytes, digestBytes, pubBytes []byte) {
		if len(digestBytes) != 32 {
			return
		}
		d := [32]byte(digestBytes)
		var s Signature
		var err error
		switch len(sigBytes) {
		case 64:
			s, err = ParseSignature(sigBytes)
		case 65:
			s, err = ParseRecoverableSignature(sigBytes)
		default:
			if _, e1 := ParseSignature(sigBytes); e1 == nil {
				t.Fatal("wrong length accepted")
			}
			return
		}
		if err != nil {
			return
		}
		// A parsed signature re-encodes to exactly its input.
		var enc []byte
		if len(sigBytes) == 64 {
			c, _ := s.Compact()
			enc = c[:]
		} else {
			c, _ := s.Recoverable()
			enc = c[:]
		}
		if !bytes.Equal(enc, sigBytes) {
			t.Fatal("non-canonical round trip")
		}
		if p, err := ParsePublicKey(pubBytes); err == nil {
			_ = Verify(p, d, s) // must not panic
		}
		if k, err := RecoverPublicKey(d, s); err == nil {
			// A recovered key always verifies the signature it came from.
			if !Verify(k, d, s) {
				t.Fatal("recovered key does not verify")
			}
		}
	})
}

func FuzzSignVerifyRecover(f *testing.F) {
	f.Add(bytes.Repeat([]byte{1}, 32), make([]byte, 32))
	f.Add(bytes.Repeat([]byte{0xFF}, 32), bytes.Repeat([]byte{0xFF}, 32))
	f.Fuzz(func(t *testing.T, keyBytes, digestBytes []byte) {
		if len(digestBytes) != 32 {
			return
		}
		priv, err := ParsePrivateKey(keyBytes)
		if err != nil {
			return
		}
		pub, err := priv.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		d := [32]byte(digestBytes)
		sig, err := Sign(priv, d)
		if err != nil {
			t.Fatal(err)
		}
		if !Verify(pub, d, sig) {
			t.Fatal("own signature rejected")
		}
		rec, err := RecoverPublicKey(d, sig)
		if err != nil || !rec.Equal(pub) {
			t.Fatal("recovery mismatch")
		}
		d[31] ^= 1
		if Verify(pub, d, sig) {
			t.Fatal("signature valid for a different digest")
		}
	})
}
