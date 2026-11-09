// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// secp256k1 generator G, from SEC 2 v2.0, §2.4.1.
const generatorCompressed = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
const generatorUncompressed = "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"

func mustHex(s string) []byte {
	v, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return v
}

func TestGeneratorCompressedAndUncompressed(t *testing.T) {
	compressed := mustHex(generatorCompressed)
	uncompressed := mustHex(generatorUncompressed)
	for _, input := range [][]byte{compressed, uncompressed} {
		pub, err := ParsePublicKey(input)
		if err != nil {
			t.Fatalf("valid generator rejected: %v", err)
		}
		c, err := pub.Compressed()
		if err != nil || !bytes.Equal(c[:], compressed) {
			t.Fatalf("compressed mismatch: %x, %v", c, err)
		}
		u, err := pub.Uncompressed()
		if err != nil || !bytes.Equal(u[:], uncompressed) {
			t.Fatalf("uncompressed mismatch: %x, %v", u, err)
		}
		x, y, err := pub.Coordinates()
		if err != nil || !bytes.Equal(x[:], compressed[1:]) || !bytes.Equal(y[:], uncompressed[33:]) {
			t.Fatal("unexpected public coordinates")
		}
	}
}

func TestOddGeneratorPublicPoint(t *testing.T) {
	odd := mustHex(generatorCompressed)
	odd[0] = 0x03
	pub, err := ParsePublicKey(odd)
	if err != nil {
		t.Fatal(err)
	}
	c, err := pub.Compressed()
	if err != nil || !bytes.Equal(c[:], odd) {
		t.Fatalf("odd parity point mismatch: %x %v", c, err)
	}
	u, err := pub.Uncompressed()
	if err != nil {
		t.Fatal(err)
	}
	p2, err := ParsePublicKey(u[:])
	if err != nil {
		t.Fatal(err)
	}
	c2, err := p2.Compressed()
	if err != nil || c != c2 {
		t.Fatal("odd point roundtrip mismatch")
	}
}

func TestRejectMalformedPublicKeys(t *testing.T) {
	generator := mustHex(generatorCompressed)
	primeBytes := mustHex(primeHex)
	cases := map[string][]byte{
		"empty": nil,
		"infinity": {0x00},
		"short": generator[:32],
		"long": append(bytes.Clone(generator), 0),
		"hybrid": append([]byte{0x06}, mustHex(generatorUncompressed)[1:]...),
		"wrong prefix": append([]byte{0x05}, generator[1:]...),
		"x equals p": append([]byte{0x02}, primeBytes...),
		"nonresidue at x zero": make([]byte, 33),
	}
	cases["nonresidue at x zero"][0] = 0x02
	badY := mustHex(generatorUncompressed)
	badY[64] ^= 0x01
	cases["off curve"] = badY
	yEqualsP := mustHex(generatorUncompressed)
	copy(yEqualsP[33:], primeBytes)
	cases["y equals p"] = yEqualsP
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePublicKey(data); !errors.Is(err, ErrInvalidPublicKey) {
				t.Fatalf("accepted invalid key %x, error %v", data, err)
			}
		})
	}
}

func TestZeroValueCannotBeSerialized(t *testing.T) {
	var pub PublicKey
	if _, err := pub.Compressed(); !errors.Is(err, ErrInvalidPublicKey) {
		t.Fatal("zero compressed key accepted")
	}
	if _, err := pub.Uncompressed(); !errors.Is(err, ErrInvalidPublicKey) {
		t.Fatal("zero uncompressed key accepted")
	}
	if _, _, err := pub.Coordinates(); !errors.Is(err, ErrInvalidPublicKey) {
		t.Fatal("zero coordinates accepted")
	}
}

func FuzzPublicKeyRoundTrip(f *testing.F) {
	f.Add(mustHex(generatorCompressed))
	f.Add(mustHex(generatorUncompressed))
	f.Add(mustHex("0379BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"))
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, data []byte) {
		pub, err := ParsePublicKey(data)
		if err != nil {
			return
		}
		compressed, err := pub.Compressed()
		if err != nil {
			t.Fatal(err)
		}
		copyPub, err := ParsePublicKey(compressed[:])
		if err != nil {
			t.Fatal(err)
		}
		uncompressed, err := copyPub.Uncompressed()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := ParsePublicKey(uncompressed[:])
		if err != nil {
			t.Fatal(err)
		}
		compressedAgain, err := decoded.Compressed()
		if err != nil || compressedAgain != compressed {
			t.Fatal("inconsistent public key codec")
		}
	})
}
