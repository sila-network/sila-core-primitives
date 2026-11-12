// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package account

import (
	"encoding/hex"
	"testing"

	"github.com/sila-network/sila-core-primitives/secp256k1"
)

// Private key 1 has the public key G; its address is the widely published
// 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf. The differential test against
// go-ethereum's crypto.PubkeyToAddress is in benchmarks/geth-compare.
func TestAddressOfKeyOne(t *testing.T) {
	k := make([]byte, 32)
	k[31] = 1
	priv, err := secp256k1.ParsePrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := priv.PublicKey()
	a, err := FromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(a[:]); got != "7e5f4552091a69125d5dfcb7b8c2659029395bdf" {
		t.Fatalf("address %s", got)
	}
}

func TestAddressRejectsInvalidKey(t *testing.T) {
	if _, err := FromPublicKey(secp256k1.PublicKey{}); err == nil {
		t.Fatal("zero public key accepted")
	}
}
