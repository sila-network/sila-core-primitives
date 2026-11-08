// SPDX-License-Identifier: Apache-2.0

// sila-keccak256 computes the Keccak-256 digest of standard input.
package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/sila-network/sila-core-primitives/keccak"
)

func main() {
	h := keccak.New()
	if _, err := io.Copy(h, os.Stdin); err != nil {
		fmt.Fprintln(os.Stderr, "failed reading input:", err)
		os.Exit(1)
	}
	fmt.Println(hex.EncodeToString(h.Sum(nil)))
}
