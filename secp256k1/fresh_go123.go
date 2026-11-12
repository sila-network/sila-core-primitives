// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

//go:build !go1.24

package secp256k1

import "io"

// readFresh fills b from the package random source, or with zeros if the
// source fails. Before Go 1.24, crypto/rand.Read passes its argument
// through an io.Reader interface, so the bytes are read into a separate
// heap buffer (one allocation per signature on Go 1.23 builds) and b
// itself stays on the stack.
func readFresh(b *[32]byte) {
	buf := make([]byte, len(b))
	_, err := io.ReadFull(randomSource, buf)
	copy(b[:], buf)
	clear(buf)
	if err != nil {
		clear(b[:])
	}
}
