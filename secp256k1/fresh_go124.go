// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

//go:build go1.24

package secp256k1

import (
	cryptorand "crypto/rand"
	"io"
)

// readFresh fills b from the package random source, or with zeros if the
// source fails. With the default source it calls crypto/rand.Read
// directly: since Go 1.24 that keeps b on the stack (no allocation per
// signature). Tests replace the source to exercise failures; that path
// reads through a separate buffer so b never reaches an interface call.
func readFresh(b *[32]byte) {
	var err error
	if randomSource == cryptorand.Reader {
		_, err = cryptorand.Read(b[:])
	} else {
		buf := make([]byte, len(b))
		_, err = io.ReadFull(randomSource, buf)
		copy(b[:], buf)
		clear(buf)
	}
	if err != nil {
		clear(b[:])
	}
}
