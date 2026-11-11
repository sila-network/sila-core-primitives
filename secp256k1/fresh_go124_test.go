// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

//go:build go1.24

package secp256k1

// allocFreeFresh reports whether readFresh avoids allocation (Go >= 1.24).
const allocFreeFresh = true
