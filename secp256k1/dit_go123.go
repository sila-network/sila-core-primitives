// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

//go:build !go1.24

package secp256k1

// withDIT runs f directly: Go releases before 1.24 cannot enable the
// processor's data-independent-timing mode (see dit_go124.go).
func withDIT(f func()) { f() }
