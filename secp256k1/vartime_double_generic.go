// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

//go:build !arm64 || purego

package secp256k1

// jacDouble sets r = 2p (Jacobian; public inputs only).
func jacDouble(r, p *jacobian) { jacDoubleGo(r, p) }
