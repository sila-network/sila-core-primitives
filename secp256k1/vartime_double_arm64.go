// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

//go:build arm64 && !purego

package secp256k1

// jacDoubleArm64 is the halved doubling of jacDoubleGo with all field
// operations inlined (vartime_arm64.s); PUBLIC inputs only, like the rest
// of the vartime*.go code. tmp holds the intermediates.
//
//go:noescape
func jacDoubleArm64(r, p *jacobian, tmp *[5]limbs)

// jacDouble sets r = 2p (Jacobian; public inputs only).
func jacDouble(r, p *jacobian) {
	if p.inf {
		r.inf = true
		return
	}
	var tmp [5]limbs
	jacDoubleArm64(r, p, &tmp)
	r.inf = false
}
