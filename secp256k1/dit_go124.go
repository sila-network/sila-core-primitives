// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

//go:build go1.24

package secp256k1

import "crypto/subtle"

// withDIT runs f with the processor's data-independent-timing mode
// enabled where the platform offers one (PSTATE.DIT on arm64 processors
// with FEAT_DIT, through crypto/subtle.WithDataIndependentTiming). Without
// it, Arm does not guarantee that multiplications and other instructions
// used by the constant-time code take the same time for every operand. On
// other platforms f runs unchanged.
func withDIT(f func()) { subtle.WithDataIndependentTiming(f) }
