// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

//go:build race

package secp256k1

// raceEnabled reports a -race build. The race detector's instrumentation
// moves the argument of crypto/rand.Read to the heap, so allocation
// counts are only meaningful without it.
const raceEnabled = true
