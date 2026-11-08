// SPDX-License-Identifier: Apache-2.0

package gethcompare

import (
	"flag"
	"os"
	"testing"
	_ "unsafe" // go:linkname

	_ "github.com/sila-network/sila-core-primitives/keccak"
)

// Test-harness-only switch: force SILA onto its portable Go kernel while
// go-ethereum keeps its amd64 assembly (models a CPU without AVX-512).
//
//go:linkname silaUseAVX512 github.com/sila-network/sila-core-primitives/keccak.useAVX512
var silaUseAVX512 bool

var noAVX512 = flag.Bool("sila.noavx512", false, "force SILA portable kernel")

func TestMain(m *testing.M) {
	flag.Parse()
	if *noAVX512 {
		silaUseAVX512 = false
	}
	os.Exit(m.Run())
}

func TestDispatchReport(t *testing.T) { t.Logf("SILA AVX-512 path enabled: %v", silaUseAVX512) }
