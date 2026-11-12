// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package secp256k1

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The production code of the SILA signature stack (this package, txsig and
// account) is independent: it imports only the Go standard library and
// SILA packages, and it does not name external projects or networks.
// External implementations appear only in _test.go files and in the
// separate comparison module benchmarks/geth-compare.
func TestIndependentProductionCode(t *testing.T) {
	const self = "github.com/sila-network/sila-core-primitives/"
	stdOrSILA := func(path string) bool {
		if strings.HasPrefix(path, self) {
			return true
		}
		first := strings.SplitN(path, "/", 2)[0]
		return !strings.Contains(first, ".") // standard-library paths have no dot
	}
	names := regexp.MustCompile(`(?i)ethereum|\bgeth\b|go-ethereum|\beip-?\d|\berc-?\d|libsecp256k1|decred|bitcoin|ecrecover`)
	checked := 0
	for _, dir := range []string{".", "../txsig", "../account"} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			if m := names.Find(src); m != nil {
				t.Errorf("%s names an external project: %q", f, m)
			}
			af, err := parser.ParseFile(token.NewFileSet(), f, src, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range af.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				if !stdOrSILA(p) {
					t.Errorf("%s imports %q", f, p)
				}
			}
			checked++
		}
	}
	if checked < 10 {
		t.Fatalf("only %d files checked", checked)
	}
	// The SILA module itself has no third-party requirements.
	mod, err := os.ReadFile("../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(mod), "require") {
		t.Fatal("go.mod of the SILA module has requirements")
	}
}
