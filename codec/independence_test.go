// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Ahmed Ibrahim

package codec

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

// The production code of the SILA codec imports only the Go standard
// library, carries the SILA copyright and does not name external projects
// or networks. External implementations appear only in the separate
// comparison module benchmarks/geth-compare.
func TestIndependentProductionCode(t *testing.T) {
	names := regexp.MustCompile(`(?i)ethereum|\bgeth\b|\brlp\b|yellow ?paper|\beip-?\d|\berc-?\d|bitcoin|\bssz\b`)
	files, _ := filepath.Glob("*.go")
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(string(src), "// SPDX-License-Identifier: Apache-2.0\n// Copyright 2026 Ahmed Ibrahim\n") {
			t.Errorf("%s: missing SILA license header", f)
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
			if first := strings.SplitN(p, "/", 2)[0]; strings.Contains(first, ".") {
				t.Errorf("%s imports %q (not standard library)", f, p)
			}
		}
		checked++
	}
	if checked < 3 {
		t.Fatalf("only %d files checked", checked)
	}
	mod, err := os.ReadFile("../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(mod), "require") {
		t.Fatal("go.mod of the SILA module has requirements")
	}
}
