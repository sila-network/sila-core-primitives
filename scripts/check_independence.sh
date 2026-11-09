#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmed Ibrahim
#
# Independence check for the SILA module (production code only):
#   1. go.mod has no requirements;
#   2. the transitive dependency graph of every production package holds
#      only the Go standard library and SILA packages;
#   3. the module builds and its tests pass offline (no module proxy, no
#      network access to any service) and without cgo;
#   4. a probe binary that links the signature packages records no
#      dependency other than the SILA module in its build metadata, and
#      embeds no foreign project or network name;
#   5. production sources of the signature packages name no foreign
#      project or network.
# External implementations live only in benchmarks/geth-compare, a
# separate module that is never part of a SILA build.
set -euo pipefail
cd "$(dirname "$0")/.."
MOD=github.com/sila-network/sila-core-primitives
fail() { echo "FAIL: $*" >&2; exit 1; }

echo "== 1. go.mod requirements"
if grep -Eq '^\s*require\b' go.mod; then fail "go.mod has requirements"; fi
echo "none"

echo "== 2. transitive production dependency graph"
pkgs=$(go list ./... | grep -v '/internal/gen$')
foreign=$(go list -deps $pkgs | awk -v m="$MOD" 'index($0, m) != 1 && $0 ~ /^[^\/]*\./')
if [ -n "$foreign" ]; then fail "non-standard dependencies: $foreign"; fi
echo "$(go list -deps $pkgs | grep -c "^$MOD") SILA packages, $(go list -deps $pkgs | grep -vc "^$MOD") standard-library packages, 0 others"

echo "== 3. offline build and tests, cgo disabled"
export GOPROXY=off GOFLAGS=-mod=readonly GONOSUMDB= GOSUMDB=off CGO_ENABLED=0
go build ./...
go test -count=1 -short ./secp256k1 ./txsig ./account ./keccak

echo "== 4. probe binary metadata and strings"
probe=$(mktemp -d ./.independence-probe.XXXXXX)
trap 'rm -rf "$probe"' EXIT
cat > "$probe/main.go" <<'GO'
package main

import (
	"fmt"

	"github.com/sila-network/sila-core-primitives/account"
	"github.com/sila-network/sila-core-primitives/keccak"
	"github.com/sila-network/sila-core-primitives/secp256k1"
	"github.com/sila-network/sila-core-primitives/txsig"
)

func main() {
	k := make([]byte, 32)
	k[31] = 1
	priv, _ := secp256k1.ParsePrivateKey(k)
	pub, _ := priv.PublicKey()
	d := keccak.Sum256([]byte("probe"))
	sig, _ := secp256k1.Sign(priv, d)
	rec, _ := secp256k1.RecoverPublicKey(d, sig)
	c, _ := txsig.CompactYParity(sig)
	a, _ := account.FromPublicKey(pub)
	fmt.Println(secp256k1.Verify(pub, d, sig), rec.Equal(pub), len(c), len(a))
}
GO
go build -trimpath -o "$probe/probe" "./$probe"
out=$("$probe/probe")
[ "$out" = "true true 64 20" ] || fail "probe output: $out"
meta=$(go version -m "$probe/probe")
if echo "$meta" | grep -E '^\s+dep\s' ; then fail "binary records foreign dependencies"; fi
echo "$meta" | grep -E '^\s+(path|mod)\s'
names='ethereum|go-ethereum|geth|libsecp256k1|decred|bitcoin'
if strings "$probe/probe" | grep -Eiwo "$names" | sort -u | grep . ; then
  fail "binary embeds foreign names"
fi
echo "no foreign dependency or name in the binary"

echo "== 5. production sources of the signature packages"
if grep -EIin "$names|\beip-?[0-9]|\berc-?[0-9]|ecrecover" $(ls secp256k1/*.go txsig/*.go account/*.go | grep -v '_test\.go$'); then
  fail "foreign names in production sources"
fi
echo "clean"
echo "PASS"
