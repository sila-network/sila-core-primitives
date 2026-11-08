#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Reproducible head-to-head runs. Same toolchain, flags, core and inputs.
#   ./run.sh asm      SILA (AVX-512 when available) vs geth (amd64 asm)
#   ./run.sh noavx    SILA portable Go kernel       vs geth (amd64 asm)
#   ./run.sh purego   SILA portable Go kernel       vs geth portable Go
# Compare with: benchstat -col /impl -row .name,/size results/<mode>.txt
set -e
MODE=${1:-asm}
export GOTOOLCHAIN=go1.25.4 GOAMD64=v1 GOGC=off
TAGS=""; ARGS=""
case "$MODE" in
  asm) ;;
  noavx) ARGS="-args -sila.noavx512" ;;
  purego) TAGS="-tags purego" ;;
  *) echo "unknown mode $MODE"; exit 2 ;;
esac
OUT=results/$MODE.txt
mkdir -p results
go test $TAGS -count=1 -run 'TestSameOutput|TestRandomAgainstGeth' . $ARGS
{ echo "# mode: $MODE"; go version; grep -m1 'model name' /proc/cpuinfo; } > "$OUT"
go test $TAGS -count=1 -run TestDispatchReport -v . $ARGS | grep enabled >> "$OUT"
taskset -c 2 go test $TAGS -run '^$' -bench . -cpu 1 -count 10 -benchtime 150ms . $ARGS | tee -a "$OUT"
