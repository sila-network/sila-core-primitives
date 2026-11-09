#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Reproducible head-to-head runs. Same toolchain, flags, core and inputs.
#   ./run.sh asm      SILA default kernel (AVX-512 when available) vs geth default
#   ./run.sh noavx    SILA portable Go kernel vs geth default (amd64 only)
#   ./run.sh purego   SILA portable Go kernel vs geth portable Go
# Output: $RESULTS/<mode>.txt (default RESULTS=results).
# Compare with: benchstat -col /impl -row .name,/size $RESULTS/<mode>.txt
set -e
MODE=${1:-asm}
RESULTS=${RESULTS:-results}
export GOTOOLCHAIN=${GOTOOLCHAIN_BENCH:-go1.25.4} GOAMD64=v1 GOGC=off
TAGS=""; ARGS=""; BINARGS=""
case "$MODE" in
  asm) ;;
  noavx) ARGS="-args -sila.noavx512"; BINARGS="-sila.noavx512" ;;
  purego) TAGS="-tags purego" ;;
  *) echo "unknown mode $MODE"; exit 2 ;;
esac
OUT=$RESULTS/$MODE.txt
mkdir -p "$RESULTS"

cpu_model() {
  if [ -r /proc/cpuinfo ] && grep -q 'model name' /proc/cpuinfo; then
    grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//'
  elif command -v sysctl >/dev/null 2>&1 && sysctl -n machdep.cpu.brand_string >/dev/null 2>&1; then
    sysctl -n machdep.cpu.brand_string
  elif command -v lscpu >/dev/null 2>&1; then
    lscpu | awk -F: '/Model name/ {sub(/^ +/, "", $2); print $2; exit}'
  else
    uname -m
  fi
}

# Equivalence first: numbers are only recorded if both produce identical digests.
go test $TAGS -count=1 -run 'TestSameOutput|TestRandomAgainstGeth' . $ARGS
{
  echo "# mode: $MODE"
  go version
  model=$(cpu_model 2>/dev/null || true)
  echo "# cpu: ${model:-unknown ($(uname -m))}"
  echo "# os/arch: $(go env GOOS)/$(go env GOARCH)"
} > "$OUT"
go test $TAGS -count=1 -run TestDispatchReport -v . $ARGS | grep enabled >> "$OUT"

PIN=""
if command -v taskset >/dev/null 2>&1 && [ "$(nproc 2>/dev/null || echo 1)" -gt 2 ]; then
  PIN="taskset -c 2"
fi
# The test binary is built once and run 10 times. Each run measures every
# size for both implementations, so SILA and geth samples are interleaved
# in time and slow drift of a shared host affects both sides equally
# (go test -count 10 would instead take all samples of one side in a row).
BIN=$(mktemp "${TMPDIR:-/tmp}/geth-compare.XXXXXX")
trap 'rm -f "$BIN"' EXIT
go test $TAGS -c -o "$BIN" .
for i in 1 2 3 4 5 6 7 8 9 10; do
  $PIN "$BIN" -test.run '^$' -test.bench . -test.cpu 1 -test.count 1 -test.benchtime 150ms $BINARGS
done | tee -a "$OUT"
