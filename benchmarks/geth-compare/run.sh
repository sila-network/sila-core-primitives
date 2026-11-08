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
TAGS=""; ARGS=""
case "$MODE" in
  asm) ;;
  noavx) ARGS="-args -sila.noavx512" ;;
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
  echo "# cpu: $(cpu_model)"
  echo "# os/arch: $(go env GOOS)/$(go env GOARCH)"
} > "$OUT"
go test $TAGS -count=1 -run TestDispatchReport -v . $ARGS | grep enabled >> "$OUT"

PIN=""
if command -v taskset >/dev/null 2>&1 && [ "$(nproc 2>/dev/null || echo 1)" -gt 2 ]; then
  PIN="taskset -c 2"
fi
$PIN go test $TAGS -run '^$' -bench . -cpu 1 -count 10 -benchtime 150ms . $ARGS | tee -a "$OUT"
