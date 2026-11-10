#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmed Ibrahim
#
# Timing measurement for finding S-8 on DEDICATED hardware (not a shared
# CI runner). Run it on each target machine (at least one amd64 and one
# arm64), as root for the frequency settings, with nothing else running.
#
#   sudo ./scripts/timing_dedicated.sh [samples] [runs] [cpu]
#
# Defaults: 1,000,000 samples per class, 10 runs, CPU 2. It measures only
# the production paths (blinded inversion, blinded k·G, Sign, PublicKey)
# with tiny-vs-random secrets and random-vs-random controls, and prints the
# machine facts needed to interpret the result.
#
# Closure criterion for S-8 (docs/SECP256K1-SECURITY-REVIEW.md §6.1), per
# machine: for every production path, no run set has |t| > 4.5 with the
# same sign in all runs, and the controls stay below |t| = 4.5 in at least
# 9 of 10 runs (otherwise the machine is too noisy and the result does not
# count).
set -euo pipefail
cd "$(dirname "$0")/.."
SAMPLES=${1:-1000000}
RUNS=${2:-10}
CPU=${3:-2}

echo "== machine"
uname -a
go version
case "$(uname -s)" in
Linux)
  grep -m1 'model name' /proc/cpuinfo || grep -m1 -i 'cpu part' /proc/cpuinfo || true
  if grep -qw dit /proc/cpuinfo; then echo "FEAT_DIT: yes (enabled by Sign and PublicKey with Go >= 1.24)"; else echo "FEAT_DIT: no"; fi
  for f in /sys/devices/system/cpu/cpu"$CPU"/cpufreq/scaling_governor; do
    [ -r "$f" ] && echo "governor(cpu$CPU): $(cat "$f")"
  done
  [ -r /sys/devices/system/cpu/intel_pstate/no_turbo ] && echo "intel no_turbo: $(cat /sys/devices/system/cpu/intel_pstate/no_turbo)"
  [ -r /sys/devices/system/cpu/cpufreq/boost ] && echo "cpufreq boost: $(cat /sys/devices/system/cpu/cpufreq/boost)"
  echo "isolated CPUs: $(cat /sys/devices/system/cpu/isolated 2>/dev/null || echo unknown)"
  if [ "$(id -u)" = 0 ]; then
    # Fixed frequency: performance governor, no turbo/boost.
    gov=/sys/devices/system/cpu/cpu"$CPU"/cpufreq/scaling_governor
    if [ -w "$gov" ]; then echo performance > "$gov"; fi
    if [ -w /sys/devices/system/cpu/intel_pstate/no_turbo ]; then echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo; fi
    if [ -w /sys/devices/system/cpu/cpufreq/boost ]; then echo 0 > /sys/devices/system/cpu/cpufreq/boost; fi
  else
    echo "not root: frequency scaling left as is (the result may not count)"
  fi
  PIN=(taskset -c "$CPU")
  ;;
Darwin)
  sysctl -n machdep.cpu.brand_string 2>/dev/null || true
  echo "FEAT_DIT: $(sysctl -n hw.optional.arm.FEAT_DIT 2>/dev/null || echo unknown)"
  PIN=()
  ;;
*)
  PIN=()
  ;;
esac

echo "== measurement: $SAMPLES samples x $RUNS runs, production paths only"
SILA_TIMING_TEST=1 SILA_TIMING_PRODUCTION_ONLY=1 \
SILA_TIMING_SAMPLES="$SAMPLES" SILA_TIMING_REPS="$RUNS" \
  "${PIN[@]}" go test -count=1 -timeout 24h -run ConstantTimeStatistical -v ./secp256k1 |
  grep -E 'timing_test|^(---|ok|FAIL)'
