# Changelog

## V1.1 — review round 2 (2026-11-08)

- Ownership: `NOTICE` now reads "Copyright 2026 Ahmed Ibrahim", replacing
  the placeholder. `TRADEMARKS.md` names Ahmed Ibrahim as the owner who
  declared ownership of the SILA name and logo, without claiming a
  registration. "SILA Network" is the hosting organization, not the
  rights holder.
- Output unchanged.
- **Fix (availability):** the AVX-512 path is now preemptible. Hashing a
  very large input previously blocked a concurrent GC stop-the-world for
  the whole hash (~1 s for 512 MiB); now ~1 ms. Inputs go to the assembly
  kernel in chunks of at most 64 blocks, through a non-inlined Go wrapper.
- CPU dispatch: pure, table-tested decision rule; `GODEBUG=cpu.avx512=off`
  (and cpu.all / cpu.avx512f / cpu.avx512vl) is honoured, with a separate
  state per required feature (a later `cpu.avx512vl=on` no longer cancels
  `cpu.avx512f=off`; review finding).
- The preemption regression test now measures scheduling latency with a
  single P instead of the wall-clock time of runtime.GC(), which was flaky
  under GOMAXPROCS=1 and did not detect the original defect there (review
  finding).
- An emulator test executes the generated assembly text on any platform and
  checks semantics, memory bounds, register use and register clearing.
- Official Keccak team KATs (short, long, Monte Carlo, 1 GiB), Ethereum
  topics/selectors, unaligned and concurrent tests.
- Benchmarks: SILA and geth samples are interleaved in time; a GitHub
  workflow measures Linux amd64, Linux arm64 and macOS arm64 runners.
- Both portable kernel shapes are kept and benchmarked per CPU.

## V1.1 — 2026-11-08

- Output unchanged: byte-identical Keccak-256 (Ethereum variant).
- New generated kernels (`internal/gen`): AVX-512VL lane-per-register for
  amd64, and a portable unrolled Go kernel with lane complementing. The
  original V1 loop is kept as a test oracle.
- Fused multi-block absorb in assembly that reads exactly the input bytes.
- Vector registers are zeroed on return from assembly.
- Throughput at 1 MiB on the reference machine: 43.8 → 632.7 MB/s.
- Module path `sila/core-primitives` → `github.com/sila-network/sila-core-primitives`.
- `scripts/verify_openssl.py` → `scripts/verify_independent.py`: automatic
  oracle discovery (PyCryptodome / OpenSSL ≥ 3.2), a KAT self-check of each
  oracle, a 907-case set, and a clear exit 2 when no oracle is present.
- New separate benchmark module `benchmarks/geth-compare` (go-ethereum v1.17.10).
- Extended tests: KAT and boundary vectors, every length and split point,
  random chunking, fuzzing, guard-page over-read test, zero-allocation test,
  fallback test, and a stale-generated-file check.
- License: Apache-2.0 adopted (LICENSE, SPDX headers).
- Added NOTICE, TRADEMARKS.md, CONTRIBUTING.md and SECURITY.md.
