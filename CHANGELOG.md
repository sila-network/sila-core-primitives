# Changelog

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
- License: Apache-2.0 adopted (LICENSE, SPDX headers). The NOTICE copyright
  line holds a placeholder until the legal entity name is confirmed.
- Added NOTICE, TRADEMARKS.md, CONTRIBUTING.md and SECURITY.md.
