# SILA secp256k1 — performance record

Comparison with two independent implementations, used as references only:
libsecp256k1 (C, through go-ethereum v1.17.10's cgo binding) and decred
dcrd secp256k1/v4 v4.0.1 (pure Go). The benchmarks are in
`benchmarks/geth-compare/secp256k1_bench_test.go` and use the same key and
digest for all three implementations.

## Reference VM (2026-11-09)

Intel Xeon @ 2.10 GHz, Linux amd64, Go 1.25.4, one pinned core; the test
binary is run 8 times (alternating all implementations); `benchstat`
medians. Raw data: `benchmarks/geth-compare/results/local-2026-11-09-secp256k1/`.

| Operation | SILA | libsecp256k1 | decred | SILA vs decred |
|---|---:|---:|---:|---|
| Sign (RFC 6979, low-S, with recovery id) | 60.6 µs | 27.7 µs | 40.6 µs | slower by 33% (decred takes 0.67× SILA's time) |
| Verify | 130.4 µs | 38.6 µs | 144.6 µs | faster by 11% |
| Recover public key | 148.9 µs | 47.3 µs | 171.7 µs | faster by 15% |
| Public key from private key | 43.4 µs | — | 36.2 µs | slower by 17% |

| Allocations per operation | SILA | libsecp256k1 | decred |
|---|---|---|---|
| Sign | **0 (0 B)** | 5 (260 B) | 29 (1592 B) |
| Verify | **0** | 0 | 23 (1288 B) |
| Recover | **0** | 1 (80 B) | 24 (1368 B) |

## Interpretation

- libsecp256k1 is 2.2–3.4× faster: it is hand-optimized C (5×52-bit field
  limbs, GLV endomorphism, specialized inversions). SILA makes no
  performance-superiority claim against it.
- Against the other pure-Go implementation, SILA is faster for verification
  and recovery, and slower for signing and key derivation. Those pay for
  SILA's fully constant-time design: complete formulas, full-table scans,
  and Fermat inversion instead of variable-time algorithms.
- SILA performs no heap allocations, which avoids garbage-collector
  pressure and leaves no secret material in garbage memory.

## Optimization history (same VM)

| Step | Sign | Verify | Recover |
|---|---:|---:|---:|
| First constant-time version (generic Montgomery) | 92 µs | 255 µs | 260 µs |
| Dedicated reduction for p, windowed exponentiation | 75 µs | 230 µs | 234 µs |
| Unrolled Comba multiplication and dedicated squaring | 61 µs | 168 µs | 170 µs |
| wNAF and projective x-check in Verify/Recover, stack HMAC | **59 µs** | **~130 µs** | **~149 µs** |

## Possible further work (not done; each needs the same differential testing)

- GLV endomorphism (λ·(x, y) = (β·x, y)) to halve the doublings in
  Verify and Recover.
- Mixed affine addition for precomputed table entries; a larger comb for k·G.
- A constant-time modular inversion (Bernstein–Yang "safegcd") instead of
  Fermat exponentiation.

## GitHub runners

The `Benchmarks` workflow (`.github/workflows/bench.yml`) runs the same
comparison on Linux amd64, Linux arm64 and macOS arm64 runners and
publishes the `benchstat` table in the run summary and artifacts.
