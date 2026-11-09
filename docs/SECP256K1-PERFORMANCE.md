# SILA secp256k1 — performance record

Comparison with two independent implementations, used as references only
(separate module `benchmarks/geth-compare`): libsecp256k1 (C, through
go-ethereum v1.17.10's cgo binding) and decred dcrd secp256k1/v4 v4.0.1
(pure Go). The benchmark `BenchmarkSecp256k1` uses the same key and digest
for every implementation and calls each one through its public API.

## Reference VM (2026-11-09, after the optimization round)

Intel Xeon @ 2.10 GHz, Linux amd64, Go 1.25.0; the test binary is pinned
to one core (`taskset`) and run 8 times; `benchstat` medians with the 95 %
confidence interval. Raw data:
`benchmarks/geth-compare/results/local-2026-11-09-secp256k1-r2/`.

| Operation | SILA | libsecp256k1 (C) | decred (Go) | SILA vs libsecp256k1 | SILA vs decred |
|---|---:|---:|---:|---|---|
| Sign (RFC 6979, low-S, recovery id) | **33.55 µs ±2 %** | 29.44 µs ±4 % | 41.55 µs ±3 % | slower: C takes 0.88× SILA's time | **faster: 1.24×** |
| Verify | **59.32 µs ±11 %** | 39.59 µs ±10 % | 144.92 µs ±9 % | slower: C takes 0.67× | **faster: 2.44×** |
| Recover public key | **69.07 µs ±4 %** | 46.40 µs ±7 % | 176.19 µs ±3 % | slower: C takes 0.67× | **faster: 2.55×** |
| Public key from private key | **22.94 µs ±7 %** | — (no direct API) | 36.46 µs ±2 % | — | **faster: 1.59×** |

| Allocations per operation | SILA | libsecp256k1 | decred |
|---|---|---|---|
| Sign | **0 (0 B)** | 5 (260 B) | 29 (1592 B) |
| Verify | **0** | 0 | 23 (1288 B) |
| Recover | **0** | 1 (80 B) | 24 (1368 B) |
| Public key | **0** | — | 1 (80 B) |

All differences are significant (p = 0.000, n = 8).

### Targets

| Target | Status |
|---|---|
| Faster than the pure-Go reference (decred) in every operation | **met** (1.24× – 2.55×) |
| Zero heap allocations in every operation | **met** (better than both references) |
| Faster than libsecp256k1 (C) | **not met**: Sign is 12 % slower, Verify and Recover 33 % slower |

Why libsecp256k1 is still faster (as built by go-ethereum's cgo binding,
checked in its sources: no assembly is enabled): it is C compiled with
5×52-bit limbs, 128-bit integer products and lazy reduction (fewer carry
chains than Go's `math/bits` code); verification uses window-15 tables for
G and the "effective affine" technique for the variable point; k·G uses a
signed-digit comb; inversions use the "safegcd" (Bernstein–Yang)
algorithm, where SILA uses fixed addition chains. Closing the gap in Go
would need assembly field arithmetic per architecture (a large new review
surface) or the items below; it is documented, not hidden.

## Where the time goes (reference VM, in-package benchmarks)

| Building block | Before | After |
|---|---:|---:|
| Field multiplication (latency) | 28.6 ns | 21.4 ns |
| Field inversion | 9.4 µs | 5.6 µs |
| Scalar inversion | 15.4 µs | 7.6 µs |
| k·G (constant time) | 31.7 µs | 18.6 µs |

## Optimization history (same VM)

| Step | Sign | Verify | Recover |
|---|---:|---:|---:|
| First constant-time version (generic Montgomery) | 92 µs | 255 µs | 260 µs |
| Dedicated reduction for p, windowed exponentiation | 75 µs | 230 µs | 234 µs |
| Unrolled Comba multiplication and dedicated squaring | 61 µs | 168 µs | 170 µs |
| wNAF and projective x-check in Verify/Recover, stack HMAC | 59 µs | ~130 µs | ~149 µs |
| Fused row-wise field multiplication, specialized reduction and add/sub, addition chains | 48 µs | 100 µs | 111 µs |
| Unrolled Montgomery reduction for n, chain + sliding-window scalar inversion | 44 µs | 96 µs | 99 µs |
| Signed radix-32 base table with complete mixed addition | **34 µs** | 96 µs | 96 µs |
| Jacobian + GLV + width-8 G tables in the public-input path | 34 µs | **~56–59 µs** | **~66–69 µs** |

Every step kept the outputs byte-identical (differential, parity and
Wycheproof tests) and the constant-time properties (compiled-code check,
static guards, timing test).

## Possible further work (not done; each needs the same evidence)

- Constant-time "safegcd" (Bernstein–Yang) inversion for scalars and the
  field (about 5–8 µs per signature).
- Larger precomputed tables for G in verification (window 12–15) and
  effective-affine tables for the variable point (about 5–10 µs per
  verification).
- Assembly field multiplication (MULX/ADX on amd64, UMULH on arm64).

## GitHub runners

The `Benchmarks` workflow (`.github/workflows/bench.yml`) runs the same
comparison on Linux amd64, Linux arm64 and macOS arm64 runners and
publishes the `benchstat` table in the run summary and artifacts. Shared
runners are noisy; the reference-VM numbers above are the record.
