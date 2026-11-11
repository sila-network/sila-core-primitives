# SILA secp256k1 — performance record

Comparison with two independent implementations, used as references only
(separate module `benchmarks/geth-compare`): libsecp256k1 (C, through
go-ethereum v1.17.10's cgo binding) and decred dcrd secp256k1/v4 v4.0.1
(pure Go). The benchmark `BenchmarkSecp256k1` uses the same key and digest
for every implementation and calls each one through its public API.

## Current state (2026-11-11, performance round 3, head `3561401`)

Results on GitHub runners, SILA versus libsecp256k1 (go-ethereum
v1.17.10 cgo binding), same job and inputs, `benchstat` medians, n = 6,
Benchmarks run [#43025834696](https://github.com/sila-network/sila-core-primitives/actions/runs/43025834696):

| Runner (CPU) | Sign | Verify | Recover |
|---|---|---|---|
| ubuntu-24.04-arm (Neoverse-N2) | **25.10 vs 26.51 µs: SILA 5.6 % faster** | **32.57 vs 33.65 µs: SILA 3.3 % faster** | **38.48 vs 38.98 µs: SILA 1.3 % faster** |
| ubuntu-latest (AMD EPYC 9V74) | **22.53 vs 22.70 µs: SILA 0.8 % faster** | **29.75 vs 36.31 µs: SILA 22 % faster** | **35.36 vs 42.00 µs: SILA 19 % faster** |

All six differences have p = 0.002. The amd64 result depends on the
runner's CPU: on an Intel Xeon Platinum 8573C runner (run of `2e26a3b`,
before the last two steps) libsecp256k1 was 1.5 % faster on Sign and 6 %
faster on Recover, with Verify not significantly different. Shared
runners are not dedicated hardware; these are not timing-leak results.

Round 3 changes on arm64 (each measured on ubuntu-24.04-arm against the
previous commit; changes without a measured gain were reverted with a
new commit: shift-based squaring `08a9aa7`, fused fieldMul reduction
`a591f58`, paired subtraction `07ec5d5`, batched variable-time divsteps
(not committed)):

| Change | Paths | Constant time? | Effect (arm64) |
|---|---|---|---|
| arm64 assembly: field/scalar multiplication and squaring (MUL/UMULH, ADDS/ADCS, CSEL), NEON base-table scan | all | yes (straight line; source allow-list and compiled-code checks) | Sign 32.9 → 27.2 µs, Verify 45.8 → 38.3 µs |
| Products from four independent 2×2 products; final reduction as two parallel sums selected by the carry | all | yes | FieldMul 17.9 → 15.2 ns |
| Half-delta constant-time divsteps, 620 instead of 744 | Sign, PublicKey | yes | Sign 27.0 → 25.6 µs |
| Fewer field additions in the public formulas (8M + 3S mixed addition, no negations in the doubling); fused subtraction helpers; 3T − L² in the doubling | Verify, Recover | no — public inputs only | Verify 38.8 → 34.7 µs |
| wNAF skips runs of zero digits | Verify, Recover | no — public | Verify 34.7 → 33.4 µs |
| GLV split in integer arithmetic modulo 2^192 | Verify, Recover | no — public | Verify 33.3 → 32.6 µs |

## Round 2 (2026-11-11)

What changed (each step measured A/B against the previous commit and
checked by the full test suite; see the commit messages):

| Change | Paths | Constant time? |
|---|---|---|
| Field multiplication/squaring in amd64 assembly: MULX/ADCX/ADOX when CPUID reports BMI2+ADX, MULQ otherwise; scalar Montgomery multiplication likewise | all, amd64 only | yes (straight line; checked, §3 of the security review) |
| SSE2 scan of the fixed-base table (all 16 entries, masks) | Sign, PublicKey, amd64 only | yes |
| Constant-time divstep scalar and field inversion (620 fixed half-delta divsteps; 744 before) | Sign, PublicKey | yes |
| Variable-time divstep inversion; effective-affine co-Z table for the public point; halved doubling; width-12 G tables (128 KiB, built on the first verification, about 0.4 ms) | Verify, Recover only | no — public inputs only |
| Per-signature fresh masks and key-share re-randomisation (security fix S-12/S-13) | Sign | yes; costs about +7 % on Sign |

Measured results, SILA versus libsecp256k1 (go-ethereum v1.17.10 cgo
binding) and decred, same machine and process (`benchstat`, medians):

| Machine | Commit | Sign | Verify | Recover | PublicKey |
|---|---|---|---|---|---|
| Development VM, Xeon 2.3 GHz (amd64, ADX), pinned core, n = 10 | `d3a76d3` (before S-12/S-13) | **20.25 vs 21.95 µs: SILA 8 % faster** (p = 0.001) | **29.57 vs 30.38 µs: SILA 2.7 % faster** (p = 0.015) | 35.32 vs 35.82 µs: no significant difference (p = 0.218) | 13.88 µs (decred 29.54) |
| GitHub runner, Xeon Platinum 8573C (amd64, ADX), n = 6 | `d3a76d3` | 26.37 vs 25.03 µs: **libsecp256k1 5 % faster** | 37.76 vs 32.87 µs: **libsecp256k1 13 % faster** | 45.71 vs 39.16 µs: **libsecp256k1 14 % faster** | 18.25 µs (decred 38.19) |
| GitHub runner, ubuntu-24.04-arm (arm64, no assembly), n = 6 | `d3a76d3` | 32.21 vs 26.55 µs: **libsecp256k1 18 % faster** | 45.99 vs 33.62 µs: **libsecp256k1 27 % faster** | 52.99 vs 38.96 µs: **libsecp256k1 26 % faster** | 24.93 µs (decred 35.19) |

On every machine SILA is faster than decred (1.2× – 3×) and makes zero
heap allocations (libsecp256k1 through cgo: 5 for Sign). Against
libsecp256k1 the target "no slower on representative machines" is
**not met**: it holds on the development VM only, and S-12/S-13 then
added about 7 % to Sign. On the GitHub amd64 runner the gap is 5–14 %, on
arm64 18–27 % (no assembly there). Before this round the gap on the
development VM was 12 % (Sign) and 33 % (Verify, Recover).

Technical reasons for the round-2 gap (since addressed in round 3 by
arm64 assembly and the public-path changes above): libsecp256k1 uses
5×52-bit limbs with lazy reduction; SILA keeps every field element
canonical and then had assembly only on amd64. Raw data:
`benchmarks/geth-compare/results/local-2026-11-11-secp256k1-r3/` — the
development-VM run of `d3a76d3`, and a run of `515377b` (after S-12/S-13)
on a second, much noisier VM (spread ±15–50 %, libsecp256k1 itself 46–48
µs there), which is kept for completeness and not used for any claim.

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
| Faster than libsecp256k1 (C) | **not met** at the time (Sign 12 %, Verify and Recover 33 % slower); see "Current state" above |

Why libsecp256k1 is still faster (as built by go-ethereum's cgo binding,
checked in its sources: no assembly is enabled): it is C compiled with
5×52-bit limbs, 128-bit integer products and lazy reduction (fewer carry
chains than Go's `math/bits` code); verification uses window-15 tables for
G and the "effective affine" technique for the variable point; k·G uses a
signed-digit comb; inversions use the "safegcd" (Bernstein–Yang)
algorithm, where SILA uses fixed addition chains. Closing the gap in Go
would need assembly field arithmetic per architecture (a large new review
surface) or the items below; it is documented, not hidden.

## After the S-8 side-channel fix (2026-11-10)

Same VM and method, 8 pinned runs (raw data:
`benchmarks/geth-compare/results/local-2026-11-10-secp256k1-s8/`, measured
with the blinding; the later private-key masking adds one scalar
multiplication, about 0.03 µs):

| Operation | SILA before | SILA after | libsecp256k1 | decred |
|---|---:|---:|---:|---:|
| Sign | 33.55 µs | 36.49 µs ±7 % | 29.55 µs | 41.13 µs |
| Verify | 59.32 µs | 61.39 µs ±5 % | 41.72 µs | 146.36 µs |
| Recover | 69.07 µs | 69.49 µs ±8 % | 48.66 µs | 175.11 µs |
| Public key | 22.94 µs | 24.24 µs ±5 % | — | 36.21 µs |

Allocations stay at 0 for every operation. The blinding cost about
3 µs per signature on that VM; the shared-runner measurement of the same
code (Sign 43 µs, decred 40 µs) showed that this ratio does not hold on
every CPU.

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
