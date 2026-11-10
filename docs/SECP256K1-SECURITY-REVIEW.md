# SILA secp256k1 — internal security review (development)

Date: 2026-11-09 (updated after the parity and optimization rounds).
**This is a review by the implementation team, not an independent
audit.** It records what was checked, the evidence, and the risks that
remain.

## 1. Scope

At the head of `dev/secp256k1-v0.1`:
- `secp256k1/`: field and scalar arithmetic, group law, constant-time
  scalar multiplication, private keys, RFC 6979 signing (deterministic and
  hedged), verification, public-key recovery, SEC 1 and signature codecs,
  and the variable-time public-input path (`vartime.go`);
- `txsig/`: transaction-layer value rules and recovery-value encodings;
- `account/`: 20-byte address derivation.

## 2. Independence

The SILA module has no third-party dependencies and works offline; it does
not connect to, or depend on, any blockchain network. Production code
imports only the Go standard library and SILA packages, and names no
external project (`TestIndependentProductionCode`). External
implementations are used only as test oracles in the separate module
`benchmarks/geth-compare`. No code was copied from them; the GLV and
curve constants are mathematical facts derived and checked independently
with `math/big` in tests.

`scripts/check_independence.sh` (CI job "SILA independence") checks, on
every change: no requirements in `go.mod`; a transitive production
dependency graph of only SILA and standard-library packages; an offline
build and test run (no module proxy, cgo disabled); and a probe binary
linking `secp256k1`, `txsig`, `account` and `keccak` whose build metadata
records no other module and whose strings contain no foreign project or
network name. Protocol semantics are not imported either: the library sets
no default network, chain identifier, transaction type or domain, and the
open protocol items are BLOCKERs in the contract (§7).

## 3. Secret-handling design

| Secret | Where | Protection |
|---|---|---|
| Private key d | `PrivateKey.d` | Range check, d·G, r·d and serialization are constant time. No `math/big`. |
| Nonce k | inside `sign` | RFC 6979 on stack buffers; k·G by the constant-time signed-digit base table; k⁻¹ by a fixed addition chain and a sliding window over the **public** exponent n − 2; k and k⁻¹ are overwritten after use. |
| Extra entropy (hedged API) | `SignWithExtraEntropy`, `SignHedged` | Copied into the stack HMAC input, cleared after use. |
| HMAC state (K, V) | `rfc6979` value on the stack | Fixed-size stack arrays, cleared. Sign makes 0 heap allocations (`TestSignDoesNotAllocate`, `TestSignHedged`). |

Constant-time techniques:
- Limb arithmetic uses only `math/bits` Add64/Sub64/Mul64 and masks.
  Branches depend only on public constants (loop bounds, the bits of p − 2,
  (p + 1)/4 and n − 2).
- Complete projective formulas (Renes–Costello–Batina 2016, Alg. 7, 8, 9).
  The mixed addition (Alg. 8) requires an affine operand that is not the
  identity; base-table entries never are, and a zero digit discards the
  sum with a constant-time select.
- Signed radix-32 digits (Booth recoding), computed with masks; every
  table lookup scans all 16 entries; the sign is applied with a
  constant-time negation and select.
- Processor support: on arm64, Arm guarantees data-independent timing of
  multiplications and other instructions only while PSTATE.DIT is set.
  With Go ≥ 1.24, `Sign`, the hedged variants and `PrivateKey.PublicKey`
  run their secret-dependent work inside
  `crypto/subtle.WithDataIndependentTiming`, which sets DIT on processors
  with FEAT_DIT (no effect elsewhere; Go 1.23 builds run without it).
- The variable-time code (Jacobian formulas with explicit special cases,
  GLV split, wNAF) is confined to `vartime.go` and is reachable only from
  Verify and RecoverPublicKey, whose inputs are all public.

Enforced by tests:
- `TestNoVariableTimeImports`: import allow-list; `math/big` is not on it.
- `TestVariableTimeHelpersOnlyOnPublicPaths`: AST check that every
  function defined in `vartime.go` is called only from Verify,
  RecoverPublicKey and other `vartime.go` functions.
- `TestCompiledConstantTimeFunctions` (run in CI): disassembles the
  compiled field, scalar and point functions and fails on any conditional
  branch other than the stack-growth prologue; a negative control shows
  the detector finds the branches of a variable-time function. Passes for
  amd64, arm64, 386, ppc64le and riscv64 machine code, with Go 1.23 and
  1.25. `TestCompiledLoopsAreCounterBound` lists the branches of the
  functions with loops (counter and public-index tests) for review.

## 4. Findings during development (all fixed)

| # | Finding | Fix | Regression evidence |
|---|---|---|---|
| S-1 | The initial package used variable-time `math/big` | Constant-time limb arithmetic | `TestNoVariableTimeImports` |
| S-2 | `crypto/hmac` leaves key-derived K and V in unreachable heap memory | Stack HMAC-SHA-256, cleared after use | `TestHMACSHA256MatchesStandardLibrary`, `TestSignDoesNotAllocate` |
| S-3 | The nonce-generator state escaped to the heap | Value type on the stack | 0 allocs/op in Sign |
| S-4 | An unchecked assumption about digests ≥ n | Measured; documented in the contract | `TestSecp256k1DigestAboveOrder` |
| S-5 | High-S handling was one rule for all contexts; raw recovery must accept high-S, transactions must not | Strict and recovery-compatible parsers; `txsig` rules; `Verify` stays strict | `TestHighSContexts`, `TestParityRawRecovery`, `TestParityValidateSignatureValues` |
| S-6 | Branch-free source does not guarantee branch-free machine code | Compiled-code check in CI on five architectures | `TestCompiledConstantTimeFunctions` |
| S-7 | During the optimization round, one timing session showed \|t\| = 5.5 for k·G | Re-measured with 5× more samples and a random-vs-random control: \|t\| did not grow, and the control reached the same level (see §6) | `TestConstantTimeStatistical` (control class) |

## 5. Correctness evidence

The full matrix (case → reference → test → result) is in
[`SECP256K1-PARITY.md`](SECP256K1-PARITY.md). In addition:

| Check | Result |
|---|---|
| Field and scalar operations vs `math/big` (edge values and random), the fused field multiplication and squaring, the unrolled Montgomery reduction, both inversion chains | identical |
| Group law vs an affine textbook reference; mixed vs complete addition; Jacobian formulas incl. P = Q, P = −Q, identity, Z ≠ 1 | identical |
| GLV constants (λ, β, lattice, rounding constants) vs `math/big`; 3000 scalar splits recombine and stay below 2^128 | pass |
| Variable-time combination vs the constant-time multiplications, incl. results equal to the identity | identical |
| Fuzzing | 4 targets: public-key round trip; parse + verify + recover; sign → verify → recover; 64-byte y-parity form |
| Architectures | amd64 and arm64 (Go 1.23 and 1.25, with `-race`); 386; s390x (big-endian), ppc64le and riscv64 under QEMU; loong64 build |

## 6. Timing evidence

`timing_test.go` (opt-in, `SILA_TIMING_TEST=1`) runs a dudect-style Welch
t-test between tiny secrets (1..255) and random secrets, interleaved, on
one pinned core, three repetitions per check; it fails only if every
repetition exceeds |t| = 4.5. A control compares two random classes.
Reference VM, after the optimization round:

| Operation | 20,000 samples (3 sessions × 3 runs) | 100,000 samples (2 sessions × 3 runs) |
|---|---|---|
| k·G | 1.69 – 5.50 | 0.38 – 3.53 |
| control (random vs random k·G) | — | 0.71 – 3.96 |
| k·P (generic) | 0.48 – 3.92 | 1.11 – 3.17 |
| scalar inverse | 0.87 – 2.82 | 0.93 – 2.96 |
| Sign (end to end) | 0.41 – 4.15 | 1.56 – 3.81 |

A real data-dependent difference grows with the number of samples (×√5 ≈
2.2 here); these values did not, and the random-vs-random control reached
the same level. **No leak was detected above the noise of this shared VM.**
This cannot rule out smaller leaks or micro-architectural channels
(cache, port contention) that wall-clock timing does not show.

### 6.1 GitHub runners (commit 05622d6, open finding S-8)

The improved test (one fixed input address, fresh secret sets per run,
signed t, random-vs-random control per operation; 100k samples, 5 runs)
on shared GitHub runners, neither of which reports FEAT_DIT:

| Runner | Operation | tiny vs random t (5 runs) | control t |
|---|---|---|---|
| amd64 | scalar inverse | +12.83, +56.99, +10.86, +9.25, +11.97 | +1.90, +1.79, −1.21, −0.86, +2.66 |
| arm64 | k·G | −12.38, −11.76, −6.82, −9.12, −7.89 | −2.65, +6.00, −1.90, −0.56, +1.70 |
| amd64, arm64 | Sign (end to end) | below the bound, mixed signs | — |

**S-8 (open):** these are consistent, same-sign differences for an extreme
secret class (values 1..255, whose Montgomery form has zero high limbs),
larger than the controls, so they are not explained by noise. The compiled
code of these functions has no data-dependent branch or memory access
(§3), so the difference comes from the processor's handling of operand
values (data-dependent instruction timing or power/frequency effects).
Nonces in `Sign` are uniform 256-bit values, and end-to-end `Sign` stayed
below the bound, but a timing dependence on the nonce's value is not
acceptable for production. Planned mitigations (not yet implemented):
blind the nonce inversion (invert k·b for a secret uniform b derived from
the RFC 6979 state, then multiply by b), randomize the projective
coordinates of the k·G accumulator, and repeat the measurement on
dedicated amd64 and arm64 hardware with DIT available.

## 7. Residual risks (must be resolved or accepted before production)

0. **Open timing finding S-8** (§6.1): consistent timing differences for
   extreme secret classes in scalar inversion (amd64 runner) and k·G
   (arm64 runner). Blocks production use until mitigated and re-measured.
1. **No independent audit** of the arithmetic, the formulas, the GLV code
   or the constant-time claims.
2. **Timing evidence is limited** to a shared VM. Needed: millions of
   samples on dedicated, quiet hardware for each target CPU (amd64 and
   arm64 at least), with frequency scaling disabled.
3. **Compiler dependence:** Go gives no constant-time guarantee. The
   compiled-code check covers the listed functions for the Go versions in
   CI; it must be re-run (it is, in CI) for every Go release used in
   production, and it does not check functions with loops beyond listing
   their branches.
4. **Memory hygiene is best-effort:** `PrivateKey.Zero`, cleared stack
   buffers and zero-allocation signing reduce exposure, but Go may copy
   stack frames (stack growth), and callers' copies of key bytes are
   outside the package's control.
5. **Fault attacks:** the default deterministic signing is exposed to
   fault injection (a glitch during signing can leak the key from two
   signatures over the same digest). `SignHedged` mitigates this; using it
   is the caller's or the protocol's decision.
6. **Protocol integration is not specified** (contract §7): the transaction
   encoding, chain identifier, domain separation and address text format.
   The library defines none of them.
7. **Performance:** libsecp256k1 (C) is 12 % faster for signing and 33 %
   faster for verification and recovery (`SECP256K1-PERFORMANCE.md`).
   Node-level throughput must be sized on the measured numbers.
