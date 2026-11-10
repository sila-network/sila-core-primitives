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
| S-9 | Randomness failure paths: unbounded loop on a broken source; a zero source left the key unmasked; one failure disabled the process-wide blinding | Bounded draws; HMAC-derived key mask; retry instead of `sync.Once` | `TestBlindingWithoutRandomness`, `TestRefreshBlindingBounded` |
| S-8 | Value-dependent timing for extreme secrets on shared runners (inversion, k·G) | Blinded nonce inversion, blinded fixed-base multiplication, masked private key; corrected timing harness | `TestBlinded*`, `TestPrivateKeyShares`, `TestConstantTimeStatistical` (§6.1); **mitigated, not closed** |
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

### 6.1 Finding S-8 — value-dependent timing on shared runners

**Status: mitigated; NOT closed for production** (see "closure" below).

**What was observed (05622d6).** On shared GitHub runners (no FEAT_DIT),
scalar inversion (amd64, t +9.25..+56.99) and k·G (arm64, t −6.8..−12.4)
were consistently slower/faster for tiny secrets (1..255, whose Montgomery
form k·(2^256 mod n) has zero high limbs) than for random ones.

**Root-cause analysis.**
1. *Code and compiled code:* no secret-dependent branch or memory access
   (the compiled-code check passes on amd64, arm64, 386, ppc64le,
   riscv64). The functions execute the same instruction stream for every
   input.
2. *Measurement artefact (proven and fixed):* the timing harness copied the
   secret from its class's array inside the timed region, so the memory
   placement of each class entered the timing. On one amd64 runner this
   made two **random** classes differ consistently (copy-only control
   t = 44..122; blinded-inverse control ≈ +5.5 in every run). Since
   1a6e7ca the secret is loaded outside the timed region.
3. *Processor behaviour (reproduced with the corrected harness):* the raw,
   unblinded inversion still shows consistent same-sign differences for
   tiny secrets on some runner instances while the per-operation controls
   do not: amd64 t = +46.03, +37.79, +19.98, +34.28, +42.38 (control
   −6.69..+0.28); arm64 t = +22.01, +3.45, +1.03, +0.65, +11.45 (control
   −0.21..+2.93); another amd64 instance −1.29..−4.55. With identical
   instruction streams, the remaining explanation is value-dependent
   timing in the processor (data-dependent instruction latency or
   power/frequency effects), which neither x86 without DOIT nor Arm without
   DIT rules out. The exact micro-architectural mechanism was not
   identified; it varies between runner instances.

**Fix (724ef8e, 1a6e7ca, and the private-key masking commit).** Make every
value that reaches a multiplication statistically independent of the
secret, whatever the processor does:
- nonce inversion: (k·ρ)⁻¹·ρ with a per-signature secret ρ derived from
  the RFC 6979 key K (domain-separated HMAC; the candidate sequence is
  unchanged);
- k·G and d·G: (k + b)·G + (−b·G) with a secret process-wide b
  (crypto/rand; `RefreshBlinding`; derived per-call fallback);
- private key: stored as random shares d = d1 + d2; r·d = r·d1 + r·d2, and
  int2octets(d) and the public key are rebuilt by additions only, so d is
  never a multiplication operand;
- unchanged results: signatures stay byte-identical to deterministic
  RFC 6979 (all parity tests), 0 allocations; Sign +3 µs.

**Evidence after the fix** (corrected harness since 1a6e7ca; 100k samples
× 5 runs per job; a production path fails when all 5 runs exceed
|t| = 4.5 with the same sign). 10 jobs on shared GitHub runners (5 amd64,
5 arm64; commits 1a6e7ca, a re-run, and f4ff94b with the masked key):

| Path | Jobs meeting the failure criterion | Notes |
|---|---|---|
| raw inversion (diagnostic, unblinded) | 1 of 10 by the criterion; 3 of 10 with all 5 runs on one side | clean-control cases: amd64 +19.98..+46.03, arm64 +0.65..+22.01 |
| blinded inversion | 0 of 10 | |
| blinded k·G | 0 of 10 | two arm64 jobs had all-positive t (0.84..11.67), below the criterion |
| Sign | 0 of 10 | one pre-masking amd64 job had all-negative t (−1.62..−6.09) |
| PublicKey | 0 of 10 | one arm64 job all-positive (1.39..9.17) with a control of the same size (−6.16..8.66) |

The random-vs-random controls themselves reach |t| = 10–120 and sometimes
keep one sign over 5 runs (e.g. +1.78..+4.75), so these runners cannot
resolve effects below roughly |t| ≈ 10.

**Closure.** S-8 is mitigated by construction (the secret never reaches a
multiplication unmasked) and the production paths pass on shared runners,
but it is **not closed**: (a) the shared runners are too noisy to give
strong repeated evidence (controls reach |t| = 20–120 in some runs); (b) no
dedicated, quiet amd64 and arm64 hardware with DIT/DOIT was available;
(c) the masking commit has 4 runner jobs so far. Required to close: millions of samples on dedicated hardware for
each target CPU, including the masked Sign and PublicKey paths.

### 6.2 Behaviour without (or with broken) randomness — finding S-9

Audit of every path that reads randomness in the blinding and masking
code (the RFC 6979 output never depends on randomness):

| Situation | Before | Now |
|---|---|---|
| crypto/rand fails (Go 1.23 returns an error; Go ≥ 1.24 crashes the program instead, fail-closed) | per-call blinding derived from the secret (safe), but a failure at first use disabled the process-wide blinding for the life of the process (`sync.Once`) | same safe fallback; creation is retried on the next call |
| a source returns only zeros (no error) to `RefreshBlinding` | **endless loop** (rejection sampling without bound) | error after 64 draws, current blinding kept |
| a source returns zeros to the key mask | **key stored unmasked** (d1 = 0) | mask = HMAC-SHA-256(key = d, label ‖ random) — pseudo-random and secret even with no or predictable randomness |
| any failure | never an unblinded or unmasked computation; results unchanged | covered by `TestBlindingWithoutRandomness`, `TestRefreshBlindingBounded` |

`SignHedged` with a failing reader returns the reader's error (it never
signs without its extra entropy). `RefreshBlinding` requires a
cryptographically secure source: a predictable one voids the protection
(never correctness), which is documented on the function.

### 6.3 What closing S-8 still requires (not available here)

| Test | Why it is needed | Status |
|---|---|---|
| ≥ 1,000,000 samples × 10 runs per path on a dedicated amd64 machine (fixed frequency, no turbo, isolated core) | shared runners' controls reach \|t\| = 10–120 | **not available**; `scripts/timing_dedicated.sh` is ready |
| the same on a dedicated arm64 machine with FEAT_DIT (and one without) | Arm guarantees data-independent timing only under DIT | **not available**; partial: CI job on macOS arm64 (Apple Silicon, FEAT_DIT) |
| x86 with DOIT enabled (Intel `IA32_UARCH_MISC_CTL`, AMD equivalent) | the x86 counterpart of DIT; needs kernel/BIOS support | **not available** |
| power / electromagnetic analysis | timing tests cannot see these channels | **not available** (lab equipment) |
| independent human audit of the blinding and masking code | the reviews so far are internal and automated | **not available**; requested from the owner |

Closure criterion per machine (also in the script): for every production
path, no set of 10 runs has \|t\| > 4.5 with one sign in all runs, and the
random-vs-random controls stay below 4.5 in at least 9 of 10 runs.

## 7. Residual risks (must be resolved or accepted before production)

0. **Timing finding S-8 — mitigated, not closed** (§6.1, §6.3): processor
   value-dependent timing on shared runners; blinding and key masking are
   in place; closing needs the dedicated-hardware measurements of §6.3 and
   an independent audit.
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
