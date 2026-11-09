# SILA secp256k1 — internal security review (development)

Date: 2026-11-09. **This is a review by the implementation team, not an
independent audit.** It records what was checked, the evidence, and the
risks that remain.

## 1. Scope

`secp256k1/` at the head of `dev/secp256k1-v0.1`: field and scalar
arithmetic, group law, constant-time scalar multiplication, private keys,
RFC 6979 signing, verification, public-key recovery, and the SEC 1 and
signature codecs.

## 2. Secret-handling design

| Secret | Where | Protection |
|---|---|---|
| Private key d | `PrivateKey.d` (scalar) | Range check, d·G, r·d and serialization are constant time. No `math/big`. |
| Nonce k | inside `Sign` | Derived by RFC 6979 on stack buffers; k·G uses the constant-time base table; k⁻¹ uses fixed-exponent Montgomery exponentiation; k and k⁻¹ are overwritten after use. |
| HMAC state (K, V) | `rfc6979` value on the stack | `hmacSHA256` uses fixed-size stack arrays, cleared on return. Sign makes 0 heap allocations (`TestSignDoesNotAllocate`), so no key-derived bytes are left in unreachable heap memory. |

Constant-time techniques:
- Limb arithmetic only uses `math/bits` Add64/Sub64/Mul64 and masks. The
  only branches depend on public constants: loop bounds and the nibbles of
  the fixed exponents p−2, (p+1)/4 and n−2.
- Complete projective addition and doubling formulas (Renes–Costello–Batina
  2016, Alg. 7 and 9), so the identity, doubling and P + (−P) need no
  branch.
- Fixed 4-bit windows with full-table scans for every secret table lookup
  (`point.lookup`).
- Variable-time code (`wnaf5`, `linearCombinationVartime`) exists only for
  Verify and RecoverPublicKey, whose inputs are all public.

Enforced by tests:
- `TestNoVariableTimeImports`: production files may import only an
  allow-list, and `math/big` is not on it.
- `TestVariableTimeHelpersOnlyOnPublicPaths`: an AST check that the
  variable-time helpers are called only from Verify and RecoverPublicKey.

## 3. Findings during development (all fixed before this review)

| # | Finding | Fix | Regression evidence |
|---|---|---|---|
| S-1 | The initial package used variable-time `math/big` | Rewrote all arithmetic on constant-time limbs | `TestNoVariableTimeImports` |
| S-2 | `crypto/hmac` allocates heap objects that hold the key-derived K and V and cannot be erased | Stack HMAC-SHA-256, cleared after use | `TestHMACSHA256MatchesStandardLibrary`, `TestSignDoesNotAllocate` |
| S-3 | The nonce-generator state escaped to the heap | Made it a value type (stack-resident) | 0 allocs/op in Sign |
| S-4 | An unchecked assumption about digests ≥ n | Measured: SILA = libsecp256k1 (RFC 6979 bits2octets); decred differs. Documented in the contract | `TestSecp256k1DigestAboveOrder` |

## 4. Correctness evidence

| Check | Result |
|---|---|
| Field and scalar operations vs `math/big` (edge values and random), including arbitrary 512-bit reduction inputs | identical |
| Group law vs an affine textbook reference: n·G = O, (n−1)·G = −G, identity, doubling, scaled projective inputs | identical |
| Signatures vs libsecp256k1 (C) | 1000/1000 random cases byte-identical, plus 50/50 with digests ≥ n |
| Signatures vs decred (pure Go) | 1000/1000 byte-identical for digests < n |
| Verify verdicts vs libsecp256k1 (valid, bit flips, high-S, random, wrong digest) | 2000/2000 identical |
| Public-key parsing vs decred (valid, random x, corrupted) | 4000/4000 identical |
| Recovery | both directions with libsecp256k1 and decred; v = 2/3 via a constructed R.x ≥ n case |
| Wycheproof ECDSA secp256k1 "bitcoin" (low-S) | 464/464 verdicts identical |
| Wycheproof "p1363" | 252/252 identical, except 72 valid high-S signatures that SILA rejects by contract |
| Fuzzing | public-key round trip; parse + verify + recover; sign → verify → recover |
| Architectures | amd64 and arm64 (CI); 386 native; s390x (big-endian), ppc64le and riscv64 under QEMU; loong64 build |

## 5. Timing evidence

`timing_test.go` (opt-in, `SILA_TIMING_TEST=1`) runs a dudect-style Welch
t-test between tiny keys (1..255) and random keys, 20,000 interleaved
samples per run, three runs per check, on the shared reference VM:

| Operation | \|t\| range over two sessions (6 runs) |
|---|---|
| k·G (base table) | 0.64 – 3.87 |
| k·P (generic) | 0.48 – 3.71 |
| scalar inverse | 0.49 – 4.39 |
| Sign (end to end) | 1.47 – 4.84 (one run above 4.5) |

A control between two random-key classes reached |t| = 3.6 on the same VM,
so these numbers are within that machine's noise. No consistent leak was
detected, but **Sign sits close to the bound**, and this test cannot rule
out leaks below the noise floor or micro-architectural channels (cache,
port contention) that wall-clock timing does not reveal.

## 6. Residual risks (must be resolved or accepted before production)

1. **No independent audit** of the arithmetic, the formulas or the
   constant-time claims.
2. **Timing evidence is limited** to wall-clock measurements on a shared VM.
   Needed: millions of samples on dedicated, quiet hardware for each target
   CPU, and ideally a tool-based constant-time check of the compiled code
   (for example a ctgrind-style or binary-level analysis).
3. **Compiler dependence:** Go gives no constant-time guarantee. A future
   compiler could turn mask selections into branches. The compiled code
   should be reviewed for each Go release used in production.
4. **Memory hygiene is best-effort:** `PrivateKey.Zero`, the cleared stack
   buffers and the zero-allocation Sign reduce exposure. But Go may copy
   stack frames (stack growth) or values passed by value, and callers'
   own copies of key bytes are outside this package's control.
5. **Fault attacks:** deterministic signing without extra entropy is
   exposed to fault-injection attacks (a glitch during signing can leak
   the key from two signatures over the same digest). Mitigation, hedged
   signing, is an OPEN protocol choice.
6. **Protocol decisions are open** (`SECP256K1-SIGNATURE-CONTRACT.md`):
   hashed encoding and domain separation, compact or recoverable form, the
   policy for v = 2/3, the canonical public-key form, and addresses.
7. **Performance:** pure Go is 2–3.4× slower than libsecp256k1. This is
   acceptable for wallets and signing services, but node-level verification
   throughput must be sized against the measured numbers
   (`SECP256K1-PERFORMANCE.md`).
