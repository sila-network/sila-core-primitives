# SILA Core Primitives — secp256k1

Status: **development candidate, not released, not approved for production.**
Original SILA implementation; Apache-2.0; Copyright 2026 Ahmed Ibrahim.
No third-party dependencies; works offline and does not depend on any
blockchain network.

## Packages and API

### `secp256k1` — keys and ECDSA

| Function / type | Purpose |
|---|---|
| `ParsePublicKey`, `PublicKey.Compressed`, `.Uncompressed`, `.Coordinates`, `.Equal` | Strict SEC 1 public-key codec (33/65 bytes) |
| `ParsePrivateKey`, `GeneratePrivateKey`, `PrivateKey.Bytes`, `.PublicKey`, `.Zero` | Private keys in [1, n−1] |
| `Sign(priv, digest)` | Deterministic ECDSA (RFC 6979), low-S, with recovery identifier — the default |
| `SignWithExtraEntropy`, `SignHedged` | Separate hedged API (RFC 6979 §3.6); valid signatures, not byte-identical to `Sign` |
| `Verify(pub, digest, sig)` | Strict verification (canonical, low-S) |
| `RecoverPublicKey(digest, sig)` | Generic public-key recovery, v ∈ {0..3} |
| `ParseSignature` (64 B), `ParseRecoverableSignature` (65 B) | Strict signature parsers (low-S) |
| `ParseSignatureAllowHighS`, `ParseRecoverableSignatureAllowHighS` | Recovery-compatible parsers (s < n) |
| `Signature.Compact`, `.Recoverable`, `.R`, `.S`, `.RecoveryID`, `.IsLowS`, `.Normalize` | Encodings and accessors |

### `txsig` — transaction-layer rules

`ParseValues`, `Parse`, `Recover` with the `Strict` (low-S, v ∈ {0, 1}) or
`RecoveryCompatible` (s < n, v ∈ {0, 1}) rule; `LegacyV` / `FromLegacyV`
(27/28); `ChainV` / `FromChainV` (v + 35 + 2·chainID, chain identifier as
a parameter); `CompactYParity` / `ParseCompactYParity` (64-byte form with
the y-parity in the top bit of s).

### `account` — addresses

`FromPublicKey`: the last 20 bytes of SILA Keccak-256 over the 64-byte
X ‖ Y.

The caller provides a 32-byte digest; the packages do not hash. The rules
are in [`docs/SECP256K1-SIGNATURE-CONTRACT.md`](../docs/SECP256K1-SIGNATURE-CONTRACT.md);
§7 there lists the protocol items (transaction encoding, chain identifier,
domain separation, address text) that the project has not specified yet
and that this library does not invent.

## Security properties

- No `math/big` in production code (enforced by a test). All arithmetic on
  private keys and nonces is constant time: limb arithmetic with masks,
  complete addition formulas, full-table scans, fixed addition chains.
- The compiled machine code of the constant-time functions is checked for
  conditional branches in CI (amd64, arm64, 386, ppc64le, riscv64).
- Variable-time code is confined to `vartime.go` and processes only public
  inputs in Verify and Recover (enforced by a static test).
- Signing allocates nothing on the heap; the RFC 6979 and HMAC state lives
  in stack buffers that are cleared.
- Details, evidence and residual risks:
  [`docs/SECP256K1-SECURITY-REVIEW.md`](../docs/SECP256K1-SECURITY-REVIEW.md).

## Equivalence

Byte-identical signatures, identical verification and recovery verdicts,
identical value rules, recovery-value encodings, key parsing and
addresses, measured against go-ethereum v1.17.10 (libsecp256k1) and
decred as test oracles: [`docs/SECP256K1-PARITY.md`](../docs/SECP256K1-PARITY.md).
The comparison tests live in `benchmarks/geth-compare` (a separate module).

## Performance

GitHub ubuntu-24.04-arm runner (Neoverse-N2), commit `0f62f69`, against
libsecp256k1 (C, through go-ethereum's binding): Sign 40.2 µs vs 26.6 µs
(Sign computes k·G twice as a fault check, which libsecp256k1 does not),
Verify 32.7 µs vs 33.6 µs, Recover 38.6 µs vs 39.0 µs, public key
18.4 µs; 0 allocations. Faster than decred (pure Go) in every operation.
Results depend on the CPU; details and amd64 figures:
[`docs/SECP256K1-PERFORMANCE.md`](../docs/SECP256K1-PERFORMANCE.md).

## References

- SEC 1 v2.0 and SEC 2 v2.0 (https://www.secg.org/).
- RFC 6979 (deterministic ECDSA).
- Renes, Costello, Batina, "Complete addition formulas for prime order
  elliptic curves", EUROCRYPT 2016.
- Gallant, Lambert, Vanstone, "Faster point multiplication on elliptic
  curves with efficient endomorphisms", CRYPTO 2001.
- Project Wycheproof test vectors (Apache-2.0), see `testdata/wycheproof/`.
