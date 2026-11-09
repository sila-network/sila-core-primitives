# SILA Core Primitives — secp256k1

Status: **development candidate, not released, not approved for production.**
Original SILA implementation; Apache-2.0; Copyright 2026 Ahmed Ibrahim.

## API

| Function / type | Purpose |
|---|---|
| `ParsePublicKey`, `PublicKey.Compressed`, `.Uncompressed`, `.Coordinates`, `.Equal` | Strict SEC 1 public-key codec (33/65 bytes) |
| `ParsePrivateKey`, `GeneratePrivateKey`, `PrivateKey.Bytes`, `.PublicKey`, `.Zero` | Private keys in [1, n−1] |
| `Sign(priv, digest [32]byte)` | Deterministic ECDSA (RFC 6979), low-S, with recovery identifier |
| `Verify(pub, digest, sig)` | Strict verification (canonical, low-S) |
| `RecoverPublicKey(digest, sig)` | Public-key recovery from a 65-byte signature |
| `ParseSignature` (64 B), `ParseRecoverableSignature` (65 B), `Signature.Compact`, `.Recoverable`, `.R`, `.S`, `.RecoveryID` | Strict signature codecs |

The caller provides a 32-byte digest; the package does not hash. The rules
(low-S, v ∈ {0..3}, digest mod n, encodings) are in
[`docs/SECP256K1-SIGNATURE-CONTRACT.md`](../docs/SECP256K1-SIGNATURE-CONTRACT.md).
Several protocol choices there are **OPEN** and await the owner's decision.

## Security properties

- No `math/big` in production code (enforced by a test). All arithmetic on
  private keys and nonces is constant time: Montgomery or special-form
  limb arithmetic, complete addition formulas, full-table scans.
- Variable-time code only processes public inputs in Verify and Recover
  (enforced by a static test).
- Sign allocates nothing on the heap; the RFC 6979 and HMAC state lives in
  stack buffers that are cleared.
- Details, evidence and residual risks:
  [`docs/SECP256K1-SECURITY-REVIEW.md`](../docs/SECP256K1-SECURITY-REVIEW.md).

## Equivalence

- **Signatures:** byte-identical to libsecp256k1 for every digest tested,
  and to decred for digests < n.
- **Verification:** verdicts identical to libsecp256k1.
- **Public-key parsing:** identical to decred.
- **Wycheproof:** all 464 "bitcoin" vectors pass.

The differential tests live in `benchmarks/geth-compare` (a separate
module; the external libraries are test oracles only).

## Performance

See [`docs/SECP256K1-PERFORMANCE.md`](../docs/SECP256K1-PERFORMANCE.md).
SILA is slower than libsecp256k1 (C), faster than decred (pure Go) for
Verify and Recover, and slower for Sign.

## References

- SEC 1 v2.0 and SEC 2 v2.0 (https://www.secg.org/).
- RFC 6979 (deterministic ECDSA).
- Renes, Costello, Batina, "Complete addition formulas for prime order
  elliptic curves", EUROCRYPT 2016.
- Project Wycheproof test vectors (Apache-2.0), see `testdata/wycheproof/`.
