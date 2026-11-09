# SILA secp256k1 signature contract

Status: **engineering contract following the owner's decision of
2026-11-09 (PR #3): functional parity with the reference secp256k1
behaviour first, then measurable improvement.** The implementation in
`secp256k1/`, `txsig/` and `account/` follows this contract. Section 7
lists what is deliberately **not** defined here because the project has
not specified it yet.

Comparison evidence for every rule is in
[`SECP256K1-PARITY.md`](SECP256K1-PARITY.md).

## 1. Curve and parameters

secp256k1 as specified in SEC 2 v2.0, §2.4.1 (field prime p, order n,
generator G, a = 0, b = 7, cofactor 1).

## 2. Keys

- Private key: exactly 32 bytes, big-endian, 1 ≤ d ≤ n − 1; anything else
  is rejected (`ParsePrivateKey`). Generation: rejection sampling from
  `crypto/rand` or a caller-supplied reader (`GeneratePrivateKey`).
- Public key: SEC 1 compressed (33 bytes, prefix 02/03) or uncompressed
  (65 bytes, prefix 04); coordinates < p; the point must satisfy the curve
  equation; the point at infinity and hybrid prefixes (06/07) are rejected
  (`ParsePublicKey`). Both encodings are produced (`Compressed`,
  `Uncompressed`).
- Account address (`account.FromPublicKey`): the last 20 bytes of
  Keccak-256 (SILA implementation) of the 64-byte X ‖ Y, without the 0x04
  prefix.

## 3. What is signed

- Signing, verification and recovery take a **32-byte digest** chosen by
  the caller; they do not hash.
- The digest is a big-endian integer reduced mod n. Digests ≥ n are
  allowed and mean `digest mod n` (also inside RFC 6979).

## 4. Signing

- `Sign`: deterministic nonces per **RFC 6979** (§3.2) with HMAC-SHA-256;
  with qlen = hlen = 256, `bits2octets(h) = int(h) mod n`. This is the
  default and is byte-identical to the reference deterministic signing
  (r, s and recovery identifier).
- The result is always **low-S** (s ≤ (n−1)/2). When the raw s is high,
  the signer uses n − s and flips bit 0 of the recovery identifier.
- `SignWithExtraEntropy` / `SignHedged`: a **separate, explicit** API that
  appends 32 bytes of additional data to the RFC 6979 input (§3.6).
  Hedged signatures verify like any other, but they are **not**
  byte-identical to `Sign`, and must not be presented as such. They are
  never used by default.

## 5. Encodings and recovery identifiers

| Name | Size | Layout | Interface |
|---|---|---|---|
| Generic compact | 64 bytes | r ‖ s | `Signature.Compact`, `ParseSignature` |
| Recoverable | 65 bytes | r ‖ s ‖ v, v ∈ {0, 1, 2, 3} | `Signature.Recoverable`, `ParseRecoverableSignature` |
| Compact with y-parity | 64 bytes | r ‖ (v·2^255 + s), v ∈ {0, 1}, low-S only | `txsig.CompactYParity`, `txsig.ParseCompactYParity` |

- v is the raw recovery identifier: bit 0 = parity of R.y, bit 1 = 1 if
  R.x ≥ n.
- The two 64-byte forms are different formats. They coincide only when
  v = 0; the caller must know which format it holds.
- Transaction-level encodings of v (`txsig`): the legacy form v + 27
  (`LegacyV` / `FromLegacyV`) and the chain-bound form
  v + 35 + 2·chainID (`ChainV` / `FromChainV`); the chain identifier is
  always a parameter, and 0 and values that would overflow 64 bits are
  rejected.

## 6. Validation contexts

| Context | r | s | v | Interfaces |
|---|---|---|---|---|
| Strict (transactions; non-malleable) | 1 ≤ r < n | 1 ≤ s ≤ (n−1)/2 | 0, 1 | `txsig.ParseValues(…, Strict)`, `txsig.Recover(…, Strict)` |
| Recovery-compatible (raw public-key recovery) | 1 ≤ r < n | 1 ≤ s < n | 0, 1 | `txsig.ParseValues(…, RecoveryCompatible)`, `txsig.Recover(…, RecoveryCompatible)` |
| Generic mathematics (library level) | 1 ≤ r < n | strict parsers: low-S; `AllowHighS` parsers: < n | 0..3 | `secp256k1.Parse*`, `RecoverPublicKey` |

- `secp256k1.Verify` always applies the strict rule and rejects high-S
  signatures. `Signature.Normalize` converts a high-S signature to its
  low-S equivalent (flipping v) for callers whose context allows it.
- v = 2 or 3 (R.x ≥ n; probability about 2⁻¹²⁷ per signature) is a valid
  mathematical recovery identifier and is accepted only at the generic
  level. The transaction layer never accepts it.
- Recovery: for v ≥ 2, R.x = r + n must be < p; R must be a curve point;
  the recovered key must not be the point at infinity.

## 7. Not defined here (requires a separate SILA specification)

The library does not invent protocol constants. The following are open
and must be specified by the project before integration:

1. The SILA transaction structure and its hashed encoding (what the 32-byte
   digest is computed from), including any typed-transaction scheme.
2. Domain separation between message types and networks.
3. The SILA chain identifier(s) used with `txsig.ChainV`, and whether the
   legacy (27/28) form is accepted at all.
4. The textual address format (prefix, checksum) on top of the 20-byte
   value from `account`.
5. Key management outside the primitive: storage, backup, hardware
   wallets or HSMs, hierarchical derivation.
