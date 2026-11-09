# SILA secp256k1 — functional parity matrix

This file records how the behaviour of the SILA packages `secp256k1`,
`txsig` and `account` was compared with independent reference
implementations. The references are used **only as test oracles** in the
separate module `benchmarks/geth-compare` (its own `go.mod`). The SILA
module has no third-party dependencies, contains no code from the
references, and works offline: it does not connect to, or depend on, any
blockchain network. `TestIndependentProductionCode` enforces this for the
production files (standard-library and SILA imports only, no external
project names, no requirements in `go.mod`).

References:

| Name in this file | What it is | Version |
|---|---|---|
| geth | go-ethereum `crypto` and `core/types` (C libsecp256k1 through cgo) | v1.17.10 |
| libsecp256k1 | the C library bundled with geth | as bundled in v1.17.10 |
| decred | `github.com/decred/dcrd/dcrec/secp256k1/v4` (pure Go) | v4.0.1 |
| Wycheproof | C2SP Project Wycheproof ECDSA secp256k1 vectors (Apache-2.0) | see `secp256k1/testdata/wycheproof/README.md` |
| ERC-2098 | published test vectors of the 64-byte compact form (CC0) | final |

Specifications used for the rule definitions (for comparison only):
SEC 1 v2.0 and SEC 2 v2.0; RFC 6979; EIP-2 (low-S for transactions);
EIP-155 (chain-bound recovery value); ERC-2098 (64-byte compact form with
y-parity).

## Matrix

"Identical" means equal bytes for outputs and equal accept/reject
decisions for inputs, on every case of the test.

| # | Case | SILA interface | Reference | Test (module) | Result |
|---|---|---|---|---|---|
| 1 | Private-key validation: 32 bytes, 1 ≤ d < n; edge values 0, 1, n−1, n, n+1, 2^256−1; wrong lengths | `secp256k1.ParsePrivateKey` | geth `crypto.ToECDSA` | `TestParityPrivateKeyValidation` (geth-compare) | 2012 inputs identical |
| 2 | Public-key derivation, uncompressed and compressed encodings | `PrivateKey.PublicKey`, `PublicKey.Uncompressed`, `.Compressed` | geth `FromECDSAPub`, `CompressPubkey` | `TestParityPublicKeys` | 500 keys identical |
| 3 | Public-key parsing: valid, prefixes 00–07, flipped bits, x or y + p, random x, infinity | `secp256k1.ParsePublicKey` | geth `UnmarshalPubkey` (65 B), `DecompressPubkey` (33 B, libsecp256k1) | `TestParityPublicKeys` | 10003 inputs identical, same decoded points |
| 4 | Public-key parsing, broader corpus | `ParsePublicKey` | decred `ParsePubKey` | `TestSecp256k1PublicKeyParsingMatchesDecred` | 4000 identical |
| 5 | Deterministic signing (RFC 6979, low-S, recovery id), random keys and digests | `secp256k1.Sign` | libsecp256k1 (`crypto.Sign`), decred `SignCompact` | `TestSecp256k1SignaturesMatchLibsecp256k1AndDecred` | 1000/1000 byte-identical (r, s, v) |
| 6 | Signing with digest ≥ n | `Sign` | libsecp256k1 | `TestSecp256k1DigestAboveOrder` | 50/50 identical; decred differs by design (unreduced digest), all cross-verify |
| 7 | Published deterministic vectors | `Sign`, `txsig.LegacyV` | ERC-2098 vectors (2) | `TestCompactYParityVectors` (txsig) | r, s, v identical |
| 8 | Strict verification: valid, 512 bit flips, high-S, random, wrong digest | `secp256k1.Verify` | libsecp256k1 (`VerifySignature`) | `TestSecp256k1VerifyVerdictsMatchLibsecp256k1` | 2000/2000 identical |
| 9 | Verification vectors | `Verify`, strict DER test parser | Wycheproof "bitcoin" (low-S) | `TestWycheproof*` (secp256k1) | 464/464 identical |
| 10 | Verification vectors, generic ECDSA | `Verify` | Wycheproof "p1363" | `TestWycheproof*` | 252/252, except 72 valid high-S that SILA rejects by contract (strict context) |
| 11 | Raw public-key recovery (ecrecover-style): valid, high-S, v = 0..5, small r for v = 2/3, boundary r/s, random | `ParseRecoverableSignatureAllowHighS` + `RecoverPublicKey` | geth `crypto.Ecrecover` (libsecp256k1) | `TestParityRawRecovery` | 5400 inputs identical: 1923 recovered (328 with v = 2/3), rest rejected by both |
| 12 | Value rules for (r, s, v) in the transaction (EIP-2) and recovery-compatible contexts | `txsig.ParseValues` (`Strict`, `RecoveryCompatible`) | geth `ValidateSignatureValues(homestead = true / false)` | `TestParityValidateSignatureValues` | 62208 combinations identical |
| 13 | Legacy recovery value 27/28, end to end | `txsig.LegacyV`, `FromLegacyV`, `Recover` | geth `HomesteadSigner` (`SignatureValues`, `Sender`) | `TestParityTransactionRecoveryValues` | 200 transactions identical V and sender; high-S rejected by both |
| 14 | Chain-bound recovery value v + 35 + 2·chainID, end to end | `txsig.ChainV`, `FromChainV`, `Recover` | geth `EIP155Signer` | `TestParityTransactionRecoveryValues` | 200 transactions (random chain IDs) identical V and sender; high-S rejected by both |
| 15 | High-S in the recovery-compatible context | `txsig.Recover(…, RecoveryCompatible)` | geth `Ecrecover` | `TestParityTransactionRecoveryValues` | identical keys |
| 16 | 64-byte compact form with y-parity, distinct from r ‖ s | `txsig.CompactYParity`, `ParseCompactYParity` | ERC-2098 vectors and definition | `TestCompactYParityVectors`, `TestCompactFormsAreDistinct`, `TestCompactYParityRejects`, `FuzzParseCompactYParity` | vectors identical; v = 1 bytes rejected by the generic strict parser |
| 17 | Account address = last 20 bytes of Keccak-256(X ‖ Y) | `account.FromPublicKey` (SILA Keccak-256) | geth `PubkeyToAddress` | `TestParityAddress` | 1000/1000 identical |
| 18 | Additional-data (hedged) nonces, RFC 6979 §3.6 | `SignWithExtraEntropy` | decred `NonceRFC6979(extra)`; an independent `crypto/hmac` reference | `TestParityHedgedNonce`, `TestSignWithExtraEntropy` | 300 + 30 identical nonces |

## Deliberate, documented differences

| Behaviour | SILA | Reference | Reason |
|---|---|---|---|
| `Verify` on a high-S signature | rejects | libsecp256k1 rejects; generic ECDSA (Wycheproof p1363) accepts | strict (non-malleable) context; callers that accept high-S can use `Normalize` first |
| v = 2 or 3 | accepted only by the generic `secp256k1` recovery | geth `Ecrecover` accepts; `ValidateSignatureValues` rejects | the transaction layer (`txsig`) never accepts 2/3 |
| Digest ≥ n in signing | `digest mod n` in RFC 6979 (same as libsecp256k1) | decred uses the unreduced digest | follows RFC 6979 bits2octets |

## Not covered by this library (protocol decisions)

The SILA transaction encoding, chain identifier, domain separators,
typed-transaction scheme and textual address format are not defined by the
project yet. The library does not invent them: `txsig.ChainV` takes the
chain identifier as a parameter, `account` returns 20 raw bytes, and every
signing function takes a 32-byte digest chosen by the caller.
