# SILA secp256k1 signature contract (proposed)

Status: **proposed engineering default, pending protocol approval by the
project owner (Ahmed Ibrahim).** The implementation in `secp256k1/` follows
this contract today. Items marked **OPEN** are protocol decisions that the
code does not settle; they must be decided before any production release.

## 1. Curve and parameters

secp256k1 as specified in SEC 2 v2.0, §2.4.1 (field prime p, order n,
generator G, a = 0, b = 7, cofactor 1).

## 2. What is signed

- The signing and verification functions take a **32-byte digest** chosen
  by the caller. They do not hash.
- The digest is interpreted as a big-endian integer and reduced mod n.
  Digests ≥ n are allowed; they have the same meaning as `digest mod n`.
- **OPEN (protocol):** the exact SILA transaction/message encoding that is
  hashed, the hash function (expected: SILA Keccak-256 v1.1.0), and domain
  separation between message types and networks (for example a chain or
  network identifier inside the hashed encoding).

## 3. Signing

- Deterministic nonces per **RFC 6979** (§3.2) with HMAC-SHA-256. Because
  qlen = hlen = 256, bits2int is the identity and
  `bits2octets(h) = int(h) mod n`. No additional entropy is mixed in.
- The result is always **low-S**: s ≤ (n−1)/2. When the raw s is high, the
  signer uses n − s and flips bit 0 of the recovery identifier.
- Interoperability, measured: for every digest, the SILA signature
  (r, s, v) is byte-identical to libsecp256k1's RFC 6979 signature (via
  go-ethereum v1.17.10). decred dcrd secp256k1 v4.0.1 produces the same
  bytes for digests < n; for digests ≥ n it feeds the unreduced digest to
  the nonce generator, so its nonce differs, but each implementation's
  signatures still verify under the others.
- **OPEN (protocol/security):** whether SILA wants "hedged" signatures
  (RFC 6979 plus extra randomness, which protects against fault attacks)
  at the cost of losing byte-for-byte determinism.

## 4. Encodings

| Name | Size | Layout |
|---|---|---|
| Compact | 64 bytes | r (32, big-endian) ‖ s (32, big-endian) |
| Recoverable | 65 bytes | r ‖ s ‖ v, with v ∈ {0, 1, 2, 3} |

- v is the raw recovery identifier: bit 0 = parity of R.y, bit 1 = 1 if
  R.x ≥ n (so r = R.x − n). No "+27" or network offset is applied.
- **OPEN (protocol):** whether SILA transactions use the 64- or 65-byte
  form; whether v = 2 or 3 (probability about 2⁻¹²⁷ per signature) is
  accepted at the transaction level or rejected as non-standard; whether
  any network identifier is folded into v (this implementation folds
  nothing).

## 5. Validity rules (enforced by `ParseSignature`, `Verify` and `RecoverPublicKey`)

1. Exact length (64 or 65 bytes); in the 65-byte form, v ≤ 3.
2. 1 ≤ r < n and 1 ≤ s ≤ (n−1)/2. High-S signatures are rejected even
   though they are valid textbook ECDSA. This removes signature
   malleability.
3. Public keys: SEC 1 compressed (33 bytes, prefix 02/03) or uncompressed
   (65 bytes, prefix 04); coordinates < p; the point must satisfy the curve
   equation; the point at infinity and hybrid prefixes (06/07) are
   rejected.
4. Recovery: for v ≥ 2, R.x = r + n must be < p; R must be a curve point;
   the recovered key must not be the point at infinity.

**OPEN (protocol):** the canonical public-key form inside SILA (compressed
or uncompressed), and any address derived from a key (for example a hash of
the key). The library exposes both encodings and defines no address.

## 6. Keys

- Private key: exactly 32 bytes, big-endian, 1 ≤ d ≤ n − 1. Anything else is
  rejected.
- Generation: rejection sampling from `crypto/rand` (or a caller-supplied
  reader).
- **OPEN (product):** key storage, backup, hardware-wallet or HSM
  integration and key-derivation schemes (for example hierarchical
  derivation) are out of scope for this primitive.
