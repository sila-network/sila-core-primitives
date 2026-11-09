# SILA Core Primitives — secp256k1

Development stage: **public-key codec and validation only**. Not a release.

This package implements strict SEC 1 compressed (33-byte) and uncompressed
(65-byte) public-key parsing, checking field ranges, the secp256k1 curve
equation and quadratic residuosity. It uses Go's standard-library `math/big`
only on **public** values; it is intentionally NOT constant-time.

It contains no private-key generation, private-scalar multiplication,
ECDSA signing, signature recovery or production key-management operations.
Do not use this initial development package for secret or signing operations.

Reference specification: [SEC 2, version 2.0, §2.4.1](https://www.secg.org/sec2-v2.pdf).
The field modulus, generator and group parameters are defined by that open
specification. The code here is an independent SILA implementation.

Target for the complete second core primitive:
- Constant-time scalar arithmetic and secret-scalar multiplication;
- ECDSA signature verification and strict signature encoding;
- Secure deterministic ECDSA signing and optional public-key recovery;
- Explicit accepted-v normalization rules in the SILA protocol specification;
- Differential and fuzz tests, multi-architecture execution and security reviews;
- Controlled release after all checks pass and Ahmed Ibrahim approves.
