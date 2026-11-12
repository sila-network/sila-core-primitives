# Wycheproof ECDSA secp256k1 test vectors

Source: Project Wycheproof (C2SP), https://github.com/C2SP/wycheproof,
directory `testvectors_v1/`, branch `main`, downloaded on 2026-11-09.
License: Apache License 2.0 (same as this project); the files are copied
unchanged.

| File | SHA-256 | Tests |
|---|---|---|
| `ecdsa_secp256k1_sha256_bitcoin_test.json` | `d3729ce83ff9740c45e74921009a4061eff6c09185b8dd1225ccd06ac57048a4` | 464 (162 valid, 302 invalid); DER signatures, high-S is invalid |
| `ecdsa_secp256k1_sha256_p1363_test.json` | `7a339efc7134fb2495cd32afdbd692e0f86427d3c24e9073f6a7d858bb8788d2` | 252 (167 valid, 85 invalid); raw r‖s, high-S allowed by the vector set |

How SILA uses them (`wycheproof_test.go`): the message is hashed with
SHA-256 and the 32-byte digest is verified with `Verify`.

- The "bitcoin" set matches the SILA contract (low-S only) and every
  verdict must agree exactly.
- The "p1363" set allows high-S. SILA rejects high-S by contract, so a
  vector marked valid is expected to be rejected by SILA exactly when its
  s is greater than (n-1)/2; every other verdict must agree.
