# SILA Keccak-256 V1 — Verification record

Date: 2026-11-08

- Platform: linux/amd64
- Compiler: Go 1.23.2
- Independent comparison: OpenSSL 3.5.5 KECCAK-256
- Unit tests (`go test ./...`): PASS
- Race instrumentation (`go test -race ./...`): PASS
- Static checks (`go vet ./...`): PASS
- Keccak package statement coverage: **100.0%**
- Independent OpenSSL cross-check: **177/177** distinct generated input cases, spanning 0 to 1,048,576 bytes, including absorption-rate boundaries.
- Included tests: public test vectors, chunked/streaming equivalence, state reset, nondestructive `Sum`, hash interface sizes, explicit distinction from NIST SHA3-256.

## Indicative benchmark (single run, not Ethereum comparison)

| Input size | Nanoseconds/op | MB/s | Allocation/op |
|---|---:|---:|---:|
| 32 bytes | 3591 | 8.91 | 0 |
| 1024 bytes | 27569 | 37.14 | 0 |

These numbers are environment-dependent and must not be treated as proof of superiority. No direct benchmark against the Ethereum client implementation was performed. This is a reference implementation; it is **not** production security-audited or approved for deployment.
