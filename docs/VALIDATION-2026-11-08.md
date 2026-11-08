# SILA Keccak-256 — Verification record

Date: 2026-11-08

## Revision 2 (V1.1: optimized kernels)

- Platform: linux/amd64, Intel Xeon (family 6, model 173), AVX-512F/VL present.
- Compilers: Go 1.25.4 (main runs) and Go 1.23.4 (minimum in `go.mod`); both PASS.
- `go test ./...`, `go test -tags purego ./...`: PASS.
- `go test -race ./...` (default and `purego`): PASS.
- `go vet` and `staticcheck 2025.1.1` (default and `purego`): no findings.
- Coverage: 98.2% (amd64, only the "CPU lacks AVX-512" branches are uncovered), 100.0% (`purego`).
- Fuzzing `FuzzSum256` for 60 s: about 2.76 M executions, no failure.
- Independent oracle: `scripts/verify_independent.py`, **907/907** cases against
  PyCryptodome 4.4.0 (XKCP-based C) for both the AVX-512 binary and the `-tags purego`
  binary. The 907 cases are every length 0–599, 1023/1024/1025/4096/65536 bytes,
  1 MiB, 5,000,000 bytes, and 300 random lengths below 100,000 bytes.
  OpenSSL here is 3.0.13, which has no KECCAK-256, so that oracle was skipped
  automatically.
- go-ethereum v1.17.10 equivalence: every length 0–2048, plus 2,000 random
  messages up to 70 KB with random streaming chunking.
- Known answers: Keccak team KAT (Msg=0xCC), the original V1 vectors,
  "a"×10^6, and boundary lengths 135/136/137/271/272/273/1000.
- Kernel equivalence: AVX-512, portable Go and the original V1 loop agree on
  20,000 random states, plus the all-zero and all-one states. Multi-block
  absorb agrees with the generic loop on 5,000 random cases.
- Memory safety: no read past the end of the input or before its start
  (guard-page test, all lengths 0–1632).

Performance: see `PERFORMANCE-2026-11-08.md`.

## Revision 1 (V1 as originally delivered)

- Compiler Go 1.23.2. Comparison against OpenSSL 3.5.5 KECCAK-256: 177/177.
- Coverage 100.0%. Indicative benchmark: 32 B 8.91 MB/s, 1024 B 37.14 MB/s.

This remains a reference implementation. It is **not** independently
security-audited or approved for deployment.
