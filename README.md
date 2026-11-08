# SILA Core Primitives — Keccak-256 (V1.1)

**Status:** Independent implementation, output-identical to Ethereum's
Keccak-256. **Not yet independently security-audited or approved for
production.**

This is the first component of the SILA network core. It provides the legacy
Keccak-256 digest (original 0x01 padding, as used by Ethereum) for
protocol-compatible hashing. It does **not** implement a blockchain, signature
scheme, Merkle tree, encoding format or consensus.

## Package and commands

- `keccak.Sum256(data []byte) [32]byte` — one-shot, zero allocations.
- `keccak.New() hash.Hash` — incremental hashing via `Write`, `Sum`, `Reset`.
- `cmd/sila-keccak256` — digest of stdin, printed as hex.
- `scripts/verify_independent.py` — 907-case cross-check against independent
  oracles (PyCryptodome and/or OpenSSL ≥ 3.2).
- `benchmarks/geth-compare` — separate Go module benchmarking SILA against
  go-ethereum v1.17.10 on the same machine.

## Implementation

| Path | When used | Kernel |
|---|---|---|
| AVX-512 | amd64 CPU+OS with AVX-512F and AVX-512VL (checked with CPUID/XGETBV at start-up) | `keccakf_avx512_amd64.s`: each of the 25 lanes lives in its own XMM register for all 24 rounds; π is register renaming done by the generator; θ and χ are one `VPTERNLOGQ` per lane; ρ is one `VPROLQ` per lane; whole blocks are absorbed without leaving registers |
| Portable Go | every other CPU/architecture, or `-tags purego` | `keccakf_generic.go`: fully unrolled two-round body, lanes addressed in place, lane complementing (one NOT per plane instead of five) |

Both kernels are **generated** by `internal/gen` (`go generate ./keccak`)
from the Keccak specification: the ρ offsets and round constants are
recomputed from their defining formulas (walk `(x,y)→(y,2x+3y)`, LFSR
`x^8+x^6+x^5+x^4+1`), and every χ expression under lane complementing is
picked by an exhaustive truth-table search. A test fails if a generated file
is stale.

## Build and test

Requires Go 1.23 or newer. The module has **no third-party dependencies**.

```sh
go test ./...
go test -race ./...
go test -tags purego ./...          # portable kernel only
go vet ./...
go test -run '^$' -fuzz FuzzSum256 -fuzztime 60s ./keccak
go build -o sila-keccak256 ./cmd/sila-keccak256
python3 -I scripts/verify_independent.py ./sila-keccak256

# Head-to-head benchmark against go-ethereum (needs Go 1.25+ and network
# access to the Go module proxy):
cd benchmarks/geth-compare && ./run.sh asm && ./run.sh noavx && ./run.sh purego
```

## Measured performance (summary)

SILA vs go-ethereum v1.17.10, same machine, same process, Go 1.25.4,
`GOAMD64=v1`, 10 interleaved runs per case, `benchstat` (Mann-Whitney,
p<0.05). The value is geth time / SILA time, geometric mean over 22 cases
(32 B to 1 MiB, one-shot and streaming); above 1.00× means SILA is faster.
Full tables, raw data and the list of unmeasured platforms:
`docs/PERFORMANCE-2026-11-08.md`.

| CPU (where) | SILA default vs geth default | Cases significant | SILA portable vs geth asm |
|---|---|---|---|
| Intel Xeon, model 173 (reference VM) | **1.26×** (AVX-512) | 22/22 | 1.09× (19/22) |
| Intel Xeon 6973P-C (GitHub) | **1.25×** (AVX-512) | 22/22 | 1.09× (21/22) |
| AMD EPYC 9V74, Zen 4 (GitHub) | **1.27×** (AVX-512) | 22/22 | 1.10× (22/22) |
| Arm Neoverse-N2, Linux arm64 (GitHub, 2 images) | **1.11×** | 22/22 | — |
| Apple M1, virtual, macOS (GitHub) | 1.20× (indicative, very noisy) | 18/22 | — |

SILA allocates nothing (0 allocs/op, 0 B/op) in every case; geth's
`Keccak256Hash` allocates once per call. SILA V1 (original) reached
43.8 MB/s at 1 MiB on the reference VM; V1.1 reaches about 616 MB/s.

Not measured: amd64 CPUs that really lack AVX-512 (simulated by forcing the
portable kernel), Graviton/Ampere, Apple Silicon on bare metal, and any
non-amd64/arm64 architecture (correctness only, under QEMU).

## Technical contract

- Function: Keccak-256 (original padding, **not** NIST SHA3-256).
- Permutation: Keccak-f[1600], 24 rounds.
- Rate: 136 bytes; capacity: 512 bits; digest length: 32 bytes.
- Lanes: 25 × 64-bit little-endian.
- Domain suffix byte `0x01`; final padding marker `0x80`.
- Streaming and one-shot results are identical; `Sum` does not change state.

## Integration boundary

This package hashes bytes only. Consumers must supply an agreed encoding
format and domain-separated message layout; it **must not** hash ambiguous
protocol objects without an explicit serialization specification.

## Originality and third-party material

SILA Core Primitives is an original, independent SILA project. No code from
go-ethereum, golang.org/x/crypto, XKCP or any other implementation was
copied. The algorithm is a public specification; the test vectors are
published known answers; lane complementing is a published technique
(Bertoni et al., *Keccak implementation overview*, §2.2).

The separate module `benchmarks/geth-compare` **depends on** go-ethereum
v1.17.10 (LGPL-3.0) only to compare results and speed. go-ethereum is
fetched by the Go toolchain at build time and is not part of this repository.
CI installs PyCryptodome as a test oracle; it is not distributed either.
See `docs/SECURITY-REVIEW-2026-11-08.md` §7.

## License, copyright and trademarks

- Code: **Apache License 2.0**, full text in `LICENSE`. Source files carry
  `SPDX-License-Identifier: Apache-2.0`.
- Copyright: `Copyright 2026 Ahmed Ibrahim` (see `NOTICE`). Ahmed Ibrahim
  is the personal owner of the rights in the project's original code.
  "SILA Network" is the name of the technical organization that hosts the
  project, not the copyright holder.
- Contributions by other people remain the copyright of their authors and
  are licensed under Apache-2.0 (Section 5 of the license); see
  `CONTRIBUTING.md`.
- Trademarks: the code license does not cover the SILA name or logo; see
  `TRADEMARKS.md`.
- Contributing: `CONTRIBUTING.md`. Security reports: `SECURITY.md`.

## Security and approval gates

For **development and review**, require passing CI (Go test, race, fuzzing,
Keccak known-answer vectors, cross-implementation equivalence and architecture
checks), GitHub CodeQL analysis, investigation of any security alerts, and
explicit approval by the project owner. Additional SILA development may
proceed without waiting for a human auditor; merge is never automatic.

For **production**, use the separate security criteria in `SECURITY.md`:
threat-model and integration review, supported-platform validation, a
confidential vulnerability-reporting channel, resolution of critical findings,
and explicit owner acceptance of residual risk. External specialist auditing
is strongly recommended for cryptographic code securing real assets.
Passing automated checks does not guarantee security or establish production
readiness. This component remains **not approved for production**.
