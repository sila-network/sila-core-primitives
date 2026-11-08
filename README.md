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

Intel Xeon (family 6, model 173), Linux VM, Go 1.25.4, `GOAMD64=v1`,
single core pinned, 10 runs per case, `benchstat` medians. The full tables,
confidence intervals and p-values are in `docs/PERFORMANCE-2026-11-08.md`.

| Comparison | Throughput, 1 MiB | geomean speed-up (all 22 cases) |
|---|---|---|
| SILA V1 (original) | 43.8 MB/s | — |
| SILA AVX-512 vs go-ethereum amd64 asm | 632.7 vs 485.5 MB/s | **SILA 26.5% faster** |
| SILA portable Go vs go-ethereum amd64 asm | 530.7 vs 482.1 MB/s | SILA 9.7% faster (2 of 22 cases not significant) |
| SILA portable Go vs go-ethereum portable Go | 526.0 vs 444.7 MB/s | SILA 19.2% faster |

These numbers come from **one machine**. They have to be confirmed on the
target production CPUs before anyone states them as a general result.

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
- Copyright: see `NOTICE`. The copyright holder is the legal entity that owns
  SILA. **Its registered legal name has not been confirmed yet**, and the
  `[SILA LEGAL ENTITY — NAME TO BE CONFIRMED]` placeholder must be replaced
  before any release.
- Trademarks: the code license does not cover the SILA name or logo; see
  `TRADEMARKS.md`.
- Contributing: `CONTRIBUTING.md`. Security reports: `SECURITY.md`.

## Approval gate

Do not classify this component as production-ready until an independent
security audit, review on the target CPUs, production workload benchmarks
and final network specification approval are complete.
