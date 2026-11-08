# SILA Core Primitives — Keccak-256 (V1)

**Status:** Independent reference implementation; **not yet security-audited or approved for production**.

This is the first component of the new SILA network core. It provides the
legacy Keccak-256 digest required for protocol-compatible block, transaction,
and address-related hashing operations. It does **not** implement an entire
blockchain, signature scheme, Merkle tree, encoding format, or consensus.

## Package and commands

- `keccak.Sum256(data []byte) [32]byte` — one-shot Keccak-256.
- `keccak.New() hash.Hash` — incremental hashing via `Write`, `Sum`, `Reset`.
- `cmd/sila-keccak256` — command-line digest of stdin.
- `scripts/verify_openssl.py` — independent cross-check for random inputs and rate boundaries.

## Build and test

Requires Go 1.23 or newer. The Go module has **no third-party dependencies**.

```sh
go test ./...
go test -race ./...
go vet ./...
go test -cover ./...
go test -bench=. -benchmem ./keccak
go build -o sila-keccak256 ./cmd/sila-keccak256
python3 scripts/verify_openssl.py ./sila-keccak256
```

## Technical contract

- Function: Keccak-256 (original padding, **not** NIST SHA3-256).
- Permutation: Keccak-f[1600], 24 rounds.
- Rate: 136 bytes; capacity: 512 bits; digest length: 32 bytes.
- Internal lanes: 25 × 64-bit little-endian.
- Domain suffix byte: `0x01`; final padding marker `0x80`.
- Streaming and one-shot operations must produce identical results.

## Integration boundary

This component does not import code from any other SILA module. Consumers will
supply an agreed encoding format and domain-separated message layout. This
package hashes bytes only; it **must not** hash ambiguous protocol objects
without an explicit serialization and domain-separation specification.

## Approval gate

Do not classify this as production-ready until an independent security audit,
explicit interoperability vectors, implementation review, production workload
benchmarks, and final network specification approval are complete.

No source from other blockchain client implementations was copied into this
implementation. The algorithm itself is a public mathematical specification;
this implementation is not a new cryptographic algorithm.

Project distribution license has **not been selected**. Decide that before publication.
