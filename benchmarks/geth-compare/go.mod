// Separate module: the SILA module itself has no dependencies. This module
// exists only to benchmark SILA against go-ethereum on the same machine.
module github.com/sila-network/sila-core-primitives/benchmarks/geth-compare

go 1.25.0

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1
	github.com/ethereum/go-ethereum v1.17.10
	github.com/sila-network/sila-core-primitives v0.0.0
)

require (
	github.com/ProjectZKM/Ziren/crates/go-runtime/zkvm_runtime v0.0.0-20251001021608-1fe7b43fc4d6 // indirect
	github.com/bits-and-blooms/bitset v1.20.0 // indirect
	github.com/consensys/gnark-crypto v0.18.1 // indirect
	github.com/crate-crypto/go-eth-kzg v1.5.0 // indirect
	github.com/ethereum/c-kzg-4844/v2 v2.1.8 // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	github.com/supranational/blst v0.3.16 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

replace github.com/sila-network/sila-core-primitives => ../..
