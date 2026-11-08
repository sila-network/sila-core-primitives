// Separate module: the SILA module itself has no dependencies. This module
// exists only to benchmark SILA against go-ethereum on the same machine.
module github.com/sila-network/sila-core-primitives/benchmarks/geth-compare

go 1.25.0

require (
	github.com/ethereum/go-ethereum v1.17.10
	github.com/sila-network/sila-core-primitives v0.0.0
)

require (
	github.com/ProjectZKM/Ziren/crates/go-runtime/zkvm_runtime v0.0.0-20251001021608-1fe7b43fc4d6 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

replace github.com/sila-network/sila-core-primitives => ../..
