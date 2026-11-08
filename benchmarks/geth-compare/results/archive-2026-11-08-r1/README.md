# Raw benchmark results (2026-11-08)

These files are the unmodified output of `./run.sh asm|noavx|purego` and of
`benchstat -format csv`. They were recorded while the module path was still
`github.com/sila-chain/sila-core-primitives`, so the `pkg:` lines show that
path. Only the module path changed afterwards (to
`github.com/sila-network/sila-core-primitives`); the measured code is the same.
The numbers are left exactly as recorded and must not be edited. To update
them, run the benchmarks again.
