# Contributing to SILA Core Primitives

Thank you for helping. This repository holds security-critical code, so every
change is reviewed.

## Ground rules

1. **Output never changes for speed.** Every change must keep Keccak-256
   byte-identical to the Ethereum variant. Do not remove, skip or weaken a
   failing test to make CI pass.
2. **No dependencies** in the main module. Comparison code that needs other
   projects goes in a separate module under `benchmarks/`.
3. **Generated kernels** (`keccak/keccakf_generic.go`,
   `keccak/keccakf_avx512_amd64.s`) are never edited by hand. Change
   `internal/gen` and run `go generate ./keccak`.
4. **Performance claims** need reproducible measurements: the
   `benchmarks/geth-compare/run.sh` output plus `benchstat`, and the machine
   description.
5. **Only original work or compatible licenses.** Do not copy code from other
   projects unless its license allows it, and keep every notice that license
   requires. Say where any third-party material comes from in the pull
   request.

## Licensing of contributions

The project is licensed under Apache License 2.0. Under Section 5 of that
license, any contribution you intentionally submit is provided under the same
license, unless you state otherwise in writing. Add the line
`// SPDX-License-Identifier: Apache-2.0` at the top of new source files.

## Authorship

Commits must carry the real identity of the human contributor who submits
them. That contributor is responsible for the whole contribution, including
any part produced with software tools. Tools are not listed as authors,
co-authors or copyright holders.

## Before opening a pull request

```sh
gofmt -l .                       # must print nothing
go vet ./... && go vet -tags purego ./...
go test ./... && go test -tags purego ./...
go test -race ./...
(cd keccak && go generate) && git diff --exit-code
python3 -I scripts/verify_independent.py ./sila-keccak256   # pip install pycryptodome
```

CI runs the same checks. Pull requests are merged only with the project
owner's approval.

## Reporting security issues

See `SECURITY.md`. Do not report vulnerabilities in public issues.
