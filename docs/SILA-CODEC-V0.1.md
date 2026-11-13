# SILA canonical encoding (`codec`) — v0.1 technical contract

**Status:** development candidate on branch `dev/codec-v0.1`. **Not**
production-approved and not released. Merge and release need the explicit
approval of the owner (Ahmed Ibrahim).

## 1. Why this is the third primitive

| Order | Primitive | Depends on | Needed by |
|---|---|---|---|
| 1 | Keccak-256 (`keccak`, v1.1.0 released) | — | hashing of every protocol object |
| 2 | secp256k1 signatures (`secp256k1`, `txsig`, `account`; PR #3, frozen) | 1 | transaction authorisation |
| **3** | **canonical encoding (`codec`)** | **none** | the bytes that are hashed and signed: transactions, receipts, blocks, Merkle and state commitments, network messages |

The signature contract (`docs/SECP256K1-SIGNATURE-CONTRACT.md` §7,
item 1, on the secp256k1 branch) lists "transaction structure,
serialization and hashed encoding" as the first blocker for protocol
integration. The encoding is the layer below it. It depends on neither
Keccak-256 nor secp256k1, so it can be built, tested and approved while
secp256k1 is frozen. Merkle and state commitments, transactions and
blocks all need it first.

## 2. Format

A value is a byte string or a list of values.

| Value | Encoding |
|---|---|
| single byte 0x00–0x7f | the byte itself |
| string of 0–55 bytes | `0x80 + len`, bytes |
| string of ≥ 56 bytes | `0xb7 + n`, `len` in n big-endian bytes (n = 1..8), bytes |
| list, content 0–55 bytes | `0xc0 + len`, content |
| list, content ≥ 56 bytes | `0xf7 + n`, `len` in n big-endian bytes, content |

List content is the concatenation of the encodings of its items.

The format is the public recursive length-prefix format already used by
the account-based networks that SILA's address and signature layers are
compatible with. Using it keeps the encodings interoperable and comparable
with an established oracle, and adds no new design risk. The SILA code is
an independent implementation of this public format; no third-party code
is used.

## 3. Canonical rules (decoder contract)

Each value has exactly one encoding. The decoder rejects every other
form:

| # | Rule | Error |
|---|---|---|
| C1 | a single byte < 0x80 must be written as itself, not as `0x81 b` | `ErrNonCanonicalSize` |
| C2 | a length < 56 must use the short form | `ErrNonCanonicalSize` |
| C3 | a long-form length has no leading zero byte | `ErrNonCanonicalSize` |
| C4 | a value must not extend past its input, or past the list that contains it | `ErrUnexpectedEnd` |
| C5 | where exactly one value is expected (`Validate`, `Builder.Raw`), nothing may follow it | `ErrTrailingData` |
| I1 | an integer has no leading zero byte; zero is the empty string `0x80` (the byte `0x00` is not an integer encoding) | `ErrNonCanonicalInteger` |
| I2 | an integer fits the requested width (64 or 256 bits) | `ErrIntegerTooLarge` |
| K | a list where a string is required, or the reverse | `ErrExpectedString`, `ErrExpectedList` |

Sizes are compared as unsigned 64-bit values before any conversion to
`int`, so a declared size above the input (up to 2^64 − 1) is rejected on
32- and 64-bit platforms without overflow.

## 4. Interface

```go
// Encoding (append-style; no allocation when dst has capacity)
func AppendString(dst, s []byte) []byte
func AppendUint64(dst []byte, v uint64) []byte
func AppendUint256(dst []byte, v *[32]byte) []byte   // big-endian
func AppendListHeader(dst []byte, contentSize int) []byte
func StringSize(n int, first byte) int
func ListSize(contentSize int) int

// Nested lists of unknown size (linear time for any depth)
type Builder struct{ ... }
func (b *Builder) String(s []byte)
func (b *Builder) Uint64(v uint64)
func (b *Builder) Uint256(v *[32]byte)
func (b *Builder) Raw(enc []byte) error   // one complete canonical value
func (b *Builder) StartList()
func (b *Builder) EndList()               // panics without StartList
func (b *Builder) Len() int
func (b *Builder) AppendTo(dst []byte) ([]byte, error) // ErrOpenList
func (b *Builder) Bytes() ([]byte, error)              // ErrOpenList
func (b *Builder) Reset()

// Decoding (strict; returns sub-slices of the input, no copy, no allocation)
func Split(b []byte) (k Kind, content, rest []byte, err error)
func SplitString(b []byte) (s, rest []byte, err error)
func SplitList(b []byte) (content, rest []byte, err error)
func SplitUint64(b []byte) (uint64, []byte, error)
func SplitUint256(b []byte) ([32]byte, []byte, error)
func Count(content []byte) (int, error)
func Validate(b []byte) error   // exactly one value, all nested items canonical
```

Behaviour at the edges:

- On error, the `Split*` functions return the unchanged input as `rest`.
- `Split` checks the header of the first value only; items are checked
  when they are read, or all at once by `Validate`.
- `Validate` does not recurse. Nesting depth is limited only by the input
  size, and it allocates nothing up to 32 nested lists.
- The decoder returns sub-slices of the input. A caller that keeps a
  decoded value after changing the input must copy it.

**Out of scope.** The package does not:
- map Go types by reflection;
- define signed integers, booleans or any other typed value;
- define the layout of any SILA protocol object (transaction fields,
  typed-transaction envelopes, block headers);
- define domain separation for hashing.

Those layouts and domain separation are SILA protocol specifications
built on this format (§7).

## 5. Verification evidence

| Area | Test | Result |
|---|---|---|
| Format examples and size boundaries (55/56, 255/256, list content 55/56) | `TestVectors` | all identical; checked against an independent in-test recursive encoder, the Builder, `AppendString`, `StringSize`, `Validate` and the strict decoder |
| Integers: uint64 and uint256 boundaries; rejects for `0x00`, leading zero, 65 bits, 264 bits, list, truncated | `TestIntegers` | pass |
| 33 malformed encodings (each rule C1–C5) | `TestRejects` | expected error each; also rejected by the test model |
| Canonical bijection: every 1- and 2-byte input, and 3-byte inputs with a boundary last byte | `TestExhaustiveShortInputs` | `Validate` accepts exactly the inputs equal to the re-encoding of their lenient decoding |
| Random values (3000, nesting 5, sizes around every boundary up to 65541 B) | `TestRandomRoundTrip` | Builder = reference encoder; decode returns the value; `Raw`, `AppendListHeader`, `ListSize` |
| Builder misuse | `TestBuilderMisuse` | `ErrOpenList`; panic on unmatched `EndList` and negative size; a failed `Raw` adds nothing |
| 200 000 nested lists | `TestDeepNesting` | encoded and validated without recursion; corruption found at the bottom |
| Declared sizes up to 2^64 − 1 | `TestLargeSizes` | `ErrUnexpectedEnd` on 386 and amd64 |
| Allocations | `TestNoAllocations` | 0 for decoding, `Validate`, append encoding and a reused Builder |
| Fuzz: decoder model, integers, Builder programs | `FuzzValidate`, `FuzzIntegers`, `FuzzBuilder` | 60 s each locally; 20 s each in CI |
| Production code imports only the standard library, carries the SILA header, names no external project; the module has no requirements | `TestIndependentProductionCode` | pass |
| Statement coverage | `go test -cover ./codec` | 100.0 % |

**Differential tests against an independent oracle** (go-ethereum v1.17.10
`rlp`, test-only, in the separate module `benchmarks/geth-compare`):

| Test | Result |
|---|---|
| `TestCodecEncodingMatchesGeth` | 5000 random nested values, 20 009 uint64 and 20 000 uint256 values: identical bytes |
| `TestCodecDecodingVerdictsMatchGeth` | 17 040 437 inputs, every input of 1–3 bytes plus 200 000 mutated encodings: identical accept/reject verdicts for `Validate`, `Split`, `SplitUint64` and `Count`; 172 811 accepted by both |
| `TestCodecTxShapeMatchesGeth` | a nine-field transaction-shaped list: identical bytes with the oracle's low-level and reflection encoders |
| `FuzzCodecAgainstGeth` | 90 s locally, 30 s in CI: no difference |

**Platforms (CI):**
- Go 1.23 and 1.25 on amd64 and arm64, with `-race` and `-tags purego`.
- 386 native.
- s390x (big-endian), ppc64le and riscv64 under QEMU.
- loong64: build only.

## 6. Performance

Indicative only: a shared 4-vCPU Xeon VM, Go 1.24.7, `benchstat`, n = 6.
CI records the same benchmarks on GitHub runners (Benchmarks workflow).

| Operation | SILA | go-ethereum v1.17.10 | Allocations (SILA / oracle) |
|---|---|---|---|
| Encode a transaction-shaped list (reused buffer) | 61.6 ns | 84.9 ns (`EncoderBuffer`); 233 ns (reflection) | 0 / 0; 1 |
| Decode the same list field by field | 61.1 ns | 74.8 ns (`Split*`); 571 ns (reflection) | 0 / 0; 7 |
| Validate a list of 1000 × 32 B | 4.34 µs | 7.94 µs | 0 / 0 |
| Validate 44 799 B of nested lists of short strings | 31.1 µs | 56.4 µs | 0 / 0 |

## 7. Not defined here (protocol decisions)

Each item is required before node integration, but none blocks releasing
the primitive:

1. The SILA transaction layout, its typed-envelope scheme (if any) and
   the exact bytes that are hashed for signing. This is §7 item 1 of the
   signature contract.
2. Domain separation between message types and networks.
3. The block header, receipt and state-commitment layouts.

## 8. Security review

| # | Risk | Treatment |
|---|---|---|
| E-1 | Several encodings of one value (signature or hash malleability) | rules C1–C5 and I1 make the encoding unique; proven by the exhaustive bijection test, the fuzz model and oracle verdicts |
| E-2 | Size overflow or wrap on 32-bit platforms | sizes compared as uint64 before conversion; `TestLargeSizes` on 386 |
| E-3 | Stack exhaustion from deeply nested input | `Validate` is iterative; 200 000 levels tested |
| E-4 | Memory amplification from declared sizes | no allocation proportional to a declared size; the decoder only slices its input |
| E-5 | Child value crossing its parent list's end | items are split within the parent's content only (C4); exhaustive and oracle tests |
| E-6 | Quadratic encoding for deep nesting | headers are written once at output; linear time |
| E-7 | Aliasing: decoded values share the input buffer | documented in the package and in §4 |
| E-8 | Timing: decoding time depends on the input | expected and acceptable: the encoding handles public data (transactions, blocks). Callers must not encode secrets with it in a context where the timing would leak them |

The independent AI review of this branch (Codex) is recorded in the pull
request. AI review is not a human audit or a certification.

## 9. Release gates

1. CI green on all platforms, plus CodeQL and Benchmarks.
2. Codex review with every confirmed finding fixed.
3. The owner's explicit approval to merge and to tag a release.
