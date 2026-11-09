# Official Keccak known-answer tests (Keccak-256)

Source: the Keccak team's KAT package for the SHA-3 competition,
`KeccakKAT-3.zip` (file dates 2011-01-14), downloaded on 2026-11-08 from
https://keccak.team/obsolete/KeccakKAT-3.zip.
SHA-256 of the zip: `af92d22d23527a0d168a6bbe70b28c840a43bba5bcea828a6d9a5e7ad79378ce`.

These are the original Keccak[r=1088, c=512] vectors with the 0x01 padding
used by Ethereum's Keccak-256, not the later FIPS 202 SHA3-256 vectors.

| File here | Origin | Content |
|---|---|---|
| `ShortMsgKAT_256_bytes.txt` | `ShortMsgKAT_256.txt` (SHA-256 `741862f9…f014851`) | the 256 byte-aligned entries out of 2048 (Len % 8 == 0), copied unchanged |
| `LongMsgKAT_256_bytes.txt` | `LongMsgKAT_256.txt` (SHA-256 `9283c15f…32abe72`) | the 65 byte-aligned entries out of 513, copied unchanged |
| `MonteCarlo_256.txt` | verbatim (SHA-256 `4c928560…9ffdfde`) | 100 checkpoints of the SHA-3 competition Monte Carlo procedure |
| `ExtremelyLongMsgKAT_256.txt` | verbatim (SHA-256 `c0346b68…d770ed`) | a 64-byte text repeated 16,777,216 times (1 GiB) |

Entries whose length is not a whole number of bytes are left out, because
this package (like Ethereum) hashes byte strings only.

The vectors are published test data of the Keccak designers (Bertoni,
Daemen, Peeters, Van Assche). They are reproduced unchanged for
verification only, and their provenance is recorded here.
