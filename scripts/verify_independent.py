#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Cross-check a built sila-keccak256 executable against independent oracles.

Usage:
    python3 -I scripts/verify_independent.py ./sila-keccak256 [--quick]

Oracles (every available one is used for every case):
  * pycryptodome  -- `pip install pycryptodome` (Crypto.Hash.keccak, XKCP-based C)
  * openssl       -- OpenSSL >= 3.2 (`openssl dgst -keccak-256`)

At least one oracle must be present, otherwise the script exits with status 2
and says which to install. It never reports PASS without a real comparison.

Case set (907 cases by default, deterministic seed 20261108):
  every length 0..599 (covers the 136-byte rate boundary four times),
  1023, 1024, 1025, 4096, 65536, 1 MiB, 5,000,000 bytes, and 300 random
  lengths below 100,000 bytes.
"""
import random
import shutil
import subprocess
import sys


def run(args, data):
    r = subprocess.run(args, input=data, capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(f"{args[0]} failed: {r.stderr.decode(errors='replace').strip()}")
    return r.stdout.decode("ascii").strip()


def find_oracles():
    oracles = {}
    try:
        from Crypto.Hash import keccak  # type: ignore

        oracles["pycryptodome"] = lambda d: keccak.new(digest_bits=256, data=d).hexdigest()
    except ImportError:
        pass
    if shutil.which("openssl"):
        probe = subprocess.run(["openssl", "dgst", "-keccak-256"], input=b"", capture_output=True)
        if probe.returncode == 0:
            oracles["openssl"] = lambda d: run(["openssl", "dgst", "-keccak-256"], d).split("= ")[-1]
    return oracles


def cases(quick):
    rng = random.Random(20261108)
    lengths = list(range(0, 600)) + [1023, 1024, 1025, 4096, 65536, 1 << 20, 5_000_000]
    lengths += [rng.randrange(0, 100_000) for _ in range(300)]
    if quick:
        lengths = [n for n in lengths if n <= 1100]
    for n in lengths:
        yield n, rng.randbytes(n)


def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: verify_independent.py <sila-keccak256 binary> [--quick]")
    binary, quick = sys.argv[1], "--quick" in sys.argv[2:]
    oracles = find_oracles()
    if not oracles:
        sys.stderr.write(
            "no independent Keccak-256 oracle found: install pycryptodome "
            "(pip install pycryptodome) or OpenSSL >= 3.2\n")
        sys.exit(2)

    # Known-answer sanity check of each oracle before trusting it.
    kat = "eead6dbfc7340a56caedc044696a168870549a6a7f6f56961e84a54bd9970b8a"  # Keccak KAT, Msg=CC
    for name, fn in oracles.items():
        if fn(b"\xcc") != kat:
            raise SystemExit(f"oracle {name} fails the Keccak KAT; it is not Keccak-256")

    count = 0
    for n, data in cases(quick):
        actual = run([binary], data)
        for name, fn in oracles.items():
            want = fn(data)
            if actual != want:
                raise SystemExit(f"FAIL case {count + 1} len={n} vs {name}: {actual} != {want}")
        count += 1
    print(f"PASS: {count} cases, oracles: {', '.join(sorted(oracles))}")


if __name__ == "__main__":
    main()
