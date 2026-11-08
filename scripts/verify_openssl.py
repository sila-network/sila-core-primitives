#!/usr/bin/env python3
"""Cross-check a built SILA Keccak-256 executable against OpenSSL.

Usage: python3 scripts/verify_openssl.py /path/to/sila-keccak256
Uses Python stdlib only. OpenSSL needs a KECCAK-256 digest provider.
"""
import random
import subprocess
import sys


def digest_command(args, data):
    result = subprocess.run(args, input=data, capture_output=True, check=True)
    return result.stdout.decode("ascii").strip()


def main(binary):
    rng = random.Random(20261108)
    lengths = [0, 1, 2, 3, 7, 31, 32, 63, 64, 127, 128,
               135, 136, 137, 138, 139, 270, 271, 272, 273,
               1023, 1024, 1025, 4096, 8192, 65536, 1048576]
    lengths.extend(rng.randrange(0, 32768) for _ in range(150))
    for count, length in enumerate(lengths, 1):
        data = rng.randbytes(length)
        actual = digest_command([binary], data)
        ref = digest_command(["openssl", "dgst", "-keccak-256"], data).split("= ")[-1]
        if actual != ref:
            raise SystemExit(f"FAIL at case {count}, len={length}: {actual} != {ref}")
    print(f"PASS: {len(lengths)} independent OpenSSL comparison cases")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_openssl.py <binary>")
    main(sys.argv[1])
