#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Summarise every results/<dir>/<mode>.{txt,csv} into one Markdown table.

Usage: python3 -I platforms.py results/dir1 results/dir2 ...
Columns: platform, CPU, mode, geomean time ratio, range of per-case
differences, significant cases, 1 MiB throughput (streaming), allocations.
"""
import os
import re
import sys


def header(txt):
    cpu = arch = ""
    for line in open(txt):
        if line.startswith("# cpu:"):
            cpu = line.split(":", 1)[1].strip()
        if line.startswith("# os/arch:"):
            arch = line.split(":", 1)[1].strip()
        if line.startswith("cpu:") and not cpu:
            cpu = line.split(":", 1)[1].strip()
        if line.startswith("goarch:") and not arch:
            arch = line.split(":", 1)[1].strip()
    return cpu, arch


def rows(csv):
    out = []
    for line in open(csv):
        if line.startswith(",B/s") or line.startswith(",B/op"):
            break
        m = re.match(r"(OneShot|Streaming) (\d+),([^,]+),[^,]*,([^,]+),[^,]*,([^,]*),(.*)", line.strip())
        if m:
            out.append((m[1], int(m[2]), float(m[3]), float(m[4]), "~" not in m[5]))
    return out


def geomean(csv):
    for line in open(csv):
        if line.startswith("geomean"):
            f = line.split(",")
            return float(f[3]) / float(f[1])
    return None


def allocs(txt):
    a = {}
    for line in open(txt):
        m = re.match(r"Benchmark\w+/impl=(\w+)/size=\d+\s.*\s(\d+) allocs/op", line)
        if m:
            a.setdefault(m[1], set()).add(int(m[2]))
    return a


print("| Results | CPU | os/arch | Mode | geomean (geth time / SILA time) | Per-case range | Significant | 1 MiB streaming MB/s (SILA vs geth) | allocs/op SILA / geth |")
print("|---|---|---|---|---:|---|---:|---|---|")
for d in sys.argv[1:]:
    for mode in ("asm", "noavx", "purego"):
        txt, csv = os.path.join(d, mode + ".txt"), os.path.join(d, mode + ".csv")
        if not (os.path.exists(txt) and os.path.exists(csv)):
            continue
        cpu, arch = header(txt)
        r = rows(csv)
        sig = [x for x in r if x[4]]
        diffs = [(g / s - 1) * 100 for (_, _, s, g, ok) in sig]
        rng = f"{min(diffs):+.1f}% … {max(diffs):+.1f}%" if diffs else "—"
        mib = [x for x in r if x[0] == "Streaming" and x[1] == 1 << 20]
        mbs = f"{(1 << 20) / mib[0][2] / 1e6:.1f} vs {(1 << 20) / mib[0][3] / 1e6:.1f}" if mib else "—"
        al = allocs(txt)
        alloc = f"{'/'.join(map(str, sorted(al.get('sila', []))))} / {'/'.join(map(str, sorted(al.get('geth', []))))}"
        gm = geomean(csv)
        print(f"| `{os.path.basename(d)}` | {cpu} | {arch} | {mode} | {gm:.3f}× | {rng} | {len(sig)}/{len(r)} | {mbs} | {alloc} |")
