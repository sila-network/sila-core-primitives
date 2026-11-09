#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Turn benchstat CSV (sec/op section) + raw allocs into a Markdown table.
Usage: python3 -I summarize.py results/asm.csv results/asm.txt"""
import re, sys
csv, raw = sys.argv[1], sys.argv[2]
rows = []
for line in open(csv):
    if line.startswith(",B/s") or line.startswith(",B/op"):
        break
    m = re.match(r"(OneShot|Streaming) (\d+),([^,]+),([^,]*),([^,]+),([^,]*),([^,]*),(.*)", line.strip())
    if m:
        rows.append(m.groups())
allocs = {}
for line in open(raw):
    m = re.match(r"Benchmark(\w+)/impl=(\w+)/size=(\d+)\s.*\s(\d+) allocs/op", line)
    if m:
        allocs[(m[1], m[2], m[3])] = m[4]
print("| API | Size (B) | SILA ns/op | geth ns/op | SILA MB/s | geth MB/s | SILA allocs | geth allocs | geth/SILA time | Result | p |")
print("|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---|")
for api, size, s, sci, g, gci, delta, p in rows:
    s, g, n = float(s), float(g), int(size)
    ratio = g / s
    sig = "~" not in delta
    verdict = (f"SILA faster by {(ratio-1)*100:.1f}%" if ratio > 1 else f"SILA slower by {(1-ratio)*100:.1f}%") if sig else "no significant difference"
    print(f"| {api} | {n} | {s*1e9:,.1f} ±{sci} | {g*1e9:,.1f} ±{gci} | {n/s/1e6:,.1f} | {n/g/1e6:,.1f} | "
          f"{allocs.get((api,'sila',size),'?')} | {allocs.get((api,'geth',size),'?')} | {ratio:.3f}x | {verdict} | {p.split()[0]} |")
