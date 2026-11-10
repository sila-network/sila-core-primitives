# SILA secp256k1 — dedicated-hardware timing procedure (finding S-8)

S-8 is **Mitigated — Not Closed** (`SECP256K1-SECURITY-REVIEW.md` §6). Closing
it needs the measurements below on machines that SILA controls; shared CI
runners are too noisy (their random-vs-random controls reach |t| = 10–120).
This file tells the person running them what to prepare, what to run and how
to read the result.

## 1. Machines

Run on at least these two; more models give stronger evidence.

| Architecture | Requirement | Why |
|---|---|---|
| amd64 | dedicated machine (bare metal, no other tenants); Intel or AMD server/desktop CPU | the amd64 runner showed the raw inversion effect |
| arm64 | dedicated machine **with FEAT_DIT** (Armv8.4+, e.g. Neoverse N2/V2, Ampere One, Apple M-series) | Sign and PublicKey enable DIT on such CPUs (Go ≥ 1.24) |
| arm64 (optional) | a CPU **without** FEAT_DIT (e.g. Neoverse N1 / Ampere Altra) | shows the countermeasures work without DIT |
| x86 with DOIT (optional) | Intel with `IA32_UARCH_MISC_CTL` DOIT enabled by the OS (or the AMD equivalent) | the x86 counterpart of DIT |

Software: Go 1.25.x (the project's CI version), the repository at the commit
being approved, `taskset` (Linux).

## 2. Preparation (Linux)

1. Nothing else running (no desktop session, no other jobs).
2. Reserve a core: boot with `isolcpus=2 nohz_full=2 rcu_nocbs=2` (or pick
   another core and pass it to the script).
3. Run as root, so the script can fix the frequency: `performance`
   governor, turbo/boost off (it prints what it could and could not set).
4. Power: AC power, fixed cooling; note the CPU model and kernel.

On macOS (Apple Silicon): close other applications, connect power; the
script prints `FEAT_DIT` (1 = available).

## 3. Run

```sh
git checkout <commit to approve>
sudo ./scripts/timing_dedicated.sh 1000000 10 2   # samples, runs, CPU
```

About 1–3 hours per machine. Keep the complete output (it starts with the
machine facts: CPU, Go version, FEAT_DIT, governor, turbo, isolated CPUs).

The script measures only the production paths: masked inverse, masked k·G,
Sign and PublicKey. For each, it compares tiny secrets with random ones
(the test) and two random sets (the control), each counterbalanced in class
order, and prints one t value per run:

```
Sign  [production] t [ … 10 values … ]; control t [ … 10 values … ]
```

## 4. Reading the result

Per machine and per path:

| Outcome | Meaning |
|---|---|
| The test does **not** have all 10 values beyond ±4.5 with one sign, **and** the control is within ±4.5 in at least 9 of 10 runs | **pass** for that path on that machine |
| The test has all 10 values beyond ±4.5 with one sign, and the control passes | **fail** — a secret-dependent timing difference; S-8 stays open and the result goes to the developers |
| The control has more than 1 of 10 values beyond ±4.5 | **machine too noisy** — the run does not count; fix the preparation and repeat |
| The test and the control fail together with the same sign | a measurement problem, not a leak; repeat after preparation |

The test command exits non-zero on a **fail**; a noisy control does not make
it fail, so check the control values yourself.

S-8 can be closed when every production path passes on every required
machine (amd64, arm64 with DIT) **and** the independent audit of the
countermeasures (blinding, key and nonce shares, randomness-failure paths;
`secp256k1/blinding.go`, `privatekey.go`, `ecdsa.go`) found no unresolved
issue. Record the outputs and the auditor's report in the security review.

## 5. What this does not cover

Power and electromagnetic analysis (needs lab equipment) and cache-sharing
attacks across tenants are outside wall-clock timing tests; they stay
listed as external items in the security review (§6.3).
