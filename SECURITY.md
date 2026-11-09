# Security Policy

## Status

SILA Core Primitives has **not** been independently security-audited and is
**not approved for production use**. The internal review is in
`docs/SECURITY-REVIEW-2026-11-08.md`.

## Security gates for development and production

We use separate acceptance gates so that security work does not prevent
development of other SILA components.

**Development / PR acceptance (not production approval):**
- All required GitHub Actions CI jobs must pass on the exact proposed commit:
  Go tests, race detection, architecture checks, known-answer vectors,
  independent oracle comparisons, differential equivalence and fuzzing.
- GitHub CodeQL security analysis for Go, Python and Actions must complete.
  Any findings must be reviewed; unresolved high/critical security findings
  block acceptance. A successful workflow alone does not prove zero alerts.
- Relevant review feedback must be addressed and the project owner must
  explicitly approve a merge. No automatic merging.
- Independent human auditing is **not a prerequisite for continuing
  development** or for merging a version explicitly marked non-production.

**Production adoption (separate decision):**
- Establish the consuming protocol's serialization, threat model, security
  requirements, supported CPU/OS targets, and safe deployment boundaries.
- Verify Keccak vectors and equivalence on each supported build and platform,
  review the generated assembly and CPU dispatch, and investigate all open
  high/critical findings.
- Obtain independent security evidence beyond the implementation team's own
  claims. External expert auditing is strongly recommended, especially before
  securing real assets; automated analysis alone is not a proof of safety.
- Enable a confidential vulnerability reporting route, document outstanding
  limitations and residual risks, and obtain an explicit production release
  decision from the owner. Do not claim "100% secure."

The GitHub CodeQL workflow is in `.github/workflows/codeql.yml`; its results
are security signals, not a formal proof of cryptographic or assembly
correctness. Current code must remain labeled **not approved for production**
until the separate production gates are satisfied.

## SILA production release candidate checklist

The target is **use as the Keccak-256 primitive inside the real SILA network**,
not merely a demonstration. This is a release checklist, not a claim that
cryptographic software can be proven free of bugs.

| Gate | Required evidence | Current status |
|---|---|---|
| Algorithm correctness | Official Keccak known-answer vectors, independent oracle, differential tests with go-ethereum, streaming/chunking tests | Verified in CI for PR #1; re-check on release commit |
| CPU safety and portability | Tests for AVX-512 selection/disable flags, fallback, bounded preemption, assembly memory and register rules; runtime tests on the CPU/OS combinations to be supported | Tested in CI on available runners; the production target inventory still needs definition |
| Static analysis | CodeQL for Go, Python and Actions, with open alerts reviewed individually | CodeQL workflow passed on PR head `6062a908`; alert-triage decision still required |
| Quality and reproducibility | Go version matrix, race detector, fuzz tests, deterministic generated files, reproducible build inputs | Verified in CI for PR #1; re-check on the exact release commit |
| Deployment integration | Consumers use the exact Keccak-256 variant and a specified serialization/domain-separation scheme, with end-to-end network and consensus test vectors | Pending: no SILA production network integration is included in this repository |
| Vulnerability response | Confirmed confidential reporting channel, maintainer and response policy | Pending administrator configuration |
| Owner release approval | Approved release commit, signed-off residual risks, tagged release, reproducible release notes and rollback process | Pending Ahmed Ibrahim's explicit sign-off |

**Release decision:** the owner may choose an automated-review-first
security assurance model with documented residual risk. An external human
security audit is strongly recommended for cryptographic code that will
secure assets, but is not defined here as an unconditional prerequisite.
CodeQL, fuzzing and independent reference comparisons cannot establish
absolute safety or certify that the entire SILA blockchain is secure.

**Do not** merge or tag a production release merely because all workflow
jobs are green. Record the exact commit, target platforms, code scanning
alert disposition, integration evidence and owner's authorization first.

## Supported versions

| Version | Supported |
|---|---|
| `dev/*` branches and `main` before the first tagged release | Security fixes only, best effort |

## Reporting a vulnerability

**Do not disclose vulnerability details in a public issue.** If GitHub
private vulnerability reporting is enabled for
`sila-network/sila-core-primitives`, use the "Report a vulnerability"
entry under Security → Advisories.

If that option is not available, do **not** post reproduction details
publicly. Ask the project maintainers to provide a private reporting
channel without disclosing the vulnerability itself. Enabling confidential
reporting is a prerequisite for any production release.

Please include:

- the affected commit or version, the platform (OS, CPU, whether it has
  AVX-512) and the build tags used (`purego` or the default);
- a minimal reproduction: input bytes, expected and actual digest, or the
  memory-safety symptom;
- your assessment of the impact.

We aim to acknowledge reports within 5 working days and to agree a
disclosure date with you. We credit reporters unless they ask us not to.

## Scope

In scope: wrong digests, out-of-bounds reads or writes, crashes,
data-dependent timing in the permutation or sponge, CPU-dispatch errors, and
problems in the code generator that lead to any of these.

Out of scope: denial of service through very large inputs, and the generic
properties of Keccak-256 itself.
