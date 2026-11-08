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
