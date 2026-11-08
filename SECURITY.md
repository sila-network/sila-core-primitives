# Security Policy

## Status

SILA Core Primitives has **not** been independently security-audited and is
**not approved for production use**. The internal review is in
`docs/SECURITY-REVIEW-2026-11-08.md`.

## Supported versions

| Version | Supported |
|---|---|
| `dev/*` branches and `main` before the first tagged release | Security fixes only, best effort |

## Reporting a vulnerability

**Do not open a public issue.** Report it privately through GitHub's
"Report a vulnerability" button (Security tab → Advisories) on
`sila-network/sila-core-primitives`.

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
