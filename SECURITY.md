# Security policy

Interlock is a security tool, so bypasses matter to us more than most bugs.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private vulnerability reporting on this repository (Security → Report a vulnerability). Include the agent and version, the policy (if not default), and the smallest reproduction you have.

We aim to acknowledge within 3 working days and to agree a disclosure timeline with you.

The threat model (assets, adversaries, where Interlock sees, and its known limits) is in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## In scope

- A tool call that should be blocked by a default rule but is not (an encoding, splitting, or tool-swap bypass).
- An injected tool result that should be withheld but reaches the agent where the agent supports withholding.
- Ways for an agent to disable or tamper with Interlock that `interlock doctor` does not detect.
- Anything that lets another local user or process talk to the daemon without the token.

## Out of scope

- Actions that never pass through an agent's hooks (documented limit).
- Findings that require an already-compromised user account.

## Verifying a release

Releases are built by GitHub Actions from the tagged commit and published to PyPI with trusted publishing (no stored
token). From 0.1.2, every wheel and sdist also carries a signed build provenance attestation (Sigstore):

```sh
pip download interlockd==<version> --no-deps -d /tmp/il && gh attestation verify /tmp/il/* --repo interlockd/interlock
```

PyPI shows the same provenance on each file's page ("Verified details").
