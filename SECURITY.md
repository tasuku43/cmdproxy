# Security Policy

## Reporting a Vulnerability

Please do not open public issues for unpatched vulnerabilities.

Report security issues privately to the maintainer with:

- impact summary
- reproduction steps
- affected version or commit if known
- suggested fix, if available

## Response Expectations

- initial acknowledgment target: within 72 hours
- follow-up may request extra detail or a proof of concept
- confirmed issues will be fixed through the normal release process

## Supported Versions

Security fixes are generally provided for the latest released version.

You may be asked to reproduce the issue on the latest release before a fix is
prepared.

## Verification Guidance

Because `cc-bash-proxy` can rewrite commands before execution, users should treat the
installed binary as part of their execution trust boundary.

Before relying on a downloaded build:

1. verify the published release checksum
2. inspect the binary with `cc-bash-proxy version --format json`
3. run `cc-bash-proxy verify --format json`

## Disclosure

After a fix is available, the project may publish:

- a short impact summary
- affected and fixed versions
- recommended upgrade guidance
