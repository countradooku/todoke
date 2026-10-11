# Security policy

## Current status

todoke is an initial repository scaffold. No released version, protocol implementation, or independently reviewed security claim exists. The intended security model is documented in [docs/DESIGN.md](docs/DESIGN.md) and [spec/PROTOCOL.md](spec/PROTOCOL.md).

## Reporting a vulnerability

GitHub private vulnerability reporting is enabled for this repository. Use
[Report a vulnerability](https://github.com/countradooku/todoke/security/advisories/new)
to send a private report to the repository maintainer, `@countradooku`.

Do not put exploit details, secrets, personal data, or private files into a public
issue or pull request. If GitHub's private reporting form is unavailable, ask the
maintainer for a private channel using a message containing no vulnerability
details. No alternate email address is currently published.

Include the affected revision and platform, the observed impact, reproduction
steps, and a minimal example using synthetic data. Redact credentials, device
keys, pairing PSKs, and file contents belonging to others. Never transmit live
secrets to demonstrate an issue.

## Coordinated handling

Maintainers should acknowledge a private report, agree on a communication channel, reproduce and assess it, prepare a fix with regression coverage, and coordinate publication with the reporter. Disclosure timing and attribution should be agreed with the reporter based on impact and remediation progress. No response-time guarantee, fixed embargo, or bug-bounty payment is currently promised.

Reports affecting dependencies should be coordinated with the relevant upstream maintainers. When publishing a fix, explain affected versions, impact, remediation, and any remaining limitations without exposing users' data.

## Supported versions

There are no released versions. Before the first release, maintainers must define supported release lines and a security update policy. Do not infer ongoing security support from a compiling development revision.
