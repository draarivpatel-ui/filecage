# Security policy

`filecage` is itself a security boundary. Vulnerability reports receive priority.

## Supported versions

| Version | Status |
| --- | --- |
| 1.0.x | Current release line |

## Reporting a vulnerability

Please do not open a public issue for an exploitable vulnerability. Use the
repository's [GitHub Security Advisory form](https://github.com/draarivpatel-ui/filecage/security/advisories/new) and do not include
exploit details in public discussion.

Include:

- Affected version and Node.js version.
- Operating system.
- A minimal byte fixture or hex representation when safe to share.
- The expected security boundary and the actual result.
- Whether the issue requires a specific policy option.

Do not include real secrets, personal data, or live third-party infrastructure
in a proof of concept.

## Response goals

- Acknowledgment: within 48 hours.
- Initial assessment: within 7 calendar days.
- Fix or mitigation plan: within 30 calendar days for confirmed high-impact reports.
- Coordinated public disclosure: up to 90 days by default, adjusted by mutual agreement when exploitation or user risk requires a different date.

## Security expectations and limitations

A clean validation result is limited to the documented policy and threat model.
`filecage` does not execute files, render documents, scan malware signatures, or
sandbox downstream decoders. Applications must still store uploads outside the
web root, avoid executing them, patch downstream parsers, and use isolation for
any re-encoding pipeline.
