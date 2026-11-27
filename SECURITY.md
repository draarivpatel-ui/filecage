# Security policy

`filecage` is itself a security boundary. Vulnerability reports receive priority.

## Supported versions

| Version | Status |
| --- | --- |
| 1.0.x | Current release line |

## Reporting a vulnerability

Please do not open a public issue for an exploitable vulnerability. Use the
GitHub private vulnerability reporting flow for this repository when available,
or open a minimal public issue asking for a private contact path without
including exploit details.

Include:

- Affected version and Node.js version.
- Operating system.
- A minimal byte fixture or hex representation when safe to share.
- The expected security boundary and the actual result.
- Whether the issue requires a specific policy option.

Do not include real secrets, personal data, or live third-party infrastructure
in a proof of concept.

## Response goals

- Acknowledgment within 7 days.
- Triage and reproduction as soon as feasible.
- A fix, regression test, and advisory decision before public disclosure when
  the report is valid.

## Security expectations and limitations

A clean validation result is limited to the documented policy and threat model.
`filecage` does not execute files, render documents, scan malware signatures, or
sandbox downstream decoders. Applications must still store uploads outside the
web root, avoid executing them, patch downstream parsers, and use isolation for
any re-encoding pipeline.
