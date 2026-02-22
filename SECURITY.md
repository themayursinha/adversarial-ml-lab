# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.2.x | Yes |
| < 0.2.0 | No |

## Reporting a Vulnerability

Do not open public issues for suspected vulnerabilities.

1. Open a private GitHub Security Advisory report (preferred).
2. Include affected version/commit, impact, reproduction steps, and any logs.
3. Use encrypted communication if sharing sensitive artifacts.

We target:
- Initial acknowledgement within 3 business days.
- Triage decision within 7 business days.
- Coordinated disclosure with reporter credit unless anonymity is requested.

## Disclosure and Severity

Severity is scored with CVSS v3.1 and mapped to internal priority:
- Critical: fix starts immediately, hotfix release target <= 72 hours.
- High: fix in next patch release.
- Medium: fix in next minor release.
- Low: fix as part of backlog hardening.

## Scope

In scope:
- Code execution, auth bypass, data exfiltration, or tampering vulnerabilities.
- Supply-chain risk in build or release pipelines.
- Security control bypasses in the defense pipeline.

Out of scope:
- Vulnerabilities in third-party dependencies without a project-specific impact path.
- Denial-of-service scenarios requiring unrealistic resource assumptions.
