# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Reporting a vulnerability

Use GitHub's **Report a vulnerability** button (private vulnerability
reporting) on this repository. Please don't open a public issue. We aim to
acknowledge reports within 3 business days and to ship a fix or mitigation
within 30 days for confirmed issues, crediting you if you'd like.

Please test only on systems you own. Don't include real credentials or
customer data in reports.

## What we consider a vulnerability

Anything that lets an effect run without a valid, matching FailStop allow;
anything that sends data off the machine without the user configuring it; a
receipt tamper that `verify` misses (within the threat model in
docs/THREAT_MODEL.md); and crashes caused by untrusted input.
