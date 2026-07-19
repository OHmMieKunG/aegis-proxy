# Security policy

Do not report secrets, private keys, production host details, or real certificates in issues or tests.

Report suspected vulnerabilities privately through the GitHub security-advisory form:
https://github.com/OHmMieKunG/aegis-proxy/security/advisories/new. Do not open a public issue
before coordinated disclosure. If the form is unavailable, contact a repository owner privately
and include only enough redacted detail to establish impact and reproduction.

Include affected commit/version, boundary, prerequisites, impact, minimal reproduction, and safe
contact details. Maintainers should acknowledge within three business days, provide a triage
status within seven business days, and coordinate disclosure timing with the reporter. These are
response targets, not guarantees.

The project is pre-release. Security-sensitive changes require a regression test, threat-model update where applicable, and review of parser, secret, authorization, or resource-limit impact. The implementation does not claim to be vulnerability-free.
