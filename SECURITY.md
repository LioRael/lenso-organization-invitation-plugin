# Security policy

Please report suspected vulnerabilities privately to the repository owner.
Do not open a public issue containing an invitation token, database URL,
pepper, derivation secret, Actor Assertion, provider receipt, email address, or
other personal data.

Supported releases receive fixes on the latest published minor line. Reports
should include the affected crate version, the relevant Capability operation,
the expected trust boundary, and a minimal reproduction with secrets removed.

Operators should treat invitation URLs as bearer credentials, restrict
management/acceptance/worker caller allowlists to exact Plugin Instance keys,
grant the four documented Access Control permissions narrowly, keep all three
Secrets references distinct, and monitor permanently failed command counts.
