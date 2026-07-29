# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately via
[GitHub Security Advisories](https://github.com/alapierre/aikido-report/security/advisories/new).
Do not open a public issue for security problems.

You can expect an initial response within a few days. Please include a
minimal reproduction where possible.

## Scope

This tool handles Aikido API credentials. Reports are especially welcome
for:

- credential leakage into logs, error messages, files, or SARIF output,
- the HTTP client sending `Authorization` to an unexpected host,
- unsafe handling of API responses (unbounded reads, injection into logs),
- report files written with unsafe permissions or to unsafe paths.

## Supported versions

Only the latest release receives security fixes.
