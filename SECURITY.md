# Security Policy

## Reporting

Report vulnerabilities through GitHub private vulnerability reporting for this repository. Do not open a public issue for a suspected credential, Prompt, proxy-recovery, certificate, update, or local IPC vulnerability.

Include the affected commit, platform, reproduction steps, and observed security boundary. Use synthetic requests and credentials only. Never attach real Prompt content, API keys, database files, support bundles, certificate private material, or proxy recovery journals.

## Response

- Critical network-recovery or credential-exposure reports are acknowledged within two business days.
- Reproduction and severity are confirmed before a public disclosure date is selected.
- Fixes include regression tests and an audit of persisted data, logs, temporary files, exports, and recovery artifacts when relevant.
- Supported security fixes target the latest `main` revision until signed release channels are available.

## Release Gates

A release is blocked by credential persistence, unrecoverable system proxy changes, invalid component hashes, an unsigned release component, a high-severity newly introduced dependency vulnerability, or a failed security-boundary test.
