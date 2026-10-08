# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Privacy & Security Model

The **Network Traffic Triage Tool (`net-triage`)** was designed as an entirely client-side, zero-dependency static web application. 

- **No Remote Transmission:** All uploaded files and analyzed packet data remain exclusively in the user's browser memory.
- **No Third-Party Scripts:** The application does not incorporate CDNs, external analytics, trackers, or cookies.
- **XSS Sanitization:** All untrusted input fields derived from packet metadata are escaped before DOM insertion.

## Reporting a Vulnerability

If you discover a security vulnerability or client-side sanitization flaw:

1. Please do not open a public issue.
2. Report the vulnerability privately via GitHub Security Advisories or contact the repository owner directly.
3. Include a description of the issue, steps to reproduce, and a sample safe CSV file demonstrating the behavior.

We appreciate your responsible disclosure and support in keeping educational cybersecurity tools safe.
