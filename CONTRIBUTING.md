# Contributing to Network Traffic Triage Tool (`net-triage`)

Thank you for your interest in contributing! This project is an open educational cybersecurity tool designed to teach students and aspiring SOC analysts how to investigate network anomalies responsibly.

## Guiding Principles

1. **Zero External Dependencies:** We strictly avoid introducing frameworks (React, Next.js, Vue, Tailwind CLI), package dependencies (Node/npm), or external backend services. The tool must remain run-ready by double-clicking `index.html`.
2. **Local-First Privacy:** No features that transmit user packets or IP addresses externally will be accepted.
3. **Explainability Over Hype:** Detections must be explainable, transparent, and provide educational context (Observed Evidence, Benign Explanations, Investigation Steps). No fake "AI maliciousness" scores.
4. **Resilient Parsing & Security:** All CSV data must be treated as untrusted input and properly sanitized to prevent DOM-based XSS attacks.

## How to Contribute

1. **Fork the Repository** on GitHub.
2. **Create a Feature Branch:**
   ```bash
   git checkout -b feature/new-triage-rule
   ```
3. **Make and Test Your Changes:**
   - Test locally with all three sample CSV files in `samples/`.
   - Ensure boundary values strictly use `>` comparisons.
   - Verify zero console errors and clean rendering.
4. **Commit and Push:**
   ```bash
   git commit -m "feat: add support for ARP storm triage rule"
   git push origin feature/new-triage-rule
   ```
5. **Open a Pull Request** describing your changes and rationale.
