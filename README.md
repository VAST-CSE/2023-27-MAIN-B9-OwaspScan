# owaspscan

<p align="center">
  <strong>Dual Static (SAST) & Dynamic (DAST) Security Scanner aligned with OWASP Top 10 (2021)</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9+-blue.svg" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/standard%20library-zero%20dependencies-brightgreen.svg" alt="Zero Dependencies">
  <img src="https://img.shields.io/badge/taxonomy-OWASP%20Top%2010%3A2021-orange.svg" alt="OWASP Top 10">
  <img src="https://img.shields.io/badge/tests-18%20passed-success.svg" alt="Tests">
</p>

---

## 📌 Overview

**`owaspscan`** is an ultra-lightweight, zero-external-dependency command-line security tool designed to bridge the gap between **Static Application Security Testing (SAST)** and **Dynamic Application Security Testing (DAST)**. 

Built exclusively using the Python Standard Library (`ast`, `re`, `http.client`, `ssl`, `argparse`), it requires zero third-party packages to install and execute, making it fast, auditable, and embeddable into lightweight CI/CD verification pipelines.

```
                  ┌────────────────────────────────────────┐
                  │               owaspscan                │
                  └──────────────────┬─────────────────────┘
                                     │
           ┌─────────────────────────┴────────────────────────┐
           ▼                                                  ▼
   [ SAST Engine ]                                    [ DAST Engine ]
 • Multi-language Regex Rules                        • TLS / Transport Verification
 • Python AST Semantic Analysis                      • Security Headers & Cookie Audit
 • Dependency Manifest Auditing                      • Soft-404 Baseline Probing
 • Line-level '# noscan' Suppression                 • Canary Param Probing (XSS/SQLi)
```

---

## ✨ Features

- **Zero Runtime Dependencies**: Runs out of the box on Python 3.9+ without needing external packages.
- **Dual Verification Modes**:
  - **SAST**: Scans source code using multi-language regex heuristics and Python AST visitors.
  - **DAST**: Evaluates live servers via passive header/cookie inspections, baseline-aware sensitive path discovery, and safe reflection probes.
- **Standardized Taxonomy**: Rules mapped directly to the official **OWASP Top 10:2021** categories.
- **CI/CD Gate Integration**: Supports `--fail-on [low|medium|high|critical]` to break builds on vulnerability discovery, with human-readable colored terminal output or machine-readable JSON (`-f json`).
- **Suppression Mechanism**: Allows inline false-positive suppression via `# noscan` or `// noscan`.
- **Safe & Non-Destructive**: Live web scans enforce `--i-have-permission` and use rate-limited, single canary payloads without brute-forcing.

---

## 🚀 Quick Start

### Installation

Clone the repository and install in editable mode:

```bash
git clone git@github.com:VAST-CSE/2023-27-MAIN-B9-OwaspScan.git
cd 2023-27-MAIN-B9-OwaspScan
pip install -e .
```

Verify installation:
```bash
owaspscan --help
```

---

## 📖 Usage Guide

### 1. Static Source Code Analysis (`scan`)

Scan a directory or file:
```bash
owaspscan scan src/
```

Scan demo vulnerable code included in the repository:
```bash
owaspscan scan samples/
```

#### Advanced Scan Options
```bash
# Filter by minimum severity
owaspscan scan src/ --min-severity medium

# CI/CD Gate: Fail (exit code 1) if high or critical issues are found
owaspscan scan src/ --fail-on high

# Export structured JSON report
owaspscan scan src/ -f json > scan-results.json

# Scope to specific OWASP categories (e.g., A01 Broken Access Control, A03 Injection)
owaspscan scan src/ --only A01,A03
```

#### Suppressing Known Lines
To mark a line as reviewed and suppress alerts, append `# noscan` (or `// noscan`):
```python
result = eval(user_expression)  # noscan: sanitized via custom parser
```

---

### 2. Live Web Transport & Dynamic Probing (`web`)

> [!IMPORTANT]
> **Authorized Testing Only**: The `--i-have-permission` flag is mandatory. Never scan targets you do not own or lack explicit permission to test.

Run safe, read-only checks against a live URL or domain:
```bash
owaspscan web example.com --i-have-permission
```

Test a specific endpoint with customized rate limiting:
```bash
owaspscan web "https://example.com/search?q=test" --i-have-permission --delay 0.5 --timeout 10
```

#### What `web` Audits:
- **A01 Sensitive Files**: Checks for 13 common sensitive endpoints (`/.git/HEAD`, `/.env`, `/.htpasswd`, etc.) calibrated against a randomized soft-404 baseline.
- **A02 Transport Security**: Validates HTTP-to-HTTPS redirection, TLS certificate expiration/verification, and weak protocol negotiation (TLS 1.0, 1.1, SSLv3).
- **A03 Parameter Reflection**: Tests GET query parameters with a single benign canary token to detect unescaped HTML reflection (XSS) and database syntax error strings (SQLi).
- **A05 Security Headers**: Audits for missing `CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and server version banners.
- **A07 Cookie Security**: Verifies `HttpOnly`, `Secure`, and `SameSite` attributes on all `Set-Cookie` directives.

#### Web Scan Flags:
- `--no-path-probe`: Disables sensitive endpoint discovery.
- `--no-param-probe`: Disables canary injection probes, keeping the scan purely passive.
- `--delay <seconds>`: Request pacing / rate limiting (default: `0.25s`).
- `--timeout <seconds>`: Socket timeout (default: `8.0s`).

---

### 3. Listing Active Rules (`rules`)

Inspect the built-in rule catalog:
```bash
owaspscan rules
```

---

## 🛡️ OWASP Top 10 (2021) Coverage Matrix

| Category | Static (SAST) Rule IDs | Dynamic (DAST) Rule IDs | Coverage Level |
| :--- | :--- | :--- | :---: |
| **A01: Broken Access Control** | `OWS-A01-001` (Path Traversal)<br>`OWS-A01-002` (Missing Route Auth) | `OWS-WEB-A01-001` (Exposed Sensitive Paths) | **High** |
| **A02: Cryptographic Failures** | `OWS-A02-001` (MD5/SHA1)<br>`OWS-A02-002` (Weak RNG for Secrets)<br>`OWS-A02-003` (verify=False)<br>`OWS-A02-004` (Hard-coded Secrets) | `OWS-WEB-A02-001` (Plain HTTP)<br>`OWS-WEB-A02-002` (TLS Cert Failed)<br>`OWS-WEB-A02-003` (TLS Cert Expired)<br>`OWS-WEB-A02-004` (Weak TLS Version) | **High** |
| **A03: Injection** | `OWS-A03-001` (SQL String Concatenation)<br>`OWS-A03-002` (Shell Command Execution)<br>`OWS-A03-003` (Dynamic eval/exec)<br>`OWS-A03-004` (SSTI / Template Injection) | `OWS-WEB-A03-001` (Reflected XSS Canary)<br>`OWS-WEB-A03-002` (Single-Quote SQL Error) | **High** |
| **A04: Insecure Design** | *Requires Architectural Threat Modeling* | *N/A* | *Manual* |
| **A05: Security Misconfiguration** | `OWS-A05-001` (Debug Mode Enabled)<br>`OWS-A05-002` (Wildcard CORS Policy) | `OWS-WEB-A05-001` (Missing Security Headers)<br>`OWS-WEB-A05-002` (Server Version Leaks) | **High** |
| **A06: Vulnerable Components** | `OWS-A06-001` (Unpinned Manifest Dependencies) | *N/A* | **Medium** |
| **A07: Identification & Auth** | `OWS-A07-001` (JWT Signature Disabled / None Alg) | `OWS-WEB-A07-001` (Missing HttpOnly)<br>`OWS-WEB-A07-002` (Missing Secure)<br>`OWS-WEB-A07-003` (Missing SameSite) | **High** |
| **A08: Software & Data Integrity**| `OWS-A08-001` (Unsafe Pickle/Marshal)<br>`OWS-A08-002` (Unsafe YAML Load) | *N/A* | **Medium** |
| **A09: Logging & Monitoring** | `OWS-A09-001` (Sensitive Data in Logs)<br>`OWS-A09-002` (Swallowed Exceptions) | *N/A* | **Medium** |
| **A10: SSRF** | `OWS-A10-001` (Outbound Request with User URL) | *N/A* | **Medium** |

---

## 📂 Project Architecture

```
owasp-scan/
├── owaspscan/
│   ├── cli.py              # CLI argument parser and CI gate exit dispatch
│   ├── models.py           # Severity enum, Finding dataclass, OWASP mapping
│   ├── scanner.py          # Static discovery, manifest parsing, regex and AST engine
│   ├── webscan.py          # Dynamic HTTP(S) client, TLS inspection, probe engine
│   ├── reporters.py        # Terminal formatting and JSON serializers
│   └── rules/
│       ├── base.py         # RegexRule definition
│       ├── regex_rules.py  # Declarative regex pattern registry
│       └── ast_rules.py    # Python AST visitors for route auth and error handling
├── samples/
│   ├── vulnerable_app.py   # Deliberately vulnerable Flask app for benchmarking
│   └── requirements.txt    # Unpinned dependencies demo
├── tests/
│   ├── test_scanner.py     # Unit test suite for static rules and AST checks
│   └── test_webscan.py     # DAST test suite with integrated mock HTTP server
├── build_reports.py        # Generates comprehensive evaluation reports (PDF/DOCX/HTML)
├── pyproject.toml          # Package metadata and entry points
└── README.md
```

---

## 🧪 Testing

Execute the automated test suite:

```bash
python3 -m unittest discover tests
```

Output:
```
..................
----------------------------------------------------------------------
Ran 18 tests in 0.55s

OK
```

---

## 📄 Documentation & Reports

A comprehensive technical evaluation report detailing research gaps, formal static analysis benchmarks against industry tools (CodeQL, Semgrep, OWASP ZAP), and architectural specifications is included in the project:
- `owaspscan_technical_report.pdf`
- `owaspscan_technical_report.docx`
- `owaspscan_technical_report.html`

To recompile reports from source:
```bash
python3 build_reports.py
```
