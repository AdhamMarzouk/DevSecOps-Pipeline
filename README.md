# DevSecOps Pipeline Implementation
## Project Report

**Course:** Security Principles  
**Date:** April 2026  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Objectives](#2-objectives)
3. [Architecture](#3-architecture)
4. [Target Application](#4-target-application)
5. [Toolchain](#5-toolchain)
6. [Security Testing Results](#6-security-testing-results)
7. [Gap Analysis](#7-gap-analysis)
8. [Remediation Roadmap](#8-remediation-roadmap)
9. [Conclusion](#9-conclusion)

---

## 1. Executive Summary

This project implements an automated DevSecOps CI/CD pipeline using GitHub Actions. The pipeline integrates three security scanning tools to perform security analysis. SonarCloud (SAST), Trivy (SCA/Container), and OWASP ZAP (DAST) to test a deliberately vulnerable Python web application.

The core principle demonstrated is that security must be embedded into the development lifecycle rather than applied at deployment. Every push triggers automated security checks with enforced gates that block progression when critical vulnerabilities are detected.

The pipeline successfully identified all deliberately introduced vulnerabilities, including SQL Injection, Command Injection, XSS, Path Traversal, Hardcoded Credentials, and vulnerable dependencies. 

---

## 2. Objectives

| # | Objective | Status |
|---|-----------|--------|
| 1 | Build a CI/CD pipeline with automated security controls | Achieved |
| 2 | Integrate SAST (source code analysis) | SonarCloud |
| 3 | Integrate SCA/Container scanning | Trivy |
| 4 | Integrate DAST (runtime scanning) | OWASP ZAP |
| 5 | Implement security gates that fail on critical findings | All 3 gates active |
| 6 | Cover a realistic vulnerability set | 7 vulnerability classes |
| 7 | Produce evidence artifacts | SARIF + HTML reports |

---

## 3. Architecture

### Pipeline Flow

```
Push to main
      │
      ▼
┌─────────────┐
│    BUILD    │
│ docker build│
└──────┬──────┘
       │
   ┌───┴───┐
   ▼       ▼
┌──────┐ ┌────────────┐
│ SAST │ │ Container  │
│Sonar │ │ Scan/Trivy │
│ Cloud│ │ HIGH/CRIT  │
│ Gate │ │   Gate     │
└──┬───┘ └─────┬──────┘
   └─────┬─────┘
         ▼
┌─────────────────┐
│    ZAP-DAST     │
│ Full scan       │
│ HIGH-risk Gate  │
└─────────────────┘
```

### Job Dependencies

| Job | Depends On | Parallel? |
|-----|------------|-----------|
| Build | — | — |
| SonarQube-SAST | Build | Yes (with Trivy) |
| Container-Image-Scan | Build | Yes (with SAST) |
| ZAP-DAST | SAST AND Container | No |

The SAST and Container scans run in parallel after Build, reducing total pipeline duration. ZAP runs last since it requires the application to be deployed and reachable.

---

## 4. Target Application

### Overview

The target is a FastAPI web application (`app/main.py`) engineered with seven deliberate vulnerability classes. Building a custom vulnerable app provided precise control over which vulnerabilities exist and how each scanner should detect them.

### Vulnerability Matrix

| Endpoint | Method | Vulnerability | CWE | Primary Scanner |
|----------|--------|---------------|-----|-----------------|
| `/search?q=` | GET | Reflected XSS | CWE-79 | DAST |
| `/login` | POST | SQL Injection | CWE-89 | SAST + DAST |
| `/admin` | GET | Broken Access Control | CWE-284 | None (gap) |
| `/ping?host=` | GET | Command Injection | CWE-78 | SAST + DAST |
| `/file?name=` | GET | Path Traversal | CWE-22 | SAST + DAST |
| `/hash` | POST | Insecure Crypto (MD5) | CWE-327 | None (gap) |
| Module constants | — | Hardcoded Credentials | CWE-798 | SAST (partial) |

### Vulnerable Dependencies

| Package | Version | CVE | Severity |
|---------|---------|-----|----------|
| pyyaml | 5.3.1 | CVE-2020-14343 | CRITICAL |
| Pillow | 9.0.0 | CVE-2022-22817, CVE-2023-50447 | CRITICAL |

### Container

The Dockerfile uses `python:3.8-slim`. Python 3.8 reached end-of-life in October 2024, resulting in numerous unpatched OS-level CVEs that Trivy correctly flags.

---

## 5. Toolchain

| Tool | Role | Gate Condition |
|------|------|----------------|
| **SonarCloud** | SAST — semantic code analysis, taint tracking, secrets detection | Quality Gate FAILED |
| **Trivy** | SCA + Container image scanning | Any HIGH/CRITICAL CVE |
| **OWASP ZAP** | DAST — active attack simulation against running app | Any HIGH-risk alert |

**Why these tools?**
- SonarCloud provides deep data-flow analysis and a native Quality Gate integration (`sonar.qualitygate.wait=true`)
- Trivy handles both dependency and container scanning in one tool with zero configuration
- ZAP's full-scan mode actively sends attack payloads, confirming exploitability rather than just pattern-matching

---

## 6. Security Testing Results

### 6.1 SAST — SonarCloud

| Finding | Severity | Location | Rule |
|---------|----------|----------|------|
| Hardcoded API_KEY | Blocker | Line 18 | S6418 |
| Reflected XSS | Blocker | `/search` (L65-74) | S5131 |
| Reflected XSS | Blocker | `/hash` (L176-184) | S5131 |
| SQL Injection | Blocker | `/login` (L101) | S3649 |
| Command Injection | Blocker | `/ping` (L136) | S2076 |
| Path Traversal | Blocker | `/file` (L152) | S2083 |

**Gate Status:** FAILED (6 Blocker issues)

### 6.2 SCA/Container — Trivy

**Dependency Findings:**

| Package | CVE | CVSS | Severity |
|---------|-----|------|----------|
| Pillow 9.0.0 | CVE-2022-22817 | 9.8 | CRITICAL |
| Pillow 9.0.0 | CVE-2023-50447 | 9.8 | CRITICAL |
| Pillow 9.0.0 | CVE-2022-24303 | 9.1 | HIGH |
| pyyaml 5.3.1 | CVE-2020-14343 | 9.8 | CRITICAL |
| setuptools | CVE-2022-40897 | 7.5 | HIGH |

**Container Image Findings (python:3.8-slim):**

| Package | CVE | Severity |
|---------|-----|----------|
| libsqlite3-0 | CVE-2025-6965 | CRITICAL |
| gpgv | CVE-2025-68973 | HIGH |
| libexpat1 | CVE-2023-52425, CVE-2026-25210 | HIGH |
| libpam0g | CVE-2025-6020 | HIGH |
| ncurses-bin | CVE-2025-69720 | HIGH |
| perl-base | CVE-2023-31484 | HIGH |

**Gate Status:** FAILED (3+ CRITICAL, 15+ HIGH)

### 6.3 DAST — OWASP ZAP (Full Scan)

| Alert | Risk | Endpoint | ZAP Plugin |
|-------|------|----------|------------|
| Cross Site Scripting (Reflected) | HIGH | `/search?q=` | 40012 |
| Cross Site Scripting (DOM Based) | HIGH | `/search`, `/hash` | 40026 |
| SQL Injection | HIGH | `/login` | 40018 |
| Remote OS Command Injection | HIGH | `/ping?host=` | 90020 |
| Path Traversal | HIGH | `/file?name=` | 6 |

**Additional findings:** 5 Medium, 5 Low, 3 Informational

**Gate Status:** FAILED (5 HIGH alerts)

---

## 7. Gap Analysis

This section examines what each tool detected versus what was intentionally introduced, identifying coverage gaps.

### 7.1 Detection Coverage Matrix

| Vulnerability | Intended? | SonarCloud | Trivy | ZAP |
|---------------|-----------|------------|-------|-----|
| SQL Injection | Yes | Detected | — | Detected |
| Command Injection | Yes | Detected | — | Detected |
| Reflected XSS | Yes | Detected | — | Detected |
| Path Traversal | Yes | Detected | — | Detected |
| Hardcoded Credentials (API_KEY) | Yes | Detected | — | — |
| Hardcoded Credentials (SECRET_KEY) | Yes | **Missed** | — | — |
| Hardcoded Credentials (DB_PASS) | Yes | **Missed** | — | — |
| Insecure Crypto (MD5) | Yes | **Missed** | — | — |
| Broken Access Control | Yes | — | — | **Missed** |
| DOM-based XSS | No (bonus) | — | — | Detected |
| Vulnerable pyyaml | Yes | — | Detected | — |
| Vulnerable Pillow | Yes | — | Detected | — |
| EOL base image CVEs | Yes | — | Detected | — |

### 7.2 Key Gaps Identified

**1. Incomplete Hardcoded Credential Detection**

SonarCloud detected `API_KEY` but missed `SECRET_KEY` and `DB_PASS`. This suggests the secrets detection engine relies on pattern matching (the string "API_KEY" is a common pattern) rather than semantic analysis of how values are used.

**Implication:** Teams should not rely solely on SAST for secrets detection. Dedicated tools like Gitleaks or TruffleHog provide broader coverage.

**2. Insecure Cryptography Not Flagged**

The use of MD5 for password hashing (`hashlib.md5()`) was not detected by any tool:
- SonarCloud did not flag the `hashlib.md5()` call
- ZAP cannot observe cryptographic choices at runtime
- Trivy scans dependencies, not application logic

**Implication:** Cryptographic misuse requires either specialized SAST rules or manual code review. This is a significant blind spot.

**3. Broken Access Control Undetectable**

The `/admin` endpoint returns data without authentication, but no tool flagged it:
- SonarCloud cannot infer authorization requirements from code
- ZAP reached the endpoint successfully but has no concept of "this should require auth"

**Implication:** Access control testing requires authenticated scanning with defined user roles, or dedicated tools like Burp Suite with authorization testing plugins.

**4. Overlap Confirms Exploitability**

SQL Injection, Command Injection, XSS, and Path Traversal were detected by both SAST and DAST. This overlap is valuable—SAST finds the pattern, DAST confirms it's actually exploitable at runtime.

### 7.3 Tool Limitation Summary

| Tool | Strengths | Blind Spots |
|------|-----------|-------------|
| SonarCloud | Data-flow analysis, taint tracking | Incomplete secrets patterns, no crypto rules, no auth logic |
| Trivy | Comprehensive CVE database, zero-config | Application logic invisible |
| OWASP ZAP | Confirms exploitability with real attacks | No auth context, no business logic understanding |

### 7.4 Recommendations to Close Gaps

| Gap | Recommended Addition |
|-----|---------------------|
| Secrets detection | Add Gitleaks or TruffleHog to pipeline |
| Insecure crypto | Enable Semgrep with crypto rules, or Bandit |
| Broken access control | Implement authenticated ZAP scan with session tokens |
| Business logic flaws | Manual penetration testing / threat modeling |

---

## 8. Remediation Roadmap

### Source Code Fixes

| Vulnerability | Remediation |
|---------------|-------------|
| SQL Injection | Parameterized queries: `cursor.execute("SELECT * FROM users WHERE username=?", (username,))` |
| XSS | HTML escape output: `from html import escape` |
| Command Injection | Avoid `shell=True`, use allowlist: `subprocess.run(["ping", "-c", "1", validated_host])` |
| Path Traversal | Validate resolved path: `Path(base / name).resolve().is_relative_to(base)` |
| Hardcoded Creds | Use `os.getenv()` + GitHub Secrets |
| Insecure Crypto | Replace MD5 with bcrypt |

### Infrastructure Fixes

| Component | Current | Remediated |
|-----------|---------|------------|
| Base image | python:3.8-slim | python:3.12-slim |
| pyyaml | 5.3.1 | >=6.0.1 |
| Pillow | 9.0.0 | >=10.3.0 |

---

## 9. Conclusion

This project demonstrates a complete DevSecOps pipeline that:

1. Triggers automatically on every push
2. Tests security at multiple layers: source code, dependencies, container image, and runtime
3. Enforces gates that halt progression on HIGH/CRITICAL findings
4. Produces evidence artifacts for security review
5. Identifies all deliberately introduced vulnerabilities through at least one tool

The gap analysis reveals that even a well-designed multi-tool pipeline has blind spots—partial secrets detection, missing crypto rules, and no automated access control testing. These gaps don't invalidate the approach; they define where additional tools or manual review are needed.

The pipeline validates that security and delivery velocity are not opposed. Automated security controls enable confident, fast delivery by making vulnerability detection routine rather than a release-blocking gate review.

---

## Appendix: File Structure

```
DevSecOps-Pipeline/
├── .github/workflows/ci-cd.yml    # Pipeline definition
├── app/
│   ├── Dockerfile                 # Container (python:3.8-slim)
│   ├── main.py                    # Vulnerable FastAPI app
│   └── requirements.txt           # Dependencies
├── docs/
│   └── project_report.md          # This document
├── sonar-project.properties       # SonarCloud config
├── trivy-results.sarif            # Trivy scan output
└── report2_html.html              # ZAP full scan report
```
