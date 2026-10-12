# Semgrep Java Rule Analysis Report

**Total rules analyzed: 108**

---

### 1. Severity Distribution

| Value | Count | Percentage |
|-------|------:|----------:|
| WARNING | 81 | 75.00% |
| ERROR | 24 | 22.22% |
| INFO | 3 | 2.78% |

### 2. Category Distribution

| Value | Count | Percentage |
|-------|------:|----------:|
| security | 104 | 96.30% |
| correctness | 4 | 3.70% |

### 3. Subcategory Distribution

| Value | Count | Percentage |
|-------|------:|----------:|
| vuln | 53 | 49.07% |
| audit | 51 | 47.22% |
| (empty) | 4 | 3.70% |

### 4. Confidence Distribution

| Value | Count | Percentage |
|-------|------:|----------:|
| LOW | 48 | 44.44% |
| HIGH | 30 | 27.78% |
| MEDIUM | 26 | 24.07% |
| (empty) | 4 | 3.70% |

### 5. Autofix Availability

| Value | Count | Percentage |
|-------|------:|----------:|
| True | 13 | 12.04% |
| False | 95 | 87.96% |

### 6. OWASP ASVS Mapping Coverage

| Value | Count | Percentage |
|-------|------:|----------:|
| True | 32 | 29.63% |
| False | 76 | 70.37% |

### 7. CWE Distribution (Top 20)

Total unique values: 40 | Total mentions: 104

| Value | Count |
|-------|------:|
| CWE-89 | 11 |
| CWE-327 | 10 |
| CWE-611 | 9 |
| CWE-326 | 7 |
| CWE-78 | 5 |
| CWE-94 | 5 |
| CWE-200 | 5 |
| CWE-328 | 4 |
| CWE-502 | 4 |
| CWE-79 | 4 |
| CWE-319 | 3 |
| CWE-90 | 3 |
| CWE-116 | 3 |
| CWE-323 | 2 |
| CWE-295 | 2 |
| CWE-601 | 2 |
| CWE-352 | 2 |
| CWE-287 | 1 |
| CWE-704 | 1 |
| CWE-1004 | 1 |
| ... (20 more) | |

### 8. OWASP Top 10 Mapping Distribution (Top 20)

Total unique values: 27 | Total mentions: 267

| Value | Count |
|-------|------:|
| A03:2021 - Injection | 37 |
| A05:2025 - Injection | 37 |
| A02:2021 - Cryptographic Failures | 28 |
| A04:2025 - Cryptographic Failures | 28 |
| A03:2017 - Sensitive Data Exposure | 26 |
| A01:2017 - Injection | 20 |
| A01:2025 - Broken Access Control | 13 |
| A01:2021 - Broken Access Control | 12 |
| A05:2021 - Security Misconfiguration | 11 |
| A02:2025 - Security Misconfiguration | 11 |
| A04:2017 - XML External Entities (XXE) | 9 |
| A07:2021 - Identification and Authentication Failures | 4 |
| A07:2025 - Authentication Failures | 4 |
| A07:2017 - Cross-Site Scripting (XSS) | 4 |
| A08:2017 - Insecure Deserialization | 3 |
| A08:2021 - Software and Data Integrity Failures | 3 |
| A08:2025 - Software or Data Integrity Failures | 3 |
| A04:2021 - Insecure Design | 3 |
| A06:2025 - Insecure Design | 3 |
| A02:2017 - Broken Authentication | 1 |
| ... (7 more) | |

### Rules by Framework/Library (derived from file path)

| Framework | Count | Percentage |
|-----------|------:|----------:|
| lang | 90 | 83.33% |
| spring | 15 | 13.89% |
| servlets | 3 | 2.78% |

### 10. Category vs. Severity

| category \ severity | ERROR | INFO | WARNING | Total |
|---|---|---|---|---|
| correctness | 3 | 0 | 1 | 4 |
| security | 21 | 3 | 80 | 104 |

### 11. Category vs. Subcategory

| category \ subcategory | (empty) | audit | vuln | Total |
|---|---|---|---|---|
| correctness | 4 | 0 | 0 | 4 |
| security | 0 | 51 | 53 | 104 |

### Severity vs. Confidence

| Severity \ Confidence | LOW | MEDIUM | HIGH | (empty) | Total |
|---|---|---|---|---|---|
| ERROR | 3 | 9 | 9 | 3 | 24 |
| WARNING | 43 | 16 | 21 | 1 | 81 |
| INFO | 2 | 1 | 0 | 0 | 3 |

### 13. Severity vs. Autofix Availability

| severity \ has_fix | False | True | Total |
|---|---|---|---|
| ERROR | 19 | 5 | 24 |
| INFO | 3 | 0 | 3 |
| WARNING | 73 | 8 | 81 |
