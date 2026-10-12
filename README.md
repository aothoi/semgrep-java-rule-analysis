# semgrep-java-rule-analysis

> Automated taxonomy extraction and data analysis for Semgrep Java static analysis rules.

This repository provides a reproducible pipeline for extracting, cataloging, and analyzing Semgrep's Java static analysis rules. Semgrep is an open-source, lightweight static analysis tool that uses pattern-matching to detect bugs, security vulnerabilities, and code style issues. Unlike PMD's XML-based rulesets, Semgrep defines its rules in YAML with rich security metadata including CWE identifiers, OWASP Top 10 mappings, ASVS compliance flags, and confidence/impact/likelihood ratings.

The rule corpus is scoped to three framework categories — core Java (`lang`), Spring (`spring`), and Servlets (`servlets`) — selected to align with the target repositories used in our research.

---

## Repository Structure

| File / Directory | Description |
| :--- | :--- |
| `rulesets/` | Semgrep Java ruleset YAML definitions across `lang`, `spring`, and `servlets` frameworks. |
| `parse_semgrep_rules.py` | Zero-dependency Python script to parse YAML rulesets into a structured CSV dataset. |
| `semgrep_java_rule_dataset.csv` | Taxonomy dataset cataloging all 108 Semgrep Java rules across 10 schema fields. |
| `semgrep_rule_dataset_analyzer.py` | Zero-dependency Python script performing exploratory data analysis on the dataset. |
| `semgrep_java_rule_analysis_report.md` | Markdown summary report generated automatically by the analyzer script. |

---

## Scripts

### **Taxonomy Parser (`parse_semgrep_rules.py`)**

The parser recursively scans all YAML rule files under `rulesets/`, extracts rule-level and metadata-level fields, and writes them into a flat CSV dataset. Each Semgrep rule is a self-contained YAML document that bundles the detection pattern with its security metadata, making it possible to extract a complete taxonomy without any external lookup tables.

- **Dynamic YAML Parsing**: Extracts metadata directly from Semgrep YAML rule definitions using line-based parsing without external libraries.
- **Security Metadata Extraction**: Captures CWE identifiers, OWASP Top 10 mappings, ASVS compliance flags, confidence levels, and subcategories.
- **Multi-Value Handling**: Flattens list-valued fields (CWE, OWASP) into semicolon-separated strings for CSV compatibility.
- **Test File Exclusion**: Automatically skips `.test.yaml` files that are used for Semgrep's internal rule validation.
- **Zero Dependencies**: Built entirely on standard Python 3 modules (`re`, `csv`, `glob`, `os`).

### **Dataset Analyzer (`semgrep_rule_dataset_analyzer.py`)**

The analyzer reads the generated CSV and computes a comprehensive set of descriptive statistics. It produces both human-readable console output and a structured Markdown report suitable for inclusion in research documents.

- **Statistical Summaries**: Computes rule distributions across severity levels, categories, subcategories, confidence levels, CWE identifiers, and OWASP Top 10 mappings.
- **Cross-Tabulation**: Evaluates relationships between category/severity, category/subcategory, severity/confidence, and severity/autofix availability.
- **Framework Breakdown**: Derives framework/library groupings from the file path structure (`lang`, `spring`, `servlets`).
- **Automated Reporting**: Prints formatted tables to console and exports `semgrep_java_rule_analysis_report.md`.
- **Zero Dependencies**: Fully portable using Python standard library (`csv`, `collections`).

---

## Dataset Schema

The dataset catalogs **108 active Semgrep Java rules** across 10 schema fields. Unlike PMD's simpler 6-field schema (rule ID, name, category, path, priority, default profile), Semgrep rules carry significantly richer metadata — particularly for security-category rules, which are required to include CWE mappings, confidence, likelihood, impact, and subcategory classifications.

| Field Name | Type | Description | Example |
| :--- | :--- | :--- | :--- |
| `semgrep_id` | String | Official Semgrep rule identifier | `httpservlet-path-traversal` |
| `severity` | String | Semgrep severity level (`ERROR`, `WARNING`, `INFO`) | `ERROR` |
| `category` | String | Rule category (`security`, `correctness`, `best-practice`) | `security` |
| `subcategory` | String | Security subcategory (`vuln`, `audit`, `secure default`) | `vuln` |
| `confidence` | String | Detection confidence level (`LOW`, `MEDIUM`, `HIGH`) | `MEDIUM` |
| `cwe` | String | CWE identifiers, semicolon-separated if multiple | `CWE-22` |
| `owasp` | String | OWASP Top 10 mappings, semicolon-separated | `A05:2017 - Broken Access Control` |
| `has_asvs` | Boolean | OWASP ASVS compliance mapping flag (`True`/`False`) | `True` |
| `has_fix` | Boolean | Whether the rule provides an autofix (`True`/`False`) | `False` |
| `rule_file_path` | String | Relative path to the YAML rule definition | `rulesets/lang/security/audit/cbc-padding-oracle.yaml` |

> **Note:** Fields `subcategory`, `confidence`, `cwe`, and `owasp` are only populated for `security`-category rules. Semgrep's metadata schema enforces these as required fields when `category: security` is set. Non-security rules (e.g., `correctness`) will have these columns empty.

---

## Usage

### **1. Extract the Taxonomy Dataset**
Ensure `rulesets/` (containing Semgrep YAML rules) is in your working directory, then run:

```bash
python3 parse_semgrep_rules.py
```
*Output*: Generates `semgrep_java_rule_dataset.csv` (108 rules).

### **2. Run Dataset Analysis**
To generate summary statistics and the markdown report:

```bash
python3 semgrep_rule_dataset_analyzer.py
```
*Output*: Displays terminal analysis and exports `semgrep_java_rule_analysis_report.md`.

---

## Key Findings

### **1. Severity Distribution**

Semgrep uses three severity levels. The majority of rules are classified as `WARNING`, indicating issues that should be reviewed but may not always represent exploitable vulnerabilities. `ERROR`-level rules flag high-confidence, directly exploitable issues.

- **WARNING**: 81 rules (75.00%)
- **ERROR**: 24 rules (22.22%)
- **INFO**: 3 rules (2.78%)

### **2. Category Distribution**

The Semgrep Java rule corpus is overwhelmingly security-focused. Only 4 rules fall under `correctness`, and none under `best-practice`, `performance`, or `maintainability` — a stark contrast to PMD, which distributes its 325 rules across 8 categories with `Error Prone` (30.77%) and `Best Practices` (21.85%) leading.

- **Security**: 104 rules (96.30%)
- **Correctness**: 4 rules (3.70%)

### **3. Subcategory Distribution**

Within the security category, Semgrep distinguishes between `vuln` (rules that detect likely-exploitable vulnerabilities) and `audit` (rules that flag patterns worth reviewing but may be intentional). This split is nearly even, providing balanced coverage of both detection modes.

- **vuln** (vulnerability): 53 rules (49.07%)
- **audit**: 51 rules (47.22%)
- **(empty)**: 4 rules (3.70%) — non-security rules

### **4. Confidence Distribution**

Confidence reflects how often a rule's finding is a true positive. Nearly half the rules are marked `LOW` confidence, meaning they require manual triage. This is consistent with the large number of `audit`-subcategory rules, which are designed to surface patterns for human review rather than flag definitive bugs.

- **LOW**: 48 rules (44.44%)
- **HIGH**: 30 rules (27.78%)
- **MEDIUM**: 26 rules (24.07%)

### **5. Autofix Availability**

Only a small fraction of rules provide automated fix suggestions. This is expected — most security rules require context-dependent remediation that cannot be safely automated with a pattern-based replacement.

- **Has Autofix (`True`)**: 13 rules (12.04%)
- **No Autofix (`False`)**: 95 rules (87.96%)

### **6. OWASP ASVS Mapping Coverage**

About a third of rules include OWASP Application Security Verification Standard (ASVS) mappings, linking each rule to a specific, verifiable security control. This is useful for compliance-driven auditing.

- **Has ASVS (`True`)**: 32 rules (29.63%)
- **No ASVS (`False`)**: 76 rules (70.37%)

### **7. Top CWE Identifiers**

The CWE distribution reveals the most commonly targeted vulnerability classes. SQL Injection (CWE-89) leads with 11 rules, followed by cryptographic weaknesses (CWE-327, CWE-326) and XML External Entities (CWE-611). The dataset spans **40 unique CWE identifiers** across 104 total mentions.

| CWE | Count | Description |
| :--- | :---: | :--- |
| CWE-89 | 11 | SQL Injection |
| CWE-327 | 10 | Use of Broken Cryptographic Algorithm |
| CWE-611 | 9 | XXE (XML External Entities) |
| CWE-326 | 7 | Inadequate Encryption Strength |
| CWE-78 | 5 | OS Command Injection |
| CWE-94 | 5 | Code Injection |
| CWE-200 | 5 | Exposure of Sensitive Information |
| CWE-328 | 4 | Use of Weak Hash |
| CWE-502 | 4 | Deserialization of Untrusted Data |
| CWE-79 | 4 | Cross-Site Scripting (XSS) |

### **8. Top OWASP Top 10 Mappings**

Rules are mapped to multiple OWASP Top 10 versions (2017, 2021, 2025), enabling cross-version risk tracking. Injection-related categories dominate, appearing in both the 2021 and 2025 editions.

| OWASP | Count |
| :--- | :---: |
| A03:2021 - Injection | 37 |
| A05:2025 - Injection | 37 |
| A02:2021 - Cryptographic Failures | 28 |
| A04:2025 - Cryptographic Failures | 28 |
| A03:2017 - Sensitive Data Exposure | 27 |
| A01:2017 - Injection | 20 |
| A01:2025 - Broken Access Control | 13 |
| A01:2021 - Broken Access Control | 12 |

Total: **27 unique OWASP mappings** across 269 mentions.

### **9. Rules by Framework/Library**

The majority of rules target core Java language patterns, applicable to any Java project. Spring-specific rules account for about 14% of the corpus, covering framework-specific concerns like SpEL injection, CSRF misconfiguration, and actuator exposure. Servlet rules are a small but focused set covering cookie security and HTTP method constraints.

| Framework | Count | Percentage |
| :--- | :---: | :---: |
| **lang** (core Java) | 90 | 83.33% |
| **spring** | 15 | 13.89% |
| **servlets** | 3 | 2.78% |

### **10. Category vs. Severity**

Almost all `ERROR`-severity rules belong to the `security` category, confirming that Semgrep reserves its highest severity for security-critical findings. The 3 `ERROR`-level correctness rules flag logic bugs like self-comparison (`$X == $X`) and assignment-in-condition.

| Category | ERROR | WARNING | INFO | Total |
| :--- | :---: | :---: | :---: | :---: |
| **security** | 21 | 80 | 3 | 104 |
| **correctness** | 3 | 1 | 0 | 4 |

### **11. Severity vs. Confidence**

`WARNING`-severity rules are disproportionately `LOW` confidence (43 out of 81), reflecting Semgrep's design choice: most audit-level rules are surfaced as warnings that require human judgment. In contrast, `ERROR`-severity rules are more evenly distributed across confidence levels.

| Severity | LOW | MEDIUM | HIGH | (empty) | Total |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **ERROR** | 3 | 9 | 9 | 3 | 24 |
| **WARNING** | 43 | 16 | 21 | 1 | 81 |
| **INFO** | 2 | 1 | 0 | 0 | 3 |
