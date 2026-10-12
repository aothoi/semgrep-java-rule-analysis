#!/usr/bin/env python3
"""
semgrep_rule_dataset_analyzer.py

Performs exploratory data analysis on the Semgrep Java rule dataset.
Zero external dependencies — uses only Python standard library (csv, collections).

Input:  semgrep_java_rule_dataset.csv
Output: semgrep_java_rule_analysis_report.md (+ console output)
"""

import csv
import os
from collections import Counter, defaultdict

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_CSV = os.path.join(SCRIPT_DIR, "semgrep_java_rule_dataset.csv")
OUTPUT_REPORT = os.path.join(SCRIPT_DIR, "semgrep_java_rule_analysis_report.md")


def load_dataset(csv_path):
    """Load the CSV dataset into a list of dicts."""
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader)


def distribution(rows, column, title, report_lines):
    """Compute and print a distribution table for a single column."""
    counter = Counter()
    for row in rows:
        val = row[column].strip() if row[column] else "(empty)"
        counter[val] += 1

    total = len(rows)
    report_lines.append(f"### {title}")
    report_lines.append("")
    report_lines.append("| Value | Count | Percentage |")
    report_lines.append("|-------|------:|----------:|")

    for val, count in counter.most_common():
        pct = (count / total) * 100
        report_lines.append(f"| {val} | {count} | {pct:.2f}% |")

    report_lines.append("")
    print(f"\n--- {title} ---")
    for val, count in counter.most_common():
        pct = (count / total) * 100
        print(f"  {val}: {count} ({pct:.2f}%)")


def boolean_distribution(rows, column, title, report_lines):
    """Distribution for True/False columns."""
    counter = Counter()
    for row in rows:
        counter[row[column]] += 1

    total = len(rows)
    report_lines.append(f"### {title}")
    report_lines.append("")
    report_lines.append("| Value | Count | Percentage |")
    report_lines.append("|-------|------:|----------:|")

    for val in ["True", "False"]:
        count = counter.get(val, 0)
        pct = (count / total) * 100
        report_lines.append(f"| {val} | {count} | {pct:.2f}% |")

    report_lines.append("")
    print(f"\n--- {title} ---")
    for val in ["True", "False"]:
        count = counter.get(val, 0)
        pct = (count / total) * 100
        print(f"  {val}: {count} ({pct:.2f}%)")


def multi_value_distribution(rows, column, title, report_lines, delimiter=";"):
    """Distribution for semicolon-separated multi-value columns (CWE, OWASP)."""
    counter = Counter()
    for row in rows:
        val = row[column].strip() if row[column] else ""
        if not val:
            continue
        for item in val.split(delimiter):
            item = item.strip()
            if item:
                counter[item] += 1

    total_mentions = sum(counter.values())
    report_lines.append(f"### {title}")
    report_lines.append(f"")
    report_lines.append(f"Total unique values: {len(counter)} | Total mentions: {total_mentions}")
    report_lines.append("")
    report_lines.append("| Value | Count |")
    report_lines.append("|-------|------:|")

    for val, count in counter.most_common(20):
        report_lines.append(f"| {val} | {count} |")

    if len(counter) > 20:
        report_lines.append(f"| ... ({len(counter) - 20} more) | |")

    report_lines.append("")
    print(f"\n--- {title} (Top 15) ---")
    for val, count in counter.most_common(15):
        print(f"  {val}: {count}")
    if len(counter) > 15:
        print(f"  ... and {len(counter) - 15} more unique values")


def cross_tabulation(rows, row_col, col_col, title, report_lines):
    """Cross-tabulation between two categorical columns."""
    table = defaultdict(Counter)
    col_values = set()

    for row in rows:
        r_val = row[row_col].strip() if row[row_col] else "(empty)"
        c_val = row[col_col].strip() if row[col_col] else "(empty)"
        table[r_val][c_val] += 1
        col_values.add(c_val)

    col_values = sorted(col_values)
    row_keys = sorted(table.keys())

    report_lines.append(f"### {title}")
    report_lines.append("")

    header = f"| {row_col} \\ {col_col} | " + " | ".join(col_values) + " | Total |"
    separator = "|" + "---|" * (len(col_values) + 2)
    report_lines.append(header)
    report_lines.append(separator)

    print(f"\n--- {title} ---")
    col_width = max(len(v) for v in col_values) if col_values else 8
    print(f"  {'':20s} " + " ".join(f"{v:>{col_width}}" for v in col_values) + f" {'Total':>6}")

    for r_key in row_keys:
        counts = [table[r_key].get(cv, 0) for cv in col_values]
        total = sum(counts)
        row_str = f"| {r_key} | " + " | ".join(str(c) for c in counts) + f" | {total} |"
        report_lines.append(row_str)
        print(f"  {r_key:20s} " + " ".join(f"{c:>{col_width}}" for c in counts) + f" {total:>6}")

    report_lines.append("")


def framework_analysis(rows, report_lines):
    """Derive framework/library from file path and analyze distribution."""
    counter = Counter()
    for row in rows:
        path = row["rule_file_path"]
        # Path format: rulesets/<framework>/<category>/...
        parts = path.split(os.sep)
        if len(parts) >= 2:
            framework = parts[1]  # e.g., 'lang', 'spring', 'android'
        else:
            framework = "(unknown)"
        counter[framework] += 1

    total = len(rows)
    title = "Rules by Framework/Library (derived from file path)"
    report_lines.append(f"### {title}")
    report_lines.append("")
    report_lines.append("| Framework | Count | Percentage |")
    report_lines.append("|-----------|------:|----------:|")

    print(f"\n--- {title} ---")
    for val, count in counter.most_common():
        pct = (count / total) * 100
        report_lines.append(f"| {val} | {count} | {pct:.2f}% |")
        print(f"  {val}: {count} ({pct:.2f}%)")

    report_lines.append("")


def severity_vs_confidence(rows, report_lines):
    """Analyze confidence distribution within each severity level."""
    table = defaultdict(Counter)
    for row in rows:
        sev = row["severity"].strip() if row["severity"] else "(empty)"
        conf = row["confidence"].strip() if row["confidence"] else "(empty)"
        table[sev][conf] += 1

    confidence_levels = ["LOW", "MEDIUM", "HIGH", "(empty)"]
    severity_levels = ["ERROR", "WARNING", "INFO"]

    report_lines.append("### Severity vs. Confidence")
    report_lines.append("")
    header = "| Severity \\ Confidence | " + " | ".join(confidence_levels) + " | Total |"
    separator = "|" + "---|" * (len(confidence_levels) + 2)
    report_lines.append(header)
    report_lines.append(separator)

    print(f"\n--- Severity vs. Confidence ---")
    print(f"  {'':12s} " + " ".join(f"{v:>8}" for v in confidence_levels) + f" {'Total':>6}")

    for sev in severity_levels:
        if sev not in table:
            continue
        counts = [table[sev].get(cl, 0) for cl in confidence_levels]
        total = sum(counts)
        row_str = f"| {sev} | " + " | ".join(str(c) for c in counts) + f" | {total} |"
        report_lines.append(row_str)
        print(f"  {sev:12s} " + " ".join(f"{c:>8}" for c in counts) + f" {total:>6}")

    report_lines.append("")


def main():
    if not os.path.isfile(INPUT_CSV):
        print(f"Error: Dataset not found: {INPUT_CSV}")
        print("Run parse_semgrep_rules.py first to generate the dataset.")
        return

    rows = load_dataset(INPUT_CSV)
    total = len(rows)

    print("=" * 60)
    print("  Semgrep Java Rule Dataset Analysis")
    print("=" * 60)
    print(f"  Total rules: {total}")
    print(f"  Dataset: {INPUT_CSV}")

    report = []
    report.append("# Semgrep Java Rule Analysis Report")
    report.append("")
    report.append(f"**Total rules analyzed: {total}**")
    report.append("")
    report.append("---")
    report.append("")

    # 1. Severity Distribution
    distribution(rows, "severity", "1. Severity Distribution", report)

    # 2. Category Distribution
    distribution(rows, "category", "2. Category Distribution", report)

    # 3. Subcategory Distribution
    distribution(rows, "subcategory", "3. Subcategory Distribution", report)

    # 4. Confidence Distribution
    distribution(rows, "confidence", "4. Confidence Distribution", report)

    # 5. Has Fix Distribution
    boolean_distribution(rows, "has_fix", "5. Autofix Availability", report)

    # 6. Has ASVS Distribution
    boolean_distribution(rows, "has_asvs", "6. OWASP ASVS Mapping Coverage", report)

    # 7. CWE Distribution (top values)
    multi_value_distribution(rows, "cwe", "7. CWE Distribution (Top 20)", report)

    # 8. OWASP Distribution (top values)
    multi_value_distribution(rows, "owasp", "8. OWASP Top 10 Mapping Distribution (Top 20)", report)

    # 9. Framework/Library Distribution
    framework_analysis(rows, report)

    # 10. Category vs. Severity Cross-Tabulation
    cross_tabulation(rows, "category", "severity", "10. Category vs. Severity", report)

    # 11. Category vs. Subcategory Cross-Tabulation
    cross_tabulation(rows, "category", "subcategory", "11. Category vs. Subcategory", report)

    # 12. Severity vs. Confidence
    severity_vs_confidence(rows, report)

    # 13. Severity vs. Has Fix
    cross_tabulation(rows, "severity", "has_fix", "13. Severity vs. Autofix Availability", report)

    # Write report
    with open(OUTPUT_REPORT, "w", encoding="utf-8") as f:
        f.write("\n".join(report))

    print(f"\n{'=' * 60}")
    print(f"  Report exported: {OUTPUT_REPORT}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
