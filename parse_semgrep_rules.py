#!/usr/bin/env python3
"""
parse_semgrep_rules.py

Parses Semgrep Java YAML rule definitions into a structured CSV dataset.
Zero Dependencies: Built entirely on standard Python 3 modules (re, csv, glob, os).

Output: semgrep_java_rule_dataset.csv
"""

import csv
import glob
import os
import re
import sys


RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rulesets")
OUTPUT_CSV = os.path.join(os.path.dirname(os.path.abspath(__file__)), "semgrep_java_rule_dataset.csv")

COLUMNS = [
    "semgrep_id",
    "severity",
    "category",
    "subcategory",
    "confidence",
    "cwe",
    "owasp",
    "has_asvs",
    "has_fix",
    "rule_file_path",
]


def parse_yaml_rule(filepath):
    """Parse a Semgrep YAML rule file without pyyaml.

    Uses line-by-line parsing to extract only the specific fields we need.
    Works reliably because Semgrep rule YAML files follow a consistent structure.
    """
    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    rules = []
    current_rule = None
    current_section = None  # tracks which metadata list we're collecting
    indent_stack = []

    for line in lines:
        raw = line.rstrip("\n")
        stripped = raw.lstrip()

        # Skip empty lines and comments
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(raw) - len(stripped)

        # New rule starts with "- id:" at the rule level
        if re.match(r"^-\s+id:\s*(.+)", stripped):
            match = re.match(r"^-\s+id:\s*(.+)", stripped)
            if current_rule:
                rules.append(current_rule)
            current_rule = {
                "id": match.group(1).strip().strip("'\""),
                "severity": "",
                "category": "",
                "subcategory": [],
                "confidence": "",
                "cwe": [],
                "owasp": [],
                "has_asvs": False,
                "has_fix": False,
            }
            current_section = None
            continue

        if current_rule is None:
            continue

        # Top-level rule fields (severity, mode, fix, fix-regex)
        m = re.match(r"^\s+severity:\s*(.+)", raw)
        if m:
            current_rule["severity"] = m.group(1).strip().strip("'\"")
            current_section = None
            continue

        # Check for fix: or fix-regex: (just presence)
        if re.match(r"^\s+fix:\s*", raw) or re.match(r"^\s+fix-regex:\s*", raw):
            current_rule["has_fix"] = True
            current_section = None
            continue

        # Metadata fields
        m = re.match(r"^\s+category:\s*(.+)", raw)
        if m:
            current_rule["category"] = m.group(1).strip().strip("'\"")
            current_section = None
            continue

        m = re.match(r"^\s+confidence:\s*(.+)", raw)
        if m:
            current_rule["confidence"] = m.group(1).strip().strip("'\"")
            current_section = None
            continue

        # Section headers for list fields
        if re.match(r"^\s+subcategory:\s*$", raw):
            current_section = "subcategory"
            continue

        if re.match(r"^\s+cwe:\s*$", raw):
            current_section = "cwe"
            continue

        if re.match(r"^\s+owasp:\s*$", raw):
            current_section = "owasp"
            continue

        if re.match(r"^\s+asvs:\s*$", raw) or re.match(r"^\s+asvs:\s*\S", raw):
            current_rule["has_asvs"] = True
            current_section = None
            continue

        # Inline single-value for cwe (e.g., "cwe: CWE-123")
        m = re.match(r"^\s+cwe:\s*['\"]?(CWE-\d+.*)$", raw)
        if m:
            current_rule["cwe"].append(m.group(1).strip().strip("'\""))
            current_section = None
            continue

        # Inline single-value for subcategory
        m = re.match(r"^\s+subcategory:\s*\[(.+)\]", raw)
        if m:
            items = [x.strip().strip("'\"") for x in m.group(1).split(",")]
            current_rule["subcategory"].extend(items)
            current_section = None
            continue

        # List items under current section
        m = re.match(r"^\s+-\s+(.+)", raw)
        if m and current_section:
            value = m.group(1).strip().strip("'\"")
            if current_section == "cwe":
                current_rule["cwe"].append(value)
            elif current_section == "owasp":
                current_rule["owasp"].append(value)
            elif current_section == "subcategory":
                current_rule["subcategory"].append(value)
            continue

        # Any non-list, non-continuation line resets the section
        if not stripped.startswith("-") and ":" in stripped:
            # Check if this is a new key (not a list continuation)
            if current_section and indent <= 4:
                pass  # could be nested key, don't reset prematurely
            if re.match(r"^\s+\w[\w-]*:\s*", raw) and current_section:
                # New key at same or higher level means section ended
                current_section = None

    # Don't forget the last rule
    if current_rule:
        rules.append(current_rule)

    return rules


def extract_cwe_ids(cwe_list):
    """Extract just the CWE IDs from full CWE strings.

    Input:  ['CWE-22: Improper Limitation of a Pathname...']
    Output: 'CWE-22'
    """
    ids = []
    for entry in cwe_list:
        match = re.match(r"(CWE-\d+)", str(entry))
        if match:
            ids.append(match.group(1))
    return ";".join(ids)


def find_yaml_files(rules_dir):
    """Find all .yaml rule files, excluding .test.yaml files."""
    pattern = os.path.join(rules_dir, "**", "*.yaml")
    all_files = glob.glob(pattern, recursive=True)
    filtered = [f for f in all_files if not f.endswith(".test.yaml")]
    return sorted(filtered)


def main():
    if not os.path.isdir(RULES_DIR):
        print(f"Error: Rulesets directory not found: {RULES_DIR}")
        sys.exit(1)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    yaml_files = find_yaml_files(RULES_DIR)
    print(f"Found {len(yaml_files)} YAML rule files in {RULES_DIR}")

    rows = []
    parse_errors = 0

    for yaml_path in yaml_files:
        try:
            rules = parse_yaml_rule(yaml_path)
        except Exception as e:
            print(f"  WARN: Could not parse {yaml_path}: {e}")
            parse_errors += 1
            continue

        rel_path = os.path.relpath(yaml_path, base_dir)

        for rule in rules:
            row = {
                "semgrep_id": rule["id"],
                "severity": rule["severity"],
                "category": rule["category"],
                "subcategory": ";".join(rule["subcategory"]),
                "confidence": rule["confidence"],
                "cwe": extract_cwe_ids(rule["cwe"]),
                "owasp": ";".join(rule["owasp"]),
                "has_asvs": str(rule["has_asvs"]),
                "has_fix": str(rule["has_fix"]),
                "rule_file_path": rel_path,
            }
            rows.append(row)

    # Write CSV
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nDataset generated: {OUTPUT_CSV}")
    print(f"  Total rules extracted: {len(rows)}")
    print(f"  Parse errors: {parse_errors}")
    print(f"  Columns: {', '.join(COLUMNS)}")


if __name__ == "__main__":
    main()
