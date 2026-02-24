#!/usr/bin/env python3
"""
Convert codex-security-scan JSON output into a minimal SARIF 2.1.0 file.

Usage:
  python3 json_to_sarif.py findings.json > findings.sarif
"""

import json
import sys

SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: json_to_sarif.py <findings.json>", file=sys.stderr)
        return 2

    with open(sys.argv[1], "r", encoding="utf-8") as handle:
        data = json.load(handle)

    findings = data.get("findings", [])
    rules = {}
    results = []

    for finding in findings:
        if finding.get("status") in ("dismissed",):
            continue

        rule_id = finding.get("id") or "CSS-UNKNOWN"
        title = finding.get("title") or "Security finding"
        severity = (finding.get("severity") or "info").lower()
        level = SEVERITY_TO_LEVEL.get(severity, "note")

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": title},
                "fullDescription": {"text": finding.get("summary") or title},
                "help": {
                    "text": (
                        (finding.get("recommendation") or "").strip()
                        + "\n\nImpact:\n"
                        + (finding.get("impact") or "").strip()
                    ).strip()
                },
                "properties": {
                    "tags": [finding.get("category") or "security"],
                    "security-severity": severity,
                    "confidence": finding.get("confidence", 0.0),
                    "cwe": finding.get("cwe", []),
                },
            }

        locations = []
        for location in finding.get("files", []):
            path = location.get("path")
            if not path:
                continue
            region = {}
            if isinstance(location.get("start_line"), int):
                region["startLine"] = location["start_line"]
            if isinstance(location.get("end_line"), int):
                region["endLine"] = location["end_line"]
            locations.append(
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": path},
                        **({"region": region} if region else {}),
                    }
                }
            )

        message_text = title
        summary = finding.get("summary")
        if summary:
            message_text += f"\n\n{summary}"

        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": message_text},
                **({"locations": locations[:1]} if locations else {}),
                "properties": {
                    "severity": severity,
                    "confidence": finding.get("confidence", 0.0),
                    "status": finding.get("status"),
                    "category": finding.get("category"),
                },
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": data.get("tool", "codex-security-scan"),
                        "informationUri": "https://developers.openai.com/codex/",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    json.dump(sarif, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
