
"""
Build CWE -> CAPEC mapping review report for crAPI findings.

Uses the offline rule-based engine in llm_mapping.py.
Does not modify the original challenges.csv.
Does not mark candidate mappings as verified.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

MAPPING_DIR = Path(__file__).resolve().parent
REPO_ROOT = MAPPING_DIR.parent

# Allow importing llm_mapping.py from this directory.
if str(MAPPING_DIR) not in sys.path:
    sys.path.insert(0, str(MAPPING_DIR))

from llm_mapping import build_report, check_report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build CWE/CAPEC mapping report for crAPI findings."
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=REPO_ROOT / "findings" / "challenges.csv",
        help="Input findings CSV file.",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=MAPPING_DIR / "cwe_capec_attack.json",
        help="Output JSON report path.",
    )

    parser.add_argument(
        "--check",
        action="store_true",
        help="Validate mappings without writing the JSON report.",
    )

    args = parser.parse_args()

    input_path = args.input.resolve()
    output_path = args.output.resolve()

    try:
        report = build_report(input_path)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: Mapping report could not be built: {error}")
        return 1

    errors = check_report(report)

    if errors:
        print("Mapping validation failed:")
        for error in errors:
            print(f" - {error}")
        return 1

    findings = report["findings"]

    if args.check:
        print(
            f"PASS: {len(findings)} challenge records passed mapping validation."
        )
        print("No candidate mapping was marked as verified.")
        return 0

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open("w", encoding="utf-8") as json_file:
            json.dump(
                report,
                json_file,
                ensure_ascii=False,
                indent=2,
            )
            json_file.write("\n")

    except OSError as error:
        print(f"ERROR: Could not write output JSON: {error}")
        return 1

    print("Mapping report successfully generated.")
    print(f"Input findings : {input_path}")
    print(f"Output report  : {output_path}")
    print(f"Challenge count: {len(findings)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
