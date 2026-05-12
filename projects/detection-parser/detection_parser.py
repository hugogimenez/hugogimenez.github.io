"""
detection_parser.py
--------------------
Processes a text file containing multiple detection entries in a YAML-like
format. Splits the file into blocks based on lines starting with `name:` and
extracts: name, description, search, confidence, and impact.
Exports the result to a structured CSV for easier analysis.

Usage:
    python detection_parser.py --input detections.txt --output detections.csv

Author: Hugo Gimenez
"""

import re
import argparse
import pandas as pd


def parse_detections(input_file: str) -> list[dict]:
    with open(input_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    current_block = []
    blocks = []

    # Split file into detection blocks
    for line in lines:
        if line.startswith("name:") and current_block:
            blocks.append("".join(current_block))
            current_block = []
        current_block.append(line)

    if current_block:
        blocks.append("".join(current_block))

    entries = []

    for block in blocks:
        # name
        name_match = re.search(r"^name:\s*(.*)", block, re.MULTILINE)
        name = name_match.group(1).strip() if name_match else ""

        # description (multiline YAML-like)
        description = ""
        block_lines = block.splitlines()
        for i, line in enumerate(block_lines):
            if line.startswith("description:"):
                first = line.split("description:")[1].strip()
                desc_lines = [first]
                j = i + 1
                while j < len(block_lines) and (
                    block_lines[j].startswith(" ") or block_lines[j].startswith("\t")
                ):
                    desc_lines.append(block_lines[j].strip())
                    j += 1
                description = "\n".join(desc_lines)
                break

        # search (multiline between single quotes)
        search_match = re.search(r"^search:\s*'(.*?)'", block, re.DOTALL | re.MULTILINE)
        search = search_match.group(1).strip() if search_match else ""

        # confidence and impact
        confidence_match = re.search(r"^\s*confidence:\s*(\d+)", block, re.MULTILINE)
        impact_match = re.search(r"^\s*impact:\s*(\d+)", block, re.MULTILINE)
        confidence = confidence_match.group(1) if confidence_match else ""
        impact = impact_match.group(1) if impact_match else ""

        entries.append({
            "name": name,
            "description": description,
            "search": search,
            "confidence": confidence,
            "impact": impact,
        })

    return entries


def main():
    parser = argparse.ArgumentParser(description="Parse detection entries to CSV")
    parser.add_argument("--input", default="detections.txt", help="Input file path")
    parser.add_argument("--output", default="detections.csv", help="Output CSV path")
    args = parser.parse_args()

    entries = parse_detections(args.input)
    df = pd.DataFrame(entries)
    df.to_csv(args.output, index=False, encoding="utf-8")
    print(f"Done. Extracted {len(df)} detection(s) → {args.output}")


if __name__ == "__main__":
    main()
