"""
detection_exporter.py
----------------------
Processes a text file containing multiple detection entries in a YAML-like
format. Splits the file into blocks based on lines starting with `name:` and
extracts the following fields:

  - name
  - description  (supports multiline content)
  - search       (captured even if it spans multiple lines within single quotes)
  - confidence
  - impact

After extracting the data, compiles it into a structured list and exports
the results to a CSV file for easier analysis.

Usage:
    python detection_exporter.py

    By default reads  detections.txt  and writes  detections.csv
    Edit the INPUT_FILE / OUTPUT_CSV constants below to change paths.

Requirements:
    pip install pandas

Author: Hugo Gimenez
"""

import re
import pandas as pd

INPUT_FILE = "detections.txt"
OUTPUT_CSV = "detections.csv"

# ── READ FILE ─────────────────────────────────────────────────────────────────

with open(INPUT_FILE, "r", encoding="utf-8") as f:
    lines = f.readlines()

# ── SPLIT INTO BLOCKS ─────────────────────────────────────────────────────────
# Each detection starts with a line beginning with "name:"

current_block: list[str] = []
blocks: list[str] = []

for line in lines:
    if line.startswith("name:") and current_block:
        blocks.append("".join(current_block))
        current_block = []
    current_block.append(line)

if current_block:
    blocks.append("".join(current_block))

# ── EXTRACT FIELDS ────────────────────────────────────────────────────────────

entries: list[dict] = []

for block in blocks:

    # name
    name_match = re.search(r"^name:\s*(.*)", block, re.MULTILINE)
    name = name_match.group(1).strip() if name_match else ""

    # description — multiline YAML-like block (indented continuation)
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

    # search — multiline content between single quotes
    search_match = re.search(r"^search:\s*'(.*?)'", block, re.DOTALL | re.MULTILINE)
    search = search_match.group(1).strip() if search_match else ""

    # confidence and impact — may be indented inside a tags block
    confidence_match = re.search(r"^\s*confidence:\s*(\d+)", block, re.MULTILINE)
    impact_match     = re.search(r"^\s*impact:\s*(\d+)",     block, re.MULTILINE)
    confidence = confidence_match.group(1) if confidence_match else ""
    impact     = impact_match.group(1)     if impact_match     else ""

    entries.append({
        "name":        name,
        "description": description,
        "search":      search,
        "confidence":  confidence,
        "impact":      impact,
    })

# ── EXPORT TO CSV ─────────────────────────────────────────────────────────────

df = pd.DataFrame(entries)
df.to_csv(OUTPUT_CSV, index=False, encoding="utf-8")
print(f"Done. Extracted: {len(df)} detection(s) → {OUTPUT_CSV}")
