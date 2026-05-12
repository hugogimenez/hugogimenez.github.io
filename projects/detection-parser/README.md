# detection-parser

A Python script to parse detection rule files in a YAML-like format and export structured data to CSV for analysis, review, or documentation.

Built for SOC/Detection Engineering workflows where detections are stored in plain text and need to be audited or catalogued at scale.

---

## What it does

- Splits a multi-detection file into individual blocks
- Extracts: `name`, `description`, `search`, `confidence`, `impact`
- Handles multiline fields (description blocks, multi-line search queries)
- Exports a clean CSV ready for review in Excel, Google Sheets, or any SIEM import pipeline

---

## Usage

```bash
pip install pandas
python detection_parser.py --input detections.txt --output detections.csv
```

---

## Input format

```
name: Suspicious PowerShell Encoded Command
description: Detects PowerShell with Base64 encoded commands,
  commonly used to evade detection.
search: 'index=windows EventCode=4688
  CommandLine="*powershell*" CommandLine="*-enc*"'
  confidence: 80
  impact: 90
```

## Output (CSV)

| name | description | search | confidence | impact |
|------|-------------|--------|------------|--------|
| Suspicious PowerShell Encoded Command | Detects PowerShell... | index=windows... | 80 | 90 |

---

## Why this exists

When managing a large detection library, it becomes impractical to review rules one by one inside a SIEM. This script lets you dump all detections, extract the key fields, and review/prioritize them as a spreadsheet — useful for detection audits, documentation, and coverage gap analysis.

---

## Author

Hugo Gimenez · Security Engineer  
[linkedin.com/in/hugogmnz](https://linkedin.com/in/hugogmnz) · [github.com/hugogimenez](https://github.com/hugogimenez)
