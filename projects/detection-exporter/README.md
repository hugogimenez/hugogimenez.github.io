detection-exporter
A Python script that parses a detection rule library stored in a YAML-like plain text format and exports each detection's fields to a structured CSV — making it easy to audit, document, and review rules at scale without opening a SIEM.

The Problem
When a detection library grows to dozens or hundreds of rules, reviewing them one by one inside a SIEM becomes slow and error-prone. This script lets you dump all detections into a flat file, extract the key fields, and analyze the full library in a spreadsheet — useful for coverage reviews, documentation, and prioritization.

What it extracts
FieldDescriptionnameDetection rule namedescriptionWhat the rule detects (multiline supported)searchThe query/search logic (multiline, within single quotes)confidenceConfidence score (0–100)impactImpact score (0–100)

Usage
bashpip install pandas
python detection_exporter.py
By default reads detections.txt and writes detections.csv.
Edit INPUT_FILE / OUTPUT_CSV at the top of the script to change paths.

Input format
name: Suspicious PowerShell Encoded Command
description: Detects PowerShell with Base64 encoded commands,
  commonly used to evade detection.
search: 'index=windows EventCode=4688
  CommandLine="*powershell*" CommandLine="*-enc*"'
  confidence: 80
  impact: 90
Output
name,description,search,confidence,impact
Suspicious PowerShell Encoded Command,"Detects PowerShell...","index=windows...",80,90

Author
Hugo Gimenez · Security Engineer
linkedin.com/in/hugogmnz · github.com/hugogimenez
