# hugogimenez.github.io

Personal portfolio and security projects by Hugo Gimenez — Security Engineer with a background in telecom and network infrastructure, now focused on detection engineering, threat hunting, and security automation.
🌐 Live site: hugogimenez.github.io

Repository Structure
hugogimenez.github.io/
├── index.html                        # Portfolio site
├── static/                           # Assets (CSS, JS, images)
└── projects/
    ├── detection-parser/             # Parse detection rules → CSV
    └── ioc-enricher/                 # Enrich IOCs via threat intel APIs

Security Projects
Detection Parser
Processes a detection rule library in YAML-like format, extracts key fields (name, description, search query, confidence, impact), and exports a structured CSV for audit and coverage gap analysis.
Stack: Python · pandas · regex

IOC Enricher
Batch-enriches IOCs (IPs, domains, hashes) by querying AbuseIPDB, VirusTotal, and AlienVault OTX. Outputs a consolidated CSV with a calculated risk score per indicator.
Stack: Python · requests · pandas

Detection Exporter
Parses a multi-entry YAML-like detection file and exports each detection's fields to a structured CSV. Supports multiline descriptions and search queries. Built to speed up detection library documentation.
Stack: Python · pandas · regex

About

🛡️ Security Engineer at WatchGuard Technologies
📍 Belo Horizonte, MG — Brazil
🎓 CST Cybersecurity · Senac Minas (2024–2027)
📜 Currently pursuing CompTIA CySA+

Connect:
LinkedIn · GitHub · hugomelogimenez@gmail.com
