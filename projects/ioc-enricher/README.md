# ioc-enricher

A Python script that enriches a list of IOCs (IPs, domains, file hashes) by querying multiple free threat intelligence APIs and consolidates the results into a single CSV report with a calculated risk score.

Built for SOC analysts who need to quickly triage a batch of indicators during incident response or threat hunting.

---

## What it does

- Auto-detects IOC type: IPv4, domain, MD5, SHA256
- Queries up to 3 APIs per indicator:
  - **AbuseIPDB** — IP abuse confidence score and report count
  - **VirusTotal** — malicious/suspicious engine detections
  - **AlienVault OTX** — threat intelligence pulse count and malware families
- Calculates a consolidated **risk score**: CRITICAL / HIGH / MEDIUM / LOW / CLEAN
- Exports a full CSV report

---

## Usage

```bash
pip install requests pandas

# Set your API keys (free registration on each platform)
export ABUSEIPDB_KEY="your_key"
export VIRUSTOTAL_KEY="your_key"
export OTX_KEY="your_key"

python ioc_enricher.py --input iocs.txt --output report.csv
```

---

## Input format (`iocs.txt`)

```
# One IOC per line, # for comments
185.220.101.45
malware-c2.example.com
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

---

## Output (CSV)

| ioc | type | abuseipdb_score | vt_malicious | otx_pulses | risk |
|-----|------|-----------------|--------------|------------|------|
| 185.220.101.45 | ip | 97 | 12 | 8 | CRITICAL |
| malware-c2.example.com | domain | — | 5 | 3 | HIGH |

---

## Risk Score Logic

| Condition | Points |
|-----------|--------|
| AbuseIPDB ≥ 80 | +3 |
| AbuseIPDB ≥ 40 | +2 |
| VT malicious ≥ 10 | +3 |
| VT malicious ≥ 3 | +2 |
| OTX pulses ≥ 5 | +2 |

**6+** → CRITICAL · **4-5** → HIGH · **2-3** → MEDIUM · **1** → LOW · **0** → CLEAN

---

## Get free API keys

- AbuseIPDB: https://www.abuseipdb.com/api
- VirusTotal: https://www.virustotal.com/gui/my-apikey
- AlienVault OTX: https://otx.alienvault.com/api

---

## Author

Hugo Gimenez · Security Engineer  
[linkedin.com/in/hugogmnz](https://linkedin.com/in/hugogmnz) · [github.com/hugogimenez](https://github.com/hugogimenez)
