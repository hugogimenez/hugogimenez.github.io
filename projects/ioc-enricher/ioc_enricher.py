"""
ioc_enricher.py
----------------
Given a file with IPs, domains, or file hashes (one per line), queries
free threat intelligence APIs and generates a consolidated enrichment report
in CSV and optionally HTML.

Supported APIs (free tier):
  - AbuseIPDB   → IP reputation
  - VirusTotal  → IP / domain / hash reputation
  - AlienVault OTX → threat intel pulses

Usage:
    python ioc_enricher.py --input iocs.txt --output report.csv

Requirements:
    pip install requests pandas

API keys (free registration):
    - ABUSEIPDB_KEY  → https://www.abuseipdb.com/api
    - VIRUSTOTAL_KEY → https://www.virustotal.com/gui/my-apikey
    - OTX_KEY        → https://otx.alienvault.com/api

Set them as environment variables or in a .env file.

Author: Hugo Gimenez
"""

import re
import os
import csv
import argparse
import requests
import pandas as pd
from datetime import datetime


# ── API KEYS (set via environment variables) ──────────────────────────────────
ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_KEY", "")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY", "")
OTX_KEY        = os.getenv("OTX_KEY", "")

# ── IOC TYPE DETECTION ────────────────────────────────────────────────────────

IP_RE     = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
MD5_RE    = re.compile(r"^[a-fA-F0-9]{32}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def detect_ioc_type(ioc: str) -> str:
    ioc = ioc.strip()
    if IP_RE.match(ioc):
        return "ip"
    if DOMAIN_RE.match(ioc):
        return "domain"
    if SHA256_RE.match(ioc):
        return "sha256"
    if MD5_RE.match(ioc):
        return "md5"
    return "unknown"


# ── ABUSEIPDB ─────────────────────────────────────────────────────────────────

def query_abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_KEY:
        return {"abuseipdb_score": "no_key", "abuseipdb_country": "", "abuseipdb_reports": ""}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
        data = resp.json().get("data", {})
        return {
            "abuseipdb_score":   data.get("abuseConfidenceScore", ""),
            "abuseipdb_country": data.get("countryCode", ""),
            "abuseipdb_reports": data.get("totalReports", ""),
        }
    except Exception as e:
        return {"abuseipdb_score": f"error:{e}", "abuseipdb_country": "", "abuseipdb_reports": ""}


# ── VIRUSTOTAL ────────────────────────────────────────────────────────────────

VT_ENDPOINTS = {
    "ip":     "https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
    "domain": "https://www.virustotal.com/api/v3/domains/{ioc}",
    "sha256": "https://www.virustotal.com/api/v3/files/{ioc}",
    "md5":    "https://www.virustotal.com/api/v3/files/{ioc}",
}


def query_virustotal(ioc: str, ioc_type: str) -> dict:
    if not VIRUSTOTAL_KEY or ioc_type not in VT_ENDPOINTS:
        return {"vt_malicious": "no_key", "vt_suspicious": "", "vt_harmless": ""}
    try:
        url = VT_ENDPOINTS[ioc_type].format(ioc=ioc)
        resp = requests.get(
            url,
            headers={"x-apikey": VIRUSTOTAL_KEY},
            timeout=15,
        )
        stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "vt_malicious":  stats.get("malicious", ""),
            "vt_suspicious": stats.get("suspicious", ""),
            "vt_harmless":   stats.get("harmless", ""),
        }
    except Exception as e:
        return {"vt_malicious": f"error:{e}", "vt_suspicious": "", "vt_harmless": ""}


# ── ALIENVAULT OTX ────────────────────────────────────────────────────────────

OTX_ENDPOINTS = {
    "ip":     "https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/general",
    "domain": "https://otx.alienvault.com/api/v1/indicators/domain/{ioc}/general",
    "sha256": "https://otx.alienvault.com/api/v1/indicators/file/{ioc}/general",
    "md5":    "https://otx.alienvault.com/api/v1/indicators/file/{ioc}/general",
}


def query_otx(ioc: str, ioc_type: str) -> dict:
    if not OTX_KEY or ioc_type not in OTX_ENDPOINTS:
        return {"otx_pulses": "no_key", "otx_malware_families": ""}
    try:
        url = OTX_ENDPOINTS[ioc_type].format(ioc=ioc)
        resp = requests.get(
            url,
            headers={"X-OTX-API-KEY": OTX_KEY},
            timeout=15,
        )
        data = resp.json()
        pulses = data.get("pulse_info", {}).get("count", 0)
        families = ", ".join(
            p.get("name", "") for p in data.get("pulse_info", {}).get("pulses", [])[:3]
        )
        return {"otx_pulses": pulses, "otx_malware_families": families}
    except Exception as e:
        return {"otx_pulses": f"error:{e}", "otx_malware_families": ""}


# ── RISK SCORE ────────────────────────────────────────────────────────────────

def calculate_risk(row: dict) -> str:
    score = 0
    try:
        abuse = int(row.get("abuseipdb_score") or 0)
        if abuse >= 80:
            score += 3
        elif abuse >= 40:
            score += 2
        elif abuse > 0:
            score += 1
    except (ValueError, TypeError):
        pass
    try:
        vt_mal = int(row.get("vt_malicious") or 0)
        if vt_mal >= 10:
            score += 3
        elif vt_mal >= 3:
            score += 2
        elif vt_mal > 0:
            score += 1
    except (ValueError, TypeError):
        pass
    try:
        pulses = int(row.get("otx_pulses") or 0)
        if pulses >= 5:
            score += 2
        elif pulses > 0:
            score += 1
    except (ValueError, TypeError):
        pass

    if score >= 6:
        return "CRITICAL"
    if score >= 4:
        return "HIGH"
    if score >= 2:
        return "MEDIUM"
    if score >= 1:
        return "LOW"
    return "CLEAN"


# ── MAIN ──────────────────────────────────────────────────────────────────────

def enrich(ioc: str) -> dict:
    ioc = ioc.strip()
    ioc_type = detect_ioc_type(ioc)
    result = {"ioc": ioc, "type": ioc_type, "timestamp": datetime.utcnow().isoformat()}

    if ioc_type == "ip":
        result.update(query_abuseipdb(ioc))
    if ioc_type in ("ip", "domain", "sha256", "md5"):
        result.update(query_virustotal(ioc, ioc_type))
        result.update(query_otx(ioc, ioc_type))

    result["risk"] = calculate_risk(result)
    return result


def main():
    parser = argparse.ArgumentParser(description="Enrich IOCs via threat intelligence APIs")
    parser.add_argument("--input",  default="iocs.txt",   help="File with one IOC per line")
    parser.add_argument("--output", default="report.csv", help="Output CSV file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        iocs = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print(f"Enriching {len(iocs)} IOC(s)...")
    results = []
    for ioc in iocs:
        print(f"  → {ioc}")
        results.append(enrich(ioc))

    df = pd.DataFrame(results)
    df.to_csv(args.output, index=False, encoding="utf-8")
    print(f"\nDone. Report saved to: {args.output}")
    print(df[["ioc", "type", "risk"]].to_string(index=False))


if __name__ == "__main__":
    main()
