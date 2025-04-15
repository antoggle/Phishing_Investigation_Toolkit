# 📝 Phishing IOC Triage Report

**Date:** 2025-04-15  
**Analyst:** Anthony Whorton  
**Campaign Name:** Example Credential Phish

---

## 📧 Summary

This report documents the investigation of suspicious domains and IPs tied to a phishing campaign. Indicators were enriched using the VirusTotal API.

---

## 📌 Indicators of Compromise (IOCs)

| Type   | Value              | Verdict    | Malicious | Harmless | Suspicious |
|--------|--------------------|------------|-----------|----------|------------|
| Domain | phishy-login.com   | Malicious  | 23        | 1        | 0          |
| IP     | 192.0.2.123        | Clean      | 0         | 70       | 0          |

---

## 🔍 Enrichment Evidence

### VirusTotal:
- phishy-login.com: https://www.virustotal.com/gui/domain/phishy-login.com
- 192.0.2.123: https://www.virustotal.com/gui/ip-address/192.0.2.123

---

## 🧠 Analysis

- `phishy-login.com` mimics a Microsoft login portal and is flagged by 23 engines.
- IP `192.0.2.123` shows no signs of malicious activity.

---

## 🛡️ Recommendations

- Block malicious domain in email gateway
- Add to IOC watchlists
- Notify security awareness team

---

## 📁 Artifacts

- `enrichment_results.json`
- `screenshots/`
