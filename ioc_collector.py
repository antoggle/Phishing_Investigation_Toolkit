# ioc_collector.py
# 🕵️ IOC Enrichment Script (Starter)

# This script simulates how a threat analyst might enrich indicators of compromise (IOCs)
# using external tools like VirusTotal, URLScan.io, and Shodan.
# This version is a placeholder with mock functionality to simulate enrichment logic.

import json

# Sample IOCs
iocs = {
    "domains": ["phishy-login.com", "secure-update.net"],
    "ips": ["192.0.2.123", "203.0.113.45"],
    "emails": ["alert@phishy-login.com"]
}

def enrich_with_mock_data(ioc):
    # Simulated enrichment (in real usage, you would call external APIs)
    return {
        "ioc": ioc,
        "vt_result": "malicious" if "phishy" in ioc else "clean",
        "urlscan_found": True if "login" in ioc else False,
        "shodan_open_ports": [80, 443] if "192.0.2.123" in ioc else [22]
    }

def main():
    enriched_results = []

    for ioc_type, values in iocs.items():
        for value in values:
            enriched = enrich_with_mock_data(value)
            enriched["type"] = ioc_type
            enriched_results.append(enriched)

    # Output simulated results to a JSON file
    with open("mock_enrichment_results.json", "w") as f:
        json.dump(enriched_results, f, indent=2)

    print("[+] Mock IOC enrichment complete. Results saved to 'mock_enrichment_results.json'.")

if __name__ == "__main__":
    main()
