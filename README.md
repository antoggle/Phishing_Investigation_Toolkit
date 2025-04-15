# Phishing Investigation Toolkit

## Project Overview and Purpose

Phishing Investigation Toolkit is a Python-based tool for security analysts to streamline the analysis of phishing threats. It focuses on enriching **Indicators of Compromise (IOCs)** – specifically suspicious domain names and IP addresses – using the VirusTotal API. The toolkit automates the retrieval of threat intelligence and outputs the results to a structured JSON file. It also includes a Markdown-based triage report template.

## Features

- IOC enrichment via VirusTotal API
- Uses `.env` file for secure API key storage
- Outputs structured JSON results
- Includes triage report template
- Beginner-friendly and extensible

## Folder Structure

```
phishing-investigation-toolkit/
├── ioc_collector.py
├── triage_report.md
├── enrichment_results.json
├── .env.example
└── README.md
```

## Getting Started

1. Clone the repo
2. Install dependencies:
   ```bash
   pip install requests python-dotenv
   ```
3. Copy `.env.example` to `.env` and add your VirusTotal API key
4. Add your IOCs to `ioc_collector.py` or modify to load from file
5. Run the script:
   ```bash
   python ioc_collector.py
   ```

## Example Usage and Output

The script prints status messages and saves results like:

```json
[
  {
    "ioc": "phishy-login.com",
    "type": "domain",
    "malicious_count": 23,
    "verdict": "Malicious"
  }
]
```

## Screenshots

*Add screenshots of console output or sample report here.*

## Triage Report Format

Includes:
- Summary
- IOC table
- Enrichment evidence
- Analysis & Recommendations

See `triage_report.md` for structure.

## License

MIT License – see `LICENSE` file.

## Contributions

Pull requests welcome. Please:
- Submit clean, tested code
- Follow PEP8 standards
- Open an issue for major changes

Thanks for using the toolkit!
