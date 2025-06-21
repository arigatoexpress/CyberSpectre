# CyberSpectre

CyberSpectre is a lightweight Python toolkit that integrates common open-source
security tools to give a quick overview of your system.

Features include:
- Optional antivirus scanning using **ClamAV** on macOS/Linux or Windows Defender on Windows.
- Basic port scanning via **nmap** if it is installed.
- Simple search for potentially sensitive files (passwords, secrets, etc.).
- Generates a JSON report with a basic score and findings summary.

## Requirements
- Python 3.8+
- Optional: `nmap`, `clamscan` (for macOS/Linux), or Windows Defender (Windows).

## Usage

```
python3 cyber_spectre.py --scan-path /path/to/scan --target localhost --report report.json
```

The script attempts to run `clamscan` (or Windows Defender) and `nmap` if they
are available on the system. Results and a simple security score are written to
the specified JSON report.

> **Note**: This project is meant for educational purposes and does not replace
> professional malware detection or comprehensive security auditing tools.
