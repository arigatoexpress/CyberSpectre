import os
import sys
import subprocess
import json
import shutil
import re
from pathlib import Path
from typing import List, Dict


def run_command(cmd: List[str]) -> Dict[str, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return {"cmd": " ".join(cmd), "stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"cmd": " ".join(cmd), "error": str(e)}


def scan_with_clamav(path: str) -> Dict[str, str]:
    if shutil.which("clamscan"):
        return run_command(["clamscan", "-r", path])
    return {"error": "clamscan not installed"}


def scan_with_nmap(target: str) -> Dict[str, str]:
    if shutil.which("nmap"):
        return run_command(["nmap", "-sV", target])
    return {"error": "nmap not installed"}


def scan_windows_defender(path: str) -> Dict[str, str]:
    defender = shutil.which("powershell")
    if defender and os.name == "nt":
        cmd = ["powershell", "-Command", f"Start-MpScan -ScanPath {path}"]
        return run_command(cmd)
    return {"error": "Windows Defender not available"}


def find_sensitive_files(base_path: Path) -> List[str]:
    keywords = [re.compile(k, re.IGNORECASE) for k in ["password", "secret", "confidential", "private"]]
    sensitive = []
    for root, _, files in os.walk(base_path):
        for name in files:
            for kw in keywords:
                if kw.search(name):
                    sensitive.append(str(Path(root) / name))
                    break
    return sensitive


def aggregate_score(results: Dict[str, Dict[str, str]]) -> int:
    score = 100
    for key, r in results.items():
        if not isinstance(r, dict):
            continue
        if r.get("returncode", 0) != 0 or r.get("error"):
            score -= 10
    return max(score, 0)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="CyberSpectre - simple security overview tool")
    parser.add_argument("--target", default="localhost", help="Target host for network scanning")
    parser.add_argument("--scan-path", default=str(Path.home()), help="Path to scan for malware")
    parser.add_argument("--report", default="cyber_report.json", help="Output report file")

    args = parser.parse_args()

    report = {}
    if os.name == "nt":
        report["defender"] = scan_windows_defender(args.scan_path)
    else:
        report["clamav"] = scan_with_clamav(args.scan_path)

    report["nmap"] = scan_with_nmap(args.target)

    sensitive_files = find_sensitive_files(Path(args.scan_path))
    report["sensitive_files"] = sensitive_files

    report["score"] = aggregate_score(report)

    with open(args.report, "w") as fh:
        json.dump(report, fh, indent=2)

    print(f"Report written to {args.report}")
    print(json.dumps({"score": report["score"], "findings": len(sensitive_files)}, indent=2))


if __name__ == "__main__":
    main()
