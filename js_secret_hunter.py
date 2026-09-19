#!/usr/bin/env python3
"""
js_secret_hunter.py

1. Reads a list of JS file URLs from a text file (one URL per line).
2. Downloads each JS file into a local folder.
3. Scans each downloaded file for patterns that commonly indicate
   leaked secrets (API keys, tokens, private keys, etc.).
4. Writes a report (JSON + human-readable text) summarizing findings.

Usage:
    python js_secret_hunter.py -i js_files.txt -o downloaded_js -r report.txt

Notes:
- Only use this against targets you are authorized to test (bug bounty
  scope, your own assets, or an engagement you have permission for).
- Regex-based secret detection produces false positives — always verify
  manually before reporting/using any finding.
"""

import argparse
import concurrent.futures
import json
import os
import re
import sys
import time
from urllib.parse import urlparse

import requests

# ---------------------------------------------------------------------------
# Secret detection patterns
# Each entry: (name, compiled regex)
# Patterns are intentionally broad; expect false positives and verify by hand.
# ---------------------------------------------------------------------------
SECRET_PATTERNS = {
    "AWS Access Key ID": re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Access Key": re.compile(r"(?i)aws(.{0,20})?secret(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Google OAuth Token": re.compile(r"ya29\.[0-9A-Za-z\-_]+"),
    "Firebase URL": re.compile(r"[a-z0-9-]+\.firebaseio\.com"),
    "Slack Token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}"),
    "Slack Webhook": re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]{8,}/B[0-9A-Za-z_]{8,}/[0-9A-Za-z_]{24}"),
    "Stripe API Key": re.compile(r"(?:sk|pk)_(live|test)_[0-9a-zA-Z]{24,}"),
    "GitHub Token": re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}"),
    "GitLab Token": re.compile(r"glpat-[0-9A-Za-z\-_]{20,}"),
    "Generic Bearer Token": re.compile(r"(?i)bearer\s+[a-z0-9\-_.=]{20,}"),
    "JWT": re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}"),
    "Generic API Key": re.compile(r"(?i)(api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\-_]{16,45}['\"]"),
    "Generic Secret": re.compile(r"(?i)(secret|token|passwd|password)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\-_!@#$%^&*]{8,45}['\"]"),
    "Private Key Block": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    "Twilio API Key": re.compile(r"SK[0-9a-fA-F]{32}"),
    "Mailgun API Key": re.compile(r"key-[0-9a-zA-Z]{32}"),
    "Square Access Token": re.compile(r"sq0atp-[0-9A-Za-z\-_]{22}"),
    "PayPal Braintree Token": re.compile(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
    "Heroku API Key": re.compile(r"(?i)heroku(.{0,20})?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]"),
    "Generic Connection String": re.compile(r"(?i)(mongodb|mysql|postgres(?:ql)?|redis)://[^\s'\"]{10,}"),
}

# Lines containing these are almost always noise; skip them to cut false positives.
NOISE_HINTS = ("sourceMappingURL", "//# sourceURL", "webpackJsonp")


def read_urls(path):
    if not os.path.isfile(path):
        print(f"[!] Input file not found: {path}", file=sys.stderr)
        sys.exit(1)
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        urls = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    return urls


def safe_filename_from_url(url, index):
    parsed = urlparse(url)
    base = os.path.basename(parsed.path) or f"file_{index}.js"
    if not base.endswith(".js"):
        base += ".js"
    # Prefix with index + host to avoid collisions when many files share a name
    host = parsed.netloc.replace(":", "_")
    return f"{index:04d}_{host}_{base}"


def download_file(session, url, out_dir, index, timeout=15, retries=2):
    filename = safe_filename_from_url(url, index)
    out_path = os.path.join(out_dir, filename)

    last_error = None
    for attempt in range(retries + 1):
        try:
            resp = session.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0 (compatible; SecretScanner/1.0)"})
            if resp.status_code == 200:
                with open(out_path, "wb") as f:
                    f.write(resp.content)
                return {"url": url, "status": "ok", "path": out_path, "size": len(resp.content)}
            else:
                last_error = f"HTTP {resp.status_code}"
        except requests.RequestException as e:
            last_error = str(e)
        time.sleep(1)

    return {"url": url, "status": "failed", "error": last_error}


def download_all(urls, out_dir, workers=10):
    os.makedirs(out_dir, exist_ok=True)
    results = []
    session = requests.Session()

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(download_file, session, url, out_dir, i): url
            for i, url in enumerate(urls, start=1)
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            status = result["status"]
            if status == "ok":
                print(f"[+] Downloaded: {result['url']} ({result['size']} bytes)")
            else:
                print(f"[-] Failed: {result['url']} ({result.get('error')})")
            results.append(result)

    return results


def scan_file_for_secrets(filepath):
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError as e:
        return findings

    for lineno, line in enumerate(lines, start=1):
        if any(hint in line for hint in NOISE_HINTS):
            continue
        for name, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(line):
                snippet = match.group(0)
                if len(snippet) > 120:
                    snippet = snippet[:120] + "..."
                findings.append({
                    "type": name,
                    "line": lineno,
                    "match": snippet,
                })
    return findings


def scan_all(download_results):
    report = []
    for result in download_results:
        if result["status"] != "ok":
            continue
        findings = scan_file_for_secrets(result["path"])
        if findings:
            report.append({
                "url": result["url"],
                "file": result["path"],
                "findings": findings,
            })
            print(f"[!] {len(findings)} potential secret(s) found in {result['url']}")
    return report


def write_report(report, download_results, report_path):
    json_path = report_path.rsplit(".", 1)[0] + ".json"

    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(report, jf, indent=2)

    with open(report_path, "w", encoding="utf-8") as tf:
        tf.write("JS Secret Scan Report\n")
        tf.write("=" * 60 + "\n\n")

        total_files = len(download_results)
        ok = sum(1 for r in download_results if r["status"] == "ok")
        failed = total_files - ok
        tf.write(f"Files listed:    {total_files}\n")
        tf.write(f"Downloaded OK:   {ok}\n")
        tf.write(f"Failed:          {failed}\n")
        tf.write(f"Files with hits: {len(report)}\n\n")

        if not report:
            tf.write("No potential secrets found.\n")
        else:
            for entry in report:
                tf.write(f"URL: {entry['url']}\n")
                tf.write(f"File: {entry['file']}\n")
                for finding in entry["findings"]:
                    tf.write(f"  - [{finding['type']}] line {finding['line']}: {finding['match']}\n")
                tf.write("\n")

    print(f"\n[+] Text report: {report_path}")
    print(f"[+] JSON report: {json_path}")


def main():
    parser = argparse.ArgumentParser(description="Download JS files and scan them for leaked secrets.")
    parser.add_argument("-i", "--input", default="js_files.txt", help="Path to file with JS URLs (one per line). Default: js_files.txt")
    parser.add_argument("-o", "--outdir", default="downloaded_js", help="Directory to save downloaded JS files. Default: downloaded_js")
    parser.add_argument("-r", "--report", default="secret_report.txt", help="Path for the text report. Default: secret_report.txt")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Number of concurrent download workers. Default: 10")
    args = parser.parse_args()

    urls = read_urls(args.input)
    if not urls:
        print("[!] No URLs found in input file.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Loaded {len(urls)} URL(s) from {args.input}")
    print(f"[*] Downloading to '{args.outdir}' with {args.workers} workers...\n")

    download_results = download_all(urls, args.outdir, workers=args.workers)

    print("\n[*] Scanning downloaded files for secrets...\n")
    report = scan_all(download_results)

    write_report(report, download_results, args.report)


if __name__ == "__main__":
    main()
