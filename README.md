# Js_secret_hunter
Good use case — this is a standard recon step in bug bounty work (finding leaked API keys, tokens, credentials in JS bundles). Here's a script that downloads the JS files and scans them for common secret patterns.**Setup:**
```
pip install requests --break-system-packages
```

**Run:**
```
python js_secret_hunter.py -i js_files.txt -o downloaded_js -r secret_report.txt
```

What it does:
- Downloads every URL in `js_files.txt` concurrently (10 workers by default, tweak with `-w`)
- Scans each file against ~20 patterns (AWS keys, GitHub/GitLab tokens, Stripe keys, JWTs, private key blocks, generic `api_key=`/`secret=` assignments, connection strings, etc.)
- Skips noisy lines like sourcemap comments to cut false positives
- Writes both a human-readable `secret_report.txt` and a machine-readable `.json` version

A few notes since this is regex-based:
- Expect false positives, especially on the "Generic Secret" / "Generic API Key" patterns — always manually verify a hit before treating it as a real finding or reporting it
- If a target sits behind auth or rate-limiting, you may need to add cookies/headers to the `requests.Session()` — happy to add that if needed
- Only run this against JS you're authorized to test
