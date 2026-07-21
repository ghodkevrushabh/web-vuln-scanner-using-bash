
Readme · MD
# Web Vulnerability Assessment Tool
 
A lightweight Bash tool that performs a **passive, non-intrusive security audit** of a target website — checking HTTP security headers, SSL/TLS configuration, exposed sensitive files/directories, open ports, and server fingerprinting.
 
> Built as a mini-project for the **PGCP-ITISS** program (Network Defense & Countermeasures module).
 
## Problem Statement
 
Design and implement a lightweight web vulnerability assessment tool that performs automated reconnaissance and security configuration checks on a target website, identifying common misconfigurations (missing security headers, weak SSL/TLS setup, exposed sensitive files, outdated server banners) to help administrators harden their web infrastructure before deployment.
 
This tool is **passive/config-only** — it does not attempt exploitation (no SQLi/XSS injection, no brute force). It is designed for authorized security audits of your own systems or systems you have explicit permission to test.
 
## Features
 
| Module | Checks |
|---|---|
| DNS & Reachability | Resolves domain, confirms HTTPS reachability |
| Port Scan | Common ports (21, 22, 23, 25, 80, 443, 3306, 8080, 8443) |
| HTTP Header Audit | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| Server Fingerprinting | `Server` and `X-Powered-By` header disclosure |
| SSL/TLS Audit | Certificate expiry, deprecated protocol support (SSLv2/v3, TLS 1.0/1.1) |
| Exposure Check | `robots.txt`, `.git/config`, `.env`, `/admin`, backup files, `.htaccess`, etc. |
| Reporting | Consolidated PASS/WARN/FAIL report saved to a timestamped `.txt` file |
 
## Requirements
 
- Bash (Linux/macOS, or WSL on Windows)
- `curl`
- `openssl`
- `nmap` (optional — falls back to `/dev/tcp` checks if not installed)
## Usage
 
```bash
chmod +x vuln_scanner.sh
./vuln_scanner.sh example.com
```
 
Output is printed to the terminal and saved to `vuln_report_<domain>_<timestamp>.txt`.
 
## Sample Output
 
```
[1] DNS & Reachability Check
[PASS] Resolved example.com -> 93.184.216.34
[PASS] Target is reachable over HTTPS
 
[3] HTTP Security Header Audit
[FAIL] Content-Security-Policy header MISSING
[PASS] Strict-Transport-Security header present
...
==================== SUMMARY ====================
Passed checks : 14
Warnings      : 2
Failed checks : 3
==================================================
```
 
## Design / Architecture
 
Linear pipeline, one Bash function per module:
 
```
Input → DNS/Reachability → Port Scan → Header Audit → SSL/TLS Audit → Exposure Check → Report
```
 
## Disclaimer
 
This tool is intended **for educational purposes and authorized security testing only**. Only run it against domains/systems you own or have explicit written permission to test. Unauthorized scanning of third-party systems may violate local laws (e.g., IT Act 2000 in India) and terms of service.
 
## Future Scope
 
- Integrate `nikto` for deeper web-server-specific checks
- Add JSON/HTML report export
- CVE lookup based on detected server banner version
- Rate-limiting/politeness delay for large scans
- GenAi Intergrated Vulenrability Assessment and report generation tool 

  
## Author
Vrushabh Rajkumar Ghodke — PGCP-ITISS, IACSD Pune (Feb 2026 batch)
