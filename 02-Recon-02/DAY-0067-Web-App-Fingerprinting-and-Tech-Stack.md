---
title: "Web App Fingerprinting and Tech Stack — Wappalyzer, whatweb, Headers, Error Pages"
tags: [recon, fingerprinting, tech-stack, Wappalyzer, whatweb, HTTP-headers, error-pages,
       CME-identification, version-detection, T1592, T1595, bug-bounty]
module: 02-Recon-02
day: 67
related_topics:
  - Parameter Discovery and JS Analysis (Day 066)
  - HTTP Headers and Security Headers (Day 018)
  - Masscan and Fast Network Scanning (Day 068)
  - nmap Service Detection NSE and Evasion (Day 064)
  - MITRE ATT&CK T1592.002 (Gather Victim Host Information: Software)
---

# Day 067 — Web App Fingerprinting and Tech Stack

## Goals

By the end of this lesson you will be able to:

1. Use Wappalyzer and whatweb to fingerprint technology stacks from HTTP responses.
2. Manually extract technology indicators from HTTP headers, cookies, and error pages.
3. Map a fingerprinted stack to known CVEs and attack techniques.
4. Identify the version of a CMS, framework, or library and look it up in NVD/ExploitDB.
5. Explain why fingerprinting matters for attack prioritisation.

---

## Prerequisites

- [Day 018 — HTTP Headers and Security Headers](../01-Foundation-03/DAY-0018-HTTP-Headers-and-Security-Headers.md)
- [Day 066 — Parameter Discovery and JS Analysis](DAY-0066-Parameter-Discovery-and-JS-Analysis.md)

---

## Main Content

### 1. Why Fingerprinting Matters

Generic attacks are noisy and inefficient. Targeted attacks based on confirmed
technology are precise and effective.

```
Without fingerprinting:
  → Try all 500 CVEs from the last 3 years against /login
  → 99.9% miss; target logs fill with noise
  → You get blocked or banned

With fingerprinting:
  → Confirm: Nginx 1.18.0 + Django 4.0.2 + PostgreSQL
  → Django 4.0.2 CVE: check CVE-2022-28347 (SQLi in QuerySet.annotate)
  → Test exactly that one thing, cleanly
  → Confirm vulnerability; write report
```

Fingerprinting converts recon into targeted research.

---

### 2. The Ghost Method Applied

#### Recon (Stage 1)

What are we looking for?

```
Application layer:  CMS (WordPress, Drupal, Joomla), Framework (Rails, Django,
                    Spring, Laravel, Express), Custom application
Server layer:       Web server (nginx, Apache, IIS, Caddy)
OS layer:           Linux (which distro), Windows Server
Language:           PHP version, Python version, Java version, Node.js version
Libraries/CDN:      jQuery version, Bootstrap version, React/Vue/Angular
Authentication:     Keycloak, Auth0, custom JWT, SAML
Infrastructure:     AWS (CloudFront, ALB), Cloudflare, Akamai, Fastly
```

---

### 3. Wappalyzer

Wappalyzer is a technology detection library/browser extension that matches
response content against a database of technology signatures.

#### 3.1 Browser Extension

Install the [Wappalyzer browser extension](https://www.wappalyzer.com/) —
it analyses every page you visit and shows the tech stack in the toolbar.

This is the fastest way to fingerprint when browsing a target manually.

#### 3.2 CLI (wappalyzer-cli)

```bash
# Install
npm install -g wappalyzer-cli
# or
pip install webanalyze   # Go-based faster alternative

# Analyse a URL
wappalyzer https://target.com

# webanalyze (faster, Go-based)
webanalyze -host https://target.com -apps /path/to/technologies.json
```

#### 3.3 webanalyze — Bulk Fingerprinting

```bash
# Install
go install github.com/rverton/webanalyze/cmd/webanalyze@latest

# Get technology definitions
wget https://raw.githubusercontent.com/AliasIO/wappalyzer/master/src/technologies.json

# Analyse a list of hosts
webanalyze -hosts hosts.txt -apps technologies.json -output json > fingerprints.json

# Analyse a single host
webanalyze -host https://target.com -apps technologies.json
```

**Sample output:**

```json
{
  "hostname": "target.com",
  "apps": [
    {"name": "WordPress", "version": "6.4.1", "categories": ["CMS"]},
    {"name": "PHP", "version": "8.1", "categories": ["Programming languages"]},
    {"name": "nginx", "version": "1.24.0", "categories": ["Web servers"]},
    {"name": "WooCommerce", "version": "8.1.0", "categories": ["Ecommerce"]}
  ]
}
```

This tells you: WordPress 6.4.1 → check for CVEs after 6.4.1; WooCommerce → check for payment bypass bugs.

---

### 4. whatweb

whatweb is a command-line scanner with 1800+ plugins for technology detection.
More granular than Wappalyzer for server-side analysis.

```bash
# Install (Kali/Parrot: already installed)
sudo apt install whatweb
# or
gem install whatweb

# Basic scan
whatweb https://target.com

# Verbose output (shows what each plugin found)
whatweb -v https://target.com

# Aggressive mode (makes more requests to improve detection)
whatweb -a 3 https://target.com
# -a 1: passive (default headers only)
# -a 2: moderate (one extra request per plugin)
# -a 3: aggressive (makes requests to multiple URLs)
# -a 4: heavy (follows redirects, spiders pages)

# Scan a list of targets
whatweb -i hosts.txt --log-json=results.json

# Set log format
whatweb -v --log-brief=results.txt https://target.com
```

**Sample output:**

```
https://target.com [200 OK]
Bootstrap[4.6.0],
Country[UNITED STATES][US],
Email[contact@target.com],
HTML5,
HTTPServer[Ubuntu Linux][nginx/1.24.0],
IP[104.21.45.67],
JQuery[3.6.0],
MetaGenerator[WordPress 6.4.1],
PHP[8.1.25],
Script,
Title[Target Corp — Online Store],
WordPress[6.4.1],
X-Powered-By[PHP/8.1.25]
```

---

### 5. Manual Header Analysis

HTTP headers are a rich source of fingerprint data. You do not need any tool —
just curl.

```bash
# Retrieve headers only
curl -sI https://target.com

# Follow redirects, headers only
curl -sIL https://target.com

# Show headers + body
curl -si https://target.com | head -50
```

#### 5.1 High-Value Headers

```
Server: nginx/1.24.0
  → Web server and version

X-Powered-By: PHP/8.1.25
  → Backend language and version — should be removed in production but often is not

X-AspNet-Version: 4.0.30319
  → ASP.NET version — instantly identifies .NET stack

X-Generator: Drupal 10 (https://www.drupal.org)
  → CMS identification — Drupal includes this by default

Set-Cookie: PHPSESSID=...
  → PHP session → PHP backend confirmed

Set-Cookie: JSESSIONID=...
  → Java session → Java/Tomcat/Spring backend

Set-Cookie: _rails_session=...
  → Ruby on Rails backend

Set-Cookie: ci_session=...
  → CodeIgniter PHP framework

X-CF-Powered-By: CF-Worker
  → Cloudflare Worker (edge compute)

CF-Ray: 7d9e3a1b8c2f4e5a-LAX
  → Cloudflare CDN (with PoP location)

X-Amz-Request-Id: ...
X-Amzn-Requestid: ...
  → AWS infrastructure (ALB, API Gateway)

Via: 1.1 varnish (Varnish/6.6)
  → Varnish cache layer
```

#### 5.2 Cookie Analysis

```bash
curl -sc cookies.txt https://target.com -o /dev/null
cat cookies.txt
```

```
# Cookie name signals:
PHPSESSID       → PHP
JSESSIONID      → Java (Tomcat/Jetty/Spring)
ASP.NET_SessionId → ASP.NET
_rails_session  → Ruby on Rails
laravel_session → Laravel (PHP)
django_session  → Django (Python)
connect.sid     → Express.js (Node.js)
```

#### 5.3 Error Page Fingerprinting

Trigger intentional errors and analyse the response:

```bash
# 404 error — server may reveal itself
curl -s https://target.com/does_not_exist_xyz123

# Method not allowed
curl -s -X DELETE https://target.com/api/endpoint

# Malformed request
curl -s "https://target.com/api/data?id='"

# PHP errors
curl -s "https://target.com/api/data?id[]=1"   # Pass array where string expected
```

**What error pages reveal:**

```
Apache Tomcat/9.0.52 error page → Java + Tomcat 9.0.52
Spring Whitelabel Error Page → Spring Boot
Python Traceback → Python app + file paths + installed modules
Rails error page → Ruby on Rails + file paths + gems
Nginx 404 page → nginx version in footer
IIS error page → IIS version + Windows Server version
```

---

### 6. CMS-Specific Fingerprinting

#### WordPress

```bash
# Version from meta tag
curl -s https://target.com | grep 'generator.*WordPress'
# → <meta name="generator" content="WordPress 6.4.1" />

# Version from readme file
curl -s https://target.com/readme.html | grep -i version

# Login page
curl -sI https://target.com/wp-login.php

# XML-RPC (often exploitable)
curl -sI https://target.com/xmlrpc.php

# Enumerate plugins (passive, from HTML source)
curl -s https://target.com | grep -oP '/wp-content/plugins/[^/]+' | sort -u

# wpscan — dedicated WordPress scanner
wpscan --url https://target.com --enumerate vp,vt,u
```

#### Drupal

```bash
# Version from meta tag
curl -s https://target.com | grep 'generator.*Drupal'

# Version from CHANGELOG
curl -s https://target.com/CHANGELOG.txt | head -5

# Check for Drupalgeddon2 (CVE-2018-7600)
curl -s "https://target.com/?q=user/password&name[%23post_render][]=passthru&name[%23type]=markup&name[%23markup]=id"
```

#### Joomla

```bash
# Version from manifest
curl -s https://target.com/administrator/manifests/files/joomla.xml | grep -i version

# Joomla admin panel
curl -sI https://target.com/administrator/
```

---

### 7. Mapping Fingerprint to Attack Surface

After fingerprinting, translate findings into specific things to test:

```
Technology          Version      What to check
──────────────────  ───────────  ─────────────────────────────────────────────
WordPress           < 6.4.2      CVE-2023-6633, CVE-2024-1354 — check NVD
                    Any          /wp-json/wp/v2/users — user enumeration
                                 xmlrpc.php — auth brute force, XXE
                                 /wp-content/uploads — exec permissions?

PHP                 8.0.x        CVE-2021-21702 (null ptr in SNMP ext)
                    < 7.4        Many known RCEs — version matters enormously

Spring Boot         2.x          /actuator/env — may expose secrets
                    < 2.7.x      CVE-2022-22965 (Spring4Shell)

Django              < 4.2.x      Check Django Security releases
                    Any          /admin/ — admin panel exists if not removed
                                 DEBUG=True → full stack trace exposure

jQuery              < 3.5.0      CVE-2020-11022, CVE-2020-11023 (XSS)

Nginx               1.x          Check for HTTP Request Smuggling misconfig

Apache              < 2.4.54     CVE-2021-41773, CVE-2021-42013 (path traversal)
```

```bash
# Search NVD for a specific product and version
# https://nvd.nist.gov/vuln/search
# Search: "wordpress" version:6.4.1

# ExploitDB
searchsploit wordpress 6.4
searchsploit spring boot actuator

# Install searchsploit
sudo apt install exploitdb
```

---

### 8. httpx — Bulk Fingerprinting

For large target lists (100+ subdomains), httpx provides fast HTTP probing
with technology fingerprinting.

```bash
# Install
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Probe a list of subdomains and fingerprint
cat subdomains.txt | httpx -tech-detect -title -server -status-code \
    -o httpx_results.json -json

# Filter to only live hosts
cat subdomains.txt | httpx -status-code 200,301,302,403 -o live_hosts.txt

# Full fingerprint with all probes
cat subdomains.txt | httpx \
    -tech-detect \    # Wappalyzer-style detection
    -title \          # Page title
    -server \         # Server header
    -content-length \ # Response body size
    -status-code \    # HTTP status
    -ip \             # Resolved IP
    -follow-redirects \
    -json -o httpx_full.json
```

---

### 9. Complete Fingerprinting Workflow

```bash
#!/bin/bash
# fingerprint.sh — full tech stack fingerprinting
# Usage: ./fingerprint.sh target.com

DOMAIN=$1

echo "=== HTTP Header Analysis ==="
curl -sIL "https://${DOMAIN}" | grep -E "Server:|X-Powered-By:|X-Generator:|Via:|CF-Ray:"

echo ""
echo "=== Cookie Analysis ==="
curl -sc - "https://${DOMAIN}" -o /dev/null 2>/dev/null | awk 'NF'

echo ""
echo "=== whatweb ==="
whatweb -v -a 3 "https://${DOMAIN}" 2>/dev/null

echo ""
echo "=== webanalyze ==="
webanalyze -host "https://${DOMAIN}" -apps /opt/technologies.json 2>/dev/null

echo ""
echo "=== Error page probe ==="
curl -s "https://${DOMAIN}/does_not_exist_xyz_12345" | head -30
```

---

## Key Takeaways

1. **Fingerprinting converts target knowledge into attack efficiency.** Testing
   a WordPress site for Spring4Shell wastes time. Knowing it is WordPress 6.4.1
   takes 30 seconds to cross-reference against the current CVE list.
2. **HTTP headers are the easiest fingerprint source and are often overlooked.**
   `X-Powered-By: PHP/8.1.25` in a response is a gift. Remove it on your own
   systems; use it against targets.
3. **Error pages are intentional information leaks.** Trigger a 404, a 500, and
   a method-not-allowed. Each error page may reveal framework, version, file path,
   and stack trace.
4. **httpx is the right tool for bulk fingerprinting 100+ subdomains.** Running
   whatweb serially against 300 subdomains takes 30 minutes. httpx does it in
   60 seconds.
5. **Always cross-reference fingerprinted versions against NVD and ExploitDB
   before moving to exploitation.** Fingerprinting is only valuable if you act
   on what you find.

---

## Exercises

### Exercise 1 — Header Harvest

Using only `curl -sI`, identify the following for three different targets:

1. Web server name and version
2. Backend language/framework (if disclosed)
3. CDN/proxy in use (if any)
4. Cookie name (and what technology it suggests)

---

### Exercise 2 — whatweb Deep Scan

1. Run `whatweb -a 3 -v https://target.com`.
2. List every technology detected with its version.
3. For each versioned component, search NVD for CVEs in the last 12 months.
4. Which finding has the highest CVSS score? What is the attack vector?

---

### Exercise 3 — Error Page Analysis

1. Visit `https://target.com/does-not-exist-xyz-1234`.
2. Visit `https://target.com/api/data?id='`.
3. Visit `https://target.com/` with `curl -X DELETE`.
4. For each error, document: what technology it reveals, what version information
   is present, and what attack possibilities it opens.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 066 — Parameter Discovery and JS Analysis](DAY-0066-Parameter-Discovery-and-JS-Analysis.md)*
*Next: [Day 068 — Masscan and Fast Network Scanning](DAY-0068-Masscan-and-Fast-Network-Scanning.md)*
