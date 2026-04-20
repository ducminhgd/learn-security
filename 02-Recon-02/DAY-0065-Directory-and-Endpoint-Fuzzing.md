---
title: "Directory and Endpoint Fuzzing — ffuf, dirsearch, feroxbuster, Wordlists"
tags: [recon, active-recon, fuzzing, ffuf, dirsearch, feroxbuster, wordlists, SecLists,
       endpoint-discovery, content-discovery, T1595, bug-bounty]
module: 02-Recon-02
day: 65
related_topics:
  - nmap Service Detection NSE and Evasion (Day 064)
  - Parameter Discovery and JS Analysis (Day 066)
  - Web App Fingerprinting and Tech Stack (Day 067)
  - Burp Suite Setup Proxy Repeater (Day 022)
  - MITRE ATT&CK T1595.003 (Active Scanning: Wordlist Scanning)
---

# Day 065 — Directory and Endpoint Fuzzing

## Goals

By the end of this lesson you will be able to:

1. Explain what content discovery fuzzing is and when to use it in a recon workflow.
2. Set up and run ffuf for directory, file, and parameter fuzzing.
3. Use dirsearch and feroxbuster as alternatives and know when each has an advantage.
4. Select the right wordlist for a given target (technology, context, purpose).
5. Apply response filtering to eliminate false positives and noise.
6. Interpret fuzzing results and identify high-value findings from the output.

---

## Prerequisites

- [Day 022 — Burp Suite Setup, Proxy, Repeater](../01-Foundation-03/DAY-0022-Burp-Suite-Setup-Proxy-Repeater.md)
- [Day 064 — nmap Service Detection, NSE and Evasion](DAY-0064-nmap-Service-Detection-NSE-and-Evasion.md)

---

## Main Content

### 1. What Is Content Discovery?

Port scanning tells you which services are running. Content discovery tells
you what those services expose that is not linked from the homepage.

```
What a user sees (linked):    /login  /about  /products  /contact
What actually exists:         /admin  /backup  /api/v1/users  /config  /.env
                              ↑ Content discovery finds these
```

Web applications routinely have:
- Admin panels not linked from the UI
- Old API versions still running
- Backup files left in the web root
- Debug endpoints enabled in production
- Forgotten test pages

A good fuzzer finds these before you test anything else.

---

### 2. The Ghost Method Applied

#### Recon (Stage 1) — Understand What You Are Looking For

Before running a fuzzer, think:

```
What technology is running?
  → PHP: check .php extensions, wp-admin, /phpinfo.php
  → Java/Spring: check /actuator, /swagger-ui.html, /v2/api-docs
  → Node: check /graphql, /.env, /api/
  → Python/Django: check /admin/, /api/, /schema/
  → Ruby: check /rails/info, /admin, /sidekiq

What is the intended purpose?
  → E-commerce: /admin, /api/v*/products, /checkout
  → SaaS: /api/, /dashboard, /settings, /webhooks
  → Corporate: /intranet, /staff, /hr, /it
```

Choose your wordlist AFTER understanding the target.

---

### 3. ffuf — The Primary Tool

ffuf (Fuzz Faster U Fool) is the standard for web content fuzzing. It is fast,
flexible, and the output is easy to parse.

#### 3.1 Installation

```bash
# From binary release (recommended)
wget https://github.com/ffuf/ffuf/releases/latest/download/ffuf_2.1.0_linux_amd64.tar.gz
tar -xzf ffuf_*.tar.gz
sudo mv ffuf /usr/local/bin/

# Or via Go
go install github.com/ffuf/ffuf/v2@latest
```

#### 3.2 Basic Directory Fuzzing

```bash
# Directory fuzzing — FUZZ is the injection point
ffuf -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt \
     -u https://target.com/FUZZ

# With extension (finds .php, .html, .txt files)
ffuf -w /opt/SecLists/Discovery/Web-Content/raft-medium-words.txt \
     -u https://target.com/FUZZ \
     -e .php,.html,.txt,.xml,.json,.bak,.old

# Append trailing slash (finds directories)
ffuf -w wordlist.txt -u https://target.com/FUZZ/ -e /
```

#### 3.3 Response Filtering — Critical for Reducing Noise

Without filtering, ffuf will return hundreds of false positives. Filter by:

```bash
# Filter by HTTP status code (show only 200, 301, 302, 403)
ffuf -w wordlist.txt -u https://target.com/FUZZ \
     -mc 200,301,302,403

# Filter OUT by status code (hide 404)
ffuf -w wordlist.txt -u https://target.com/FUZZ \
     -fc 404

# Filter by response size (useful when all 404s have the same body size)
ffuf -w wordlist.txt -u https://target.com/FUZZ \
     -fs 1234    # filter out responses with size 1234 bytes

# Filter by word count
ffuf -w wordlist.txt -u https://target.com/FUZZ \
     -fw 12      # filter out responses with 12 words

# Filter by regex in response body
ffuf -w wordlist.txt -u https://target.com/FUZZ \
     -fr "Page Not Found"

# Detect and set custom 404 baseline
# First, request a definitely-not-existing path:
curl -s -o /dev/null -w "%{size_download}" https://target.com/definitely-does-not-exist-1234
# → 4521 bytes
# Then filter that size:
ffuf -w wordlist.txt -u https://target.com/FUZZ -fs 4521
```

#### 3.4 Recursive Fuzzing

```bash
# Automatically fuzz discovered directories recursively
ffuf -w wordlist.txt -u https://target.com/FUZZ \
     -recursion -recursion-depth 3 \
     -mc 200,301,302,403

# Limit recursion to avoid infinite loops
# -recursion-depth 3 → max 3 levels deep
```

#### 3.5 Output Options

```bash
# Save results as JSON (best for parsing)
ffuf -w wordlist.txt -u https://target.com/FUZZ \
     -o results.json -of json

# Save as CSV
ffuf -w wordlist.txt -u https://target.com/FUZZ \
     -o results.csv -of csv

# Show only specific fields
ffuf -w wordlist.txt -u https://target.com/FUZZ \
     -v    # verbose — shows full URL and status for each match
```

#### 3.6 Rate Limiting and Delay

```bash
# Limit request rate (requests per second)
ffuf -w wordlist.txt -u https://target.com/FUZZ -rate 50

# Add delay between requests (milliseconds)
ffuf -w wordlist.txt -u https://target.com/FUZZ -p 0.1

# Set number of concurrent threads (default: 40)
ffuf -w wordlist.txt -u https://target.com/FUZZ -t 10
```

#### 3.7 Authentication and Headers

```bash
# Set cookie (for authenticated fuzzing)
ffuf -w wordlist.txt -u https://target.com/FUZZ \
     -H "Cookie: session=eyJhbGciOiJIUzI1NiJ9..."

# Set Authorization header
ffuf -w wordlist.txt -u https://target.com/FUZZ \
     -H "Authorization: Bearer <token>"

# Multiple headers
ffuf -w wordlist.txt -u https://target.com/FUZZ \
     -H "Cookie: session=abc123" \
     -H "X-Custom-Header: value"
```

---

### 4. Wordlists — Choosing the Right One

The quality of your wordlist determines the quality of your results.

#### 4.1 SecLists — The Standard

```bash
# Install SecLists
git clone https://github.com/danielmiessler/SecLists /opt/SecLists

# Key wordlists for web content discovery:
/opt/SecLists/Discovery/Web-Content/
├── directory-list-2.3-small.txt       # 87,650 words  — quick scan
├── directory-list-2.3-medium.txt      # 220,560 words — standard
├── directory-list-2.3-big.txt         # 1,273,833 words — thorough
├── raft-small-words.txt               # 43,007 words  — case-sensitive paths
├── raft-medium-words.txt              # 63,087 words  — recommended
├── raft-large-words.txt               # 119,600 words — thorough
├── common.txt                         # 4,614 words   — fast initial scan
└── api/
    ├── api-endpoints.txt              # API path patterns
    └── objects.txt                    # Object/resource names
```

#### 4.2 Technology-Specific Wordlists

```bash
# WordPress-specific
/opt/SecLists/Discovery/Web-Content/CMS/wordpress.fuzz.txt

# API-focused
/opt/SecLists/Discovery/Web-Content/api/api-endpoints.txt

# Backup files
/opt/SecLists/Discovery/Web-Content/raft-medium-files.txt

# Parameter names
/opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt

# Spring Boot actuator endpoints
/opt/SecLists/Discovery/Web-Content/spring-boot.txt
```

#### 4.3 Custom Wordlists

Generate target-specific wordlists from the application itself:

```bash
# Extract words from a web application with cewl
cewl https://target.com -d 3 -w custom_wordlist.txt
# -d 3 → spider depth 3 levels
# Combines company-specific terms with generic content

# Add target-specific technical terms manually
echo "wp-admin\nadmin\napi\nv1\nv2\ngraphql" >> custom_wordlist.txt
```

---

### 5. dirsearch

dirsearch is Python-based and easier to configure than ffuf for quick scans.

```bash
# Install
pip install dirsearch
# or
git clone https://github.com/maurosoria/dirsearch

# Basic scan
dirsearch -u https://target.com

# With extensions
dirsearch -u https://target.com -e php,html,txt,xml,json

# Custom wordlist
dirsearch -u https://target.com -w /opt/SecLists/Discovery/Web-Content/raft-medium-words.txt

# Output to file
dirsearch -u https://target.com -o results.txt --format plain

# Exclude status codes
dirsearch -u https://target.com --exclude-status 404,403
```

**When to use dirsearch over ffuf:**
- Quick scans where you want reasonable defaults without configuring filters
- Targets where dirsearch's built-in extension list saves setup time

---

### 6. feroxbuster

feroxbuster (Rust-based) excels at recursive discovery and is fast even
for deep recursive scans.

```bash
# Install
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | \
     bash -s $HOME/.local/bin

# Basic scan
feroxbuster -u https://target.com -w /opt/SecLists/Discovery/Web-Content/raft-medium-words.txt

# Recursive by default — limit depth
feroxbuster -u https://target.com -w wordlist.txt --depth 3

# With extensions
feroxbuster -u https://target.com -w wordlist.txt -x php,html,txt

# Filter by status
feroxbuster -u https://target.com -w wordlist.txt -s 200,301,302,403

# JSON output
feroxbuster -u https://target.com -w wordlist.txt -o results.json --json

# Rate limit
feroxbuster -u https://target.com -w wordlist.txt --rate-limit 50
```

**When to use feroxbuster over ffuf:**
- Deep recursive directory discovery (feroxbuster's recursion is cleaner)
- Large targets with many subdirectories
- When you want auto-tuning (feroxbuster detects and adjusts for 403/wildcard)

---

### 7. Tool Comparison

| Feature | ffuf | dirsearch | feroxbuster |
|---|---|---|---|
| Speed | Fastest | Moderate | Very fast |
| Recursion | Manual (-recursion) | Built-in | Built-in, best |
| Filtering | Most flexible | Basic | Good |
| Setup effort | High (must configure filters) | Low | Low |
| Language | Go | Python | Rust |
| Best for | Complex multi-mode fuzzing | Quick default scans | Recursive discovery |

---

### 8. Common High-Value Findings

After fuzzing, prioritise these categories:

```
Priority 1 — Direct exploit path:
  /.env                  → Database passwords, API keys
  /backup.zip            → Full application source code
  /phpinfo.php           → PHP config, server paths, loaded modules
  /.git/                 → Full git repository exposure
  /config.php.bak        → Config file backup

Priority 2 — Admin/privileged interfaces:
  /admin/                → Admin panel (try default creds)
  /wp-admin/             → WordPress admin
  /manager/              → Tomcat manager (default: tomcat:tomcat)
  /phpmyadmin/           → Database admin (default: root:)
  /.well-known/          → ACME challenges, security.txt

Priority 3 — API/technical surfaces:
  /api/v1/               → API base path (continue deep fuzzing)
  /actuator/             → Spring Boot health, env, beans, mappings
  /swagger-ui.html       → Full API documentation
  /v2/api-docs           → OpenAPI spec (Swagger)
  /graphql               → GraphQL endpoint
  /console               → H2 or Jetty console (RCE risk)
```

---

### 9. Lab Exercise

```bash
# Lab: fuzz a local DVWA instance

# Start DVWA
docker run -d -p 80:80 --name dvwa vulnerables/web-dvwa

# Phase 1: quick scan
ffuf -w /opt/SecLists/Discovery/Web-Content/common.txt \
     -u http://localhost/FUZZ \
     -mc 200,301,302 \
     -o dvwa_quick.json -of json

# Phase 2: medium scan with PHP extension
ffuf -w /opt/SecLists/Discovery/Web-Content/raft-medium-words.txt \
     -u http://localhost/FUZZ \
     -e .php,.txt,.bak \
     -mc 200,301,302,403 \
     -fs $(curl -s -o /dev/null -w "%{size_download}" http://localhost/notexist1234) \
     -o dvwa_medium.json -of json

# Phase 3: recursive
feroxbuster -u http://localhost -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt \
     --depth 3 -s 200,301,302,403 -o dvwa_recursive.json --json

# Analyse: what is the most interesting finding?
```

---

## Key Takeaways

1. **Content discovery is not optional in a real recon workflow.** A significant
   proportion of high-severity findings (exposed admin panels, backup files, debug
   endpoints) are only discoverable through fuzzing. They will not appear in links
   or JS files.
2. **Filter noise before analysing results.** A fuzzer without response size or
   word count filtering produces hundreds of false positives. Set a baseline 404
   size first and filter it.
3. **Wordlist selection is a skill.** `directory-list-2.3-medium.txt` is a good
   default. But for a Spring Boot target, `spring-boot.txt` finds `/actuator/env`
   in seconds while the generic list misses it entirely.
4. **Recursive fuzzing is where the interesting findings hide.** Top-level endpoints
   are obvious. What is inside `/api/v2/internal/`? Recursion finds out.
5. **Rate-limit to avoid killing the target.** In bug bounty, DoSing a target is
   a programme violation and potentially a legal issue. Set `-rate 50` as a default
   and only increase if the programme's policy explicitly allows it.

---

## Exercises

### Exercise 1 — Baseline and Filter

1. Fuzz a lab target and observe the output without any filtering.
2. Determine the size of the custom 404 page using: `curl -s -o /dev/null -w "%{size_download}" https://target/doesnotexist`
3. Add `-fs <size>` and re-run. How many results remain?
4. Are there any false positives remaining? How would you filter them?

---

### Exercise 2 — Technology-Aware Scan

On a WordPress lab target (e.g., `docker run wordpress`):

1. Fuzz using the generic `raft-medium-words.txt` wordlist.
2. Then fuzz using `SecLists/Discovery/Web-Content/CMS/wordpress.fuzz.txt`.
3. Which wordlist found more relevant paths? Which found paths the other missed?

---

### Exercise 3 — Authenticated Fuzzing

On a lab target that requires login:

1. Log in using a browser or Burp Suite and copy the session cookie.
2. Run ffuf with the session cookie: `ffuf -w wordlist.txt -u https://target/FUZZ -H "Cookie: session=<value>"`
3. What paths are accessible only with authentication that were hidden during
   unauthenticated fuzzing?

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 064 — nmap Service Detection, NSE and Evasion](DAY-0064-nmap-Service-Detection-NSE-and-Evasion.md)*
*Next: [Day 066 — Parameter Discovery and JS Analysis](DAY-0066-Parameter-Discovery-and-JS-Analysis.md)*
