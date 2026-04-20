---
title: "Parameter Discovery and JS Analysis — arjun, paramspider, LinkFinder, JS Mining"
tags: [recon, active-recon, parameter-discovery, JS-analysis, arjun, paramspider,
       LinkFinder, javascript, endpoint-mining, hidden-parameters, T1595, bug-bounty]
module: 02-Recon-02
day: 66
related_topics:
  - Directory and Endpoint Fuzzing (Day 065)
  - Web App Fingerprinting and Tech Stack (Day 067)
  - REST APIs JSON and GraphQL (Day 020)
  - MITRE ATT&CK T1595.003
---

# Day 066 — Parameter Discovery and JS Analysis

## Goals

By the end of this lesson you will be able to:

1. Explain why hidden parameters represent a significant attack surface.
2. Use arjun to discover undocumented GET and POST parameters on a web endpoint.
3. Use paramspider to harvest parameters from a target's URLs via Wayback Machine.
4. Extract endpoints, API paths, and secrets from JavaScript files using
   LinkFinder and manual analysis.
5. Build a parameter and endpoint inventory from JS analysis of a real target.

---

## Prerequisites

- [Day 020 — REST APIs, JSON and GraphQL](../01-Foundation-03/DAY-0020-REST-APIs-JSON-and-GraphQL.md)
- [Day 065 — Directory and Endpoint Fuzzing](DAY-0065-Directory-and-Endpoint-Fuzzing.md)

---

## Main Content

> "Everyone checks the links. Nobody checks what the JavaScript is doing in
> the background. That is where the interesting stuff lives."
>
> — Ghost

### 1. Why Parameters Matter

An endpoint is only half the picture. The other half is what parameters it
accepts — especially the ones it accepts but does not advertise.

```
Visible endpoint:   GET /api/users?id=123
Hidden parameters:  GET /api/users?id=123&debug=true
                    GET /api/users?id=123&internal=1
                    GET /api/users?id=123&admin=true
                    GET /api/users?id=123&role=admin
```

Hidden parameters are:
- **Debug parameters** left in production by developers
- **Internal parameters** used by the mobile app but not the web UI
- **Legacy parameters** from an old version of the API
- **Feature flags** not intended for public use

In bug bounty, hidden parameters regularly lead to:
- IDOR (pass another user's ID via a parameter the UI does not show)
- Privilege escalation (pass `role=admin`)
- Broken access control (pass `admin=1`)
- SSRF (pass `url=` to an endpoint that makes requests)

---

### 2. arjun — Active Parameter Discovery

arjun works by sending the endpoint a request with many candidate parameters
and detecting which ones change the response (size, status, content).

#### 2.1 Installation

```bash
pip install arjun
# or
git clone https://github.com/s0md3v/Arjun && cd Arjun && pip install .
```

#### 2.2 Basic Usage

```bash
# Discover GET parameters on a single URL
arjun -u https://target.com/api/users

# POST parameters
arjun -u https://target.com/api/login -m POST

# JSON body parameters
arjun -u https://target.com/api/data -m JSON

# Headers (pass auth)
arjun -u https://target.com/api/profile \
      --headers "Cookie: session=abc123"

# Increase thread count (default: 25)
arjun -u https://target.com/api/data -t 10

# Use a specific wordlist
arjun -u https://target.com/api/data \
      -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt

# Scan multiple URLs from a file
arjun -i endpoints.txt -m GET

# Output to file
arjun -u https://target.com/api/data -o parameters.json
```

#### 2.3 Interpreting Results

```
[+] Heuristic scan: queueing parameters
[+] Scanning 3168 parameters for GET
[*] Parameter:    debug
    Found at:     https://target.com/api/users?debug=true
    Change type:  Status (200 → 200), Size (+2847 bytes)

[*] Parameter:    internal
    Found at:     https://target.com/api/users?internal=1
    Change type:  Status (200 → 200), Size (+5120 bytes)
```

When arjun finds a parameter that changes the response size, that parameter
is active on the endpoint — even if it is not documented anywhere.

---

### 3. paramspider — Passive Parameter Harvesting

paramspider queries the Wayback Machine (web.archive.org) and other public
sources for historical URLs containing parameters. No traffic to the target.

```bash
# Install
pip install paramspider
# or
git clone https://github.com/devanshbatham/ParamSpider && pip install -e .

# Harvest parameters for a domain
paramspider -d target.com

# Output file
paramspider -d target.com -o params.txt

# Include subdomains
paramspider -d target.com --subs True

# Exclude certain file extensions
paramspider -d target.com --exclude jpg,png,gif,css,woff
```

**What paramspider returns:**

```
https://target.com/search?q=FUZZ
https://target.com/user?id=FUZZ
https://target.com/api/v1/data?callback=FUZZ
https://target.com/redirect?url=FUZZ
```

Notice: paramspider replaces parameter values with `FUZZ`. These are ready
to pipe directly into ffuf for bulk fuzzing.

#### 3.1 Chain paramspider with ffuf

```bash
# Step 1: harvest parameter URLs
paramspider -d target.com -o param_urls.txt

# Step 2: feed into ffuf for XSS/SSRF/IDOR probing
ffuf -w /opt/SecLists/Fuzzing/XSS/XSS-Jhaddix.txt \
     -u "https://target.com/search?q=FUZZ" \
     -mc 200 \
     -v

# Or use a batch mode for multiple URLs
while IFS= read -r url; do
    ffuf -w /opt/SecLists/Fuzzing/SSRF/SSRF-Jhaddix.txt \
         -u "$url" \
         -mc 200 \
         -v -o "results_$(echo $url | md5sum | cut -c1-8).json" -of json
done < param_urls.txt
```

---

### 4. JavaScript File Analysis

Modern web applications ship most of their logic as JavaScript. Inside those
files, you will find:

- API endpoint paths (often undocumented)
- Internal service URLs
- Hardcoded API keys and tokens
- Feature flags and admin paths
- GraphQL queries and mutations

#### 4.1 LinkFinder — Endpoint Extraction

LinkFinder uses regex and abstract syntax tree (AST) analysis to extract URLs
and endpoints from JS files.

```bash
# Install
git clone https://github.com/GerbenJavado/LinkFinder
pip install -r requirements.txt

# Analyse a single JS file
python3 linkfinder.py -i https://target.com/static/app.bundle.js -o cli

# Analyse a URL (crawls the page and extracts JS files)
python3 linkfinder.py -i https://target.com -d

# Output as HTML report
python3 linkfinder.py -i https://target.com/static/app.js -o results.html

# Burp Proxy — analyse all JS files passing through Burp
# (use the Burp Suite extension version of LinkFinder)
```

**Sample output:**

```
/api/v1/users
/api/v2/admin/config
/internal/debug
/api/v1/webhooks/{id}/resend
https://internal-api.target.com/v3/data
ws://ws.target.com:8080/events
```

The paths `/api/v2/admin/config` and `/internal/debug` are goldmines — if
these endpoints exist and are accessible, they are bugs.

#### 4.2 Manual JS Analysis

LinkFinder is good, but manual review of key JS files catches what automated
tools miss.

**Step 1 — Identify JS files to analyse:**

```bash
# From the browser: Developer Tools → Sources → look for bundle.js, app.js, main.js
# Via ffuf:
ffuf -w /opt/SecLists/Discovery/Web-Content/raft-medium-words.txt \
     -u https://target.com/FUZZ.js \
     -mc 200

# Via waybackurls:
waybackurls target.com | grep "\.js$" | sort -u > js_files.txt
```

**Step 2 — Download and beautify:**

```bash
# Download all JS files
cat js_files.txt | while read url; do
    filename=$(basename "$url")
    curl -s "$url" -o "js_files/${filename}"
done

# Beautify minified JS (makes it readable)
npm install -g js-beautify
js-beautify js_files/app.bundle.js > js_files/app.bundle.readable.js
```

**Step 3 — Grep for high-value patterns:**

```bash
# API endpoints
grep -E '"/(api|v[0-9]|internal|admin|graphql)[^"]*"' app.bundle.readable.js

# Hardcoded API keys
grep -E '(api_key|apiKey|API_KEY|secret|token|password)\s*[=:]\s*["\x27][^"\x27]{8,}' \
     app.bundle.readable.js

# URLs (internal services)
grep -E 'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' app.bundle.readable.js | \
     sort -u

# Hardcoded IP addresses
grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' app.bundle.readable.js

# GraphQL queries (structure)
grep -A 10 'gql`\|graphql`\|mutation\|query {' app.bundle.readable.js

# Feature flags / admin checks
grep -E '(isAdmin|role.*admin|userType.*admin|feature\.)' app.bundle.readable.js
```

**Step 4 — Look for hardcoded secrets (truffleHog):**

```bash
# Run truffleHog against a local JS file
trufflehog filesystem ./js_files/ --only-verified

# Or against a URL directly
trufflehog git file://./js_files/
```

---

### 5. Automating JS Discovery

#### 5.1 getJS — Collect JS Files

```bash
# Install
go install github.com/003random/getJS@latest

# Collect all JS files linked from a URL
getJS --url https://target.com --complete --output js_urls.txt

# From a list of URLs
getJS --input endpoints.txt --complete --output js_urls.txt
```

#### 5.2 Full JS Recon Pipeline

```bash
#!/bin/bash
# js_recon.sh — JS endpoint and secret extraction pipeline
# Usage: ./js_recon.sh target.com

DOMAIN=$1
OUTDIR="js_recon_${DOMAIN}"
mkdir -p "$OUTDIR"

echo "[*] Collecting JS files via waybackurls"
waybackurls "$DOMAIN" | grep "\.js$" | sort -u > "$OUTDIR/js_urls.txt"

echo "[*] Collecting JS files via getJS"
getJS --url "https://$DOMAIN" --complete >> "$OUTDIR/js_urls.txt"
sort -u "$OUTDIR/js_urls.txt" -o "$OUTDIR/js_urls.txt"

echo "[*] Downloading JS files"
mkdir -p "$OUTDIR/raw"
while IFS= read -r url; do
    fname=$(echo "$url" | md5sum | cut -c1-8).js
    curl -s --max-time 10 "$url" -o "$OUTDIR/raw/$fname"
done < "$OUTDIR/js_urls.txt"

echo "[*] Beautifying JS"
mkdir -p "$OUTDIR/beautified"
for f in "$OUTDIR/raw/"*.js; do
    fname=$(basename "$f")
    js-beautify "$f" > "$OUTDIR/beautified/$fname"
done

echo "[*] Extracting endpoints with LinkFinder"
for f in "$OUTDIR/beautified/"*.js; do
    python3 /opt/LinkFinder/linkfinder.py -i "$f" -o cli 2>/dev/null
done | sort -u > "$OUTDIR/endpoints_found.txt"

echo "[*] Extracting secrets"
grep -rE '(api_key|apiKey|secret|token|password)\s*[=:]\s*["\x27][^"\x27]{8,}' \
     "$OUTDIR/beautified/" > "$OUTDIR/potential_secrets.txt"

echo "[+] Done. Results in $OUTDIR/"
echo "    Endpoints: $OUTDIR/endpoints_found.txt"
echo "    Secrets:   $OUTDIR/potential_secrets.txt"
```

---

### 6. Real-World Findings From JS Analysis

These are actual bug bounty finding types enabled by JS analysis:

```
Finding type        What you found in JS
─────────────────── ──────────────────────────────────────────────────────────
Hardcoded API key   apiKey: "AIzaSyAbcDef..." → Google API key with broad scope
Internal endpoint   const ADMIN_URL = "https://admin.internal.target.com"
                    → Admin panel accessible from the internet
Undoc'd API param   fetch(`/api/users?debug=${debugMode}`)
                    → debug=true returns stack traces + user PII
GraphQL mutation    mutation deleteUser($userId: ID!)
                    → Mutation exists; no rate limiting; mass-delete possible
IDOR pattern        fetch(`/api/orders/${userId}/items`)
                    → userId is clientside, not validated server-side
```

---

## Key Takeaways

1. **JavaScript is the most information-dense file an application ships to your
   browser.** Before touching any exploit, read the JS. You will often find your
   attack path mapped out by the developers who built the feature.
2. **arjun's response-delta detection is the core technique.** It does not brute-
   force blindly — it detects which parameters actually change behaviour. This
   makes it accurate and relatively quiet.
3. **paramspider harvests parameters passively from historical URLs.** This is
   free intelligence that requires no direct interaction with the target.
4. **Hardcoded secrets in JS are an automatic High-severity finding.** An API key
   in a bundle.js is readable by every user of the application. Treat any found
   credential as a genuine incident.
5. **LinkFinder + manual grep together beat either alone.** LinkFinder extracts
   relative paths; grep extracts constants, hardcoded values, and patterns that
   the AST parser misses.

---

## Exercises

### Exercise 1 — arjun Parameter Hunt

On a lab target with a search or API endpoint:

1. Run `arjun -u https://target/api/search -m GET`.
2. What parameters were discovered?
3. Test each discovered parameter manually. Does any one change the response
   in a security-relevant way (extra data, different user, error messages)?

---

### Exercise 2 — JS Endpoint Extraction

Pick any public web application you have permission to test (or use Juice Shop):

1. Open Developer Tools → Network tab → reload the page.
2. Filter by JS files. Download the largest bundle.js.
3. Beautify it with `js-beautify`.
4. Run LinkFinder against it.
5. Manually grep for API endpoints, secrets, and internal URLs.
6. Identify the most interesting endpoint or secret found.

---

### Exercise 3 — paramspider + ffuf Chain

1. Run `paramspider -d target.com -o params.txt`.
2. Take the first 10 parameter URLs from the output.
3. For each URL with a `FUZZ` placeholder, run a quick XSS probe:
   `ffuf -w /opt/SecLists/Fuzzing/XSS/XSS-Jhaddix.txt -u "<url>" -mc 200`
4. Did any response reflect your input? That is a potential XSS surface.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 065 — Directory and Endpoint Fuzzing](DAY-0065-Directory-and-Endpoint-Fuzzing.md)*
*Next: [Day 067 — Web App Fingerprinting and Tech Stack](DAY-0067-Web-App-Fingerprinting-and-Tech-Stack.md)*
