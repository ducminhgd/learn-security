---
title: "ffuf and Custom Wordlists — Custom Wordlists, SecLists, ffuf Modes, Filter Tuning"
tags: [ffuf, fuzzing, wordlists, SecLists, directory-enumeration, parameter-discovery,
       endpoint-fuzzing, bug-bounty, filter-tuning, operations]
module: 05-BugBountyOps-01
day: 267
related_topics:
  - Directory and Endpoint Fuzzing (Day 065)
  - Parameter Discovery and JS Analysis (Day 066)
  - Recon Pipeline Automation (Day 265)
  - Bug Bounty Methodology Synthesis (Day 275)
---

# Day 267 — ffuf and Custom Wordlists

> "The difference between a researcher who finds endpoints and one who does not
> is the wordlist and the filter. A generic wordlist misses every proprietary
> path. A poorly tuned filter drowns you in false positives or silences real
> findings. Spend 20 minutes crafting the right wordlist and 10 minutes tuning
> the filter. That is the work before the work."
>
> — Ghost

---

## Goals

By the end of today's session you will be able to:

1. Use ffuf in directory, parameter, and virtual host fuzzing modes.
2. Build target-specific custom wordlists from JavaScript analysis and response
   mining.
3. Tune ffuf filters to eliminate false positives without suppressing findings.
4. Apply recursive fuzzing strategy for deep endpoint discovery.
5. Integrate ffuf output with the broader recon pipeline.

**Time budget:** 3–4 hours.

---

## Prerequisites

| Requirement | Covered in |
|---|---|
| Directory and endpoint fuzzing fundamentals | Day 065 |
| Parameter discovery and JS analysis | Day 066 |
| Recon pipeline automation | Day 265 |

---

## Part 1 — ffuf Modes

ffuf uses `FUZZ` as a placeholder in any part of the request.

### Directory / Path Fuzzing

```bash
# Basic directory enumeration:
ffuf -u https://target.example.com/FUZZ \
     -w ~/SecLists/Discovery/Web-Content/raft-medium-directories.txt \
     -mc 200,201,204,301,302,307,401,403 \
     -fc 404

# With custom extensions:
ffuf -u https://target.example.com/FUZZ \
     -w ~/SecLists/Discovery/Web-Content/raft-medium-files.txt \
     -e .php,.asp,.aspx,.jsp,.json,.bak,.old,.txt,.xml,.env,.yaml,.yml,.config \
     -mc 200,201,301,302 \
     -fc 404

# Recursive (follow discovered paths):
ffuf -u https://target.example.com/FUZZ \
     -w ~/SecLists/Discovery/Web-Content/raft-medium-directories.txt \
     -recursion \
     -recursion-depth 3 \
     -mc 200,301,302 \
     -fc 404
```

### Parameter Fuzzing

```bash
# GET parameter name discovery:
ffuf -u "https://target.example.com/search?FUZZ=test" \
     -w ~/SecLists/Discovery/Web-Content/burp-parameter-names.txt \
     -mc 200 \
     -fs 1234  # filter by response size (baseline)

# GET parameter value fuzzing (SQLi wordlist):
ffuf -u "https://target.example.com/users?id=FUZZ" \
     -w ~/SecLists/Fuzzing/SQLi/quick-SQLi.txt \
     -mc 200,500 \
     -fs 1234
```

### POST Body Fuzzing

```bash
# Fuzz a JSON POST body:
ffuf -u https://target.example.com/api/v1/login \
     -X POST \
     -H "Content-Type: application/json" \
     -d '{"username":"FUZZ","password":"test"}' \
     -w ~/SecLists/Usernames/top-usernames-shortlist.txt \
     -mc 200 \
     -fs 100  # filter by response size
```

### Virtual Host Fuzzing

```bash
# Discover virtual hosts on a shared IP:
ffuf -u https://target-ip.example.com/ \
     -H "Host: FUZZ.target.example.com" \
     -w ~/SecLists/Discovery/DNS/subdomains-top1million-20000.txt \
     -mc 200 \
     -fs 1234  # filter default vhost response size
```

### Header Value Fuzzing

```bash
# Fuzz X-Forwarded-For to bypass IP allowlisting:
ffuf -u https://target.example.com/admin \
     -H "X-Forwarded-For: FUZZ" \
     -w ~/SecLists/Fuzzing/IP-Addresses.txt \
     -mc 200 \
     -fc 403
```

---

## Part 2 — Filter Tuning

Poor filtering is the number one reason ffuf results are unusable.

### Getting the Baseline

Before fuzzing, always get the baseline response:

```bash
# Manual baseline:
curl -s -o /dev/null -w "%{http_code} %{size_download}" \
  https://target.example.com/nonexistentpath12345

# Let ffuf auto-calibrate:
ffuf -u https://target.example.com/FUZZ \
     -w wordlist.txt \
     -ac         # auto-calibrate — detects and filters baseline response
     -mc all     # match all status codes first
```

### Filter Options

```
-fc  filter-code:   Exclude responses with these status codes
                    e.g., -fc 404,302
-fs  filter-size:   Exclude responses matching this exact size (bytes)
                    e.g., -fs 1234
-fl  filter-lines:  Exclude responses with this line count
-fw  filter-words:  Exclude responses with this word count
-fr  filter-regex:  Exclude responses matching this pattern
                    e.g., -fr "not found|error 404|page not found"
```

### Tuning Workflow

```bash
# Step 1: Run with -ac (auto-calibrate) first:
ffuf -u https://target.example.com/FUZZ -w wordlist.txt -ac -mc all -o /tmp/raw.json

# Step 2: Review distribution of responses:
cat /tmp/raw.json | jq -r '.results[] | "\(.status) \(.length)"' | sort | uniq -c | sort -rn
# Output example:
#  4950 404 1234    ← This is your baseline noise
#    30 200 5432    ← These are interesting
#    15 403 234     ← These might be interesting (blocked but exists)
#     3 500 0       ← These are very interesting

# Step 3: Add targeted filters based on distribution:
ffuf -u https://target.example.com/FUZZ -w wordlist.txt \
     -fc 404 \
     -fs 1234 \
     -mc 200,201,301,302,307,401,403,500
```

---

## Part 3 — Custom Wordlist Building

Generic wordlists miss proprietary paths. Custom wordlists built from the
target's own content find what generics miss.

### Source 1: JavaScript File Mining

JavaScript files contain API endpoints, function names, and file paths.

```bash
# Extract URLs and paths from JS files:
# 1. Find all JS files on the target:
cat live-hosts.txt | while read url; do
  curl -s "$url" | grep -oP '(?<=src=")[^"]+\.js' | head -20
done | sort -u > js-files.txt

# 2. Download and mine each JS file:
cat js-files.txt | while read js; do
  curl -s "$js" | grep -oP '(?<=["\x60])/[a-zA-Z0-9/_-]+' | head -50
done | sort -u > js-paths.txt

# 3. Or use katana (crawls and extracts):
katana -u https://target.example.com \
       -d 5 \
       -ef css,png,jpg,svg,ico \
       -o katana-output.txt

cat katana-output.txt | grep -oP '/[a-zA-Z0-9/_.-]+' | sort -u > paths-from-crawl.txt
```

### Source 2: Response Body Mining

Responses often contain paths that are not in any generic wordlist:

```bash
# Use Burp's "Extract URLs from response" — right-click any response.
# Or use hakrawler / gau for historical URL data:
echo "target.example.com" | gau --blacklist png,jpg,gif,css --threads 5 | \
  grep -oP '(?<=https?://[^/]+)/[^?#]*' | sort -u > historical-paths.txt
```

### Source 3: Repository and Framework Defaults

```bash
# If target uses known framework:
# WordPress:
cat ~/SecLists/Discovery/Web-Content/CMS/wordpress.fuzz.txt

# Spring Boot / Java:
cat ~/SecLists/Discovery/Web-Content/spring-boot.txt

# Laravel / PHP:
cat ~/SecLists/Discovery/Web-Content/raft-medium-php-endpoints.txt
```

### Building a Target-Specific Wordlist

```bash
# Merge all sources, deduplicate, sort by frequency:
cat \
  js-paths.txt \
  paths-from-crawl.txt \
  historical-paths.txt \
  ~/SecLists/Discovery/Web-Content/raft-medium-directories.txt | \
  sort | uniq -c | sort -rn | awk '{print $2}' > \
  target-custom-wordlist.txt

echo "[*] Custom wordlist: $(wc -l < target-custom-wordlist.txt) entries"
```

---

## Part 4 — SecLists Reference

Key SecLists wordlists for different ffuf scenarios:

| Scenario | Wordlist path |
|---|---|
| Directory enumeration (medium) | `Discovery/Web-Content/raft-medium-directories.txt` |
| File enumeration | `Discovery/Web-Content/raft-medium-files.txt` |
| Parameter names | `Discovery/Web-Content/burp-parameter-names.txt` |
| Subdomain enumeration | `Discovery/DNS/subdomains-top1million-20000.txt` |
| Username enumeration | `Usernames/top-usernames-shortlist.txt` |
| Password fuzzing | `Passwords/Common-Credentials/10k-most-common.txt` |
| SQLi payloads | `Fuzzing/SQLi/quick-SQLi.txt` |
| XSS payloads | `Fuzzing/XSS/XSS-Jhaddix.txt` |
| SSTI payloads | `Fuzzing/template-injection.txt` |
| API paths | `Discovery/Web-Content/api/api-endpoints.txt` |
| Admin/backup paths | `Discovery/Web-Content/raft-large-files.txt` |

---

## Key Takeaways

1. **The wordlist is more important than the tool.** ffuf with a bad wordlist
   misses everything. ffuf with a custom wordlist built from the target's own
   JS files finds paths no one else looked for.
2. **Auto-calibrate is your fastest path to clean output.** `-ac` detects the
   baseline response automatically and filters it. Start with `-ac`, then
   refine with explicit `-fs`/`-fc` based on what you see.
3. **Parameter fuzzing is often more valuable than directory fuzzing.** Everyone
   runs directory fuzzing. Far fewer researchers systematically fuzz parameter
   names on every endpoint. Hidden parameters are hidden because they are not
   documented — which often means they are not properly validated either.
4. **Build your custom wordlist before the first testing session.** A good
   custom wordlist takes 20–30 minutes to build and saves hours of testing time.
   Make it target-specific: mine the JS, crawl the site, check historical URLs.
5. **Recursive fuzzing with depth control.** Running recursive mode without
   `-recursion-depth` can go very deep and trigger rate limits. Set
   `-recursion-depth 2` or `3` for most targets.

---

## Exercises

1. Build a custom wordlist for any public VDP target using all three sources
   in Part 3. Compare it to the generic raft-medium-directories.txt list.
   How many target-specific paths did you find that are not in the generic list?

2. Use ffuf in parameter fuzzing mode on an API endpoint that accepts GET
   parameters. Document: (a) What wordlist you used. (b) How you filtered the
   results. (c) What you found.

3. Write a bash one-liner that takes a URL as input and produces a custom
   wordlist by: (1) crawling with katana, (2) mining JS paths from the crawl
   output, and (3) merging with raft-medium-directories.txt.

4. Use ffuf's virtual host fuzzing mode against a lab target (DVWA or a custom
   lab) where you have configured multiple virtual hosts. Confirm ffuf discovers
   all configured vhosts without missing any.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q267.1, Q267.2 …).
> Follow-up questions use hierarchical numbering (Q267.1.1, Q267.1.2 …).

---

## Navigation

← Previous: [Day 266 — Burp Extensions for Bug Bounty](DAY-0266-Burp-Extensions-for-Bug-Bounty.md)
→ Next: [Day 268 — Tracking Findings and Notes](DAY-0268-Tracking-Findings-and-Notes.md)
