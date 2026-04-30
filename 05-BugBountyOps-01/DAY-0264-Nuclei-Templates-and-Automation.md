---
title: "Nuclei Templates and Automation — Setup, Custom Templates, CI Integration"
tags: [nuclei, automation, templates, bug-bounty, recon, vulnerability-scanning,
       YAML, CI, ProjectDiscovery, custom-templates, operations]
module: 05-BugBountyOps-01
day: 264
related_topics:
  - Recon Pipeline Automation (Day 265)
  - Directory and Endpoint Fuzzing (Day 065)
  - Active Recon Lab (Day 069)
  - Burp Extensions for Bug Bounty (Day 266)
---

# Day 264 — Nuclei Templates and Automation

> "Automation is not cheating. It is leverage. You cannot manually check 3,000
> subdomains for misconfigured S3 bucket redirects. Nuclei can. While the tool
> runs the known checks, your brain focuses on the unknown ones — the logic
> flaws, the chains, the weird behaviours that no template has ever seen. That
> is the division of labour."
>
> — Ghost

---

## Goals

By the end of today's session you will be able to:

1. Install and configure Nuclei with the official template library.
2. Run Nuclei against a target with appropriate rate limiting and scope control.
3. Interpret Nuclei output and triage false positives.
4. Write a custom Nuclei template for a newly discovered vulnerability class.
5. Integrate Nuclei into a basic recon pipeline.

**Time budget:** 4–5 hours.

---

## Prerequisites

| Requirement | Covered in |
|---|---|
| Active recon and endpoint enumeration | Days 063–070 |
| Reading program policies and scope | Day 262 |
| HTTP headers and web architecture | Days 017–028 |

---

## Part 1 — Nuclei Fundamentals

Nuclei is a fast, template-based vulnerability scanner built by ProjectDiscovery.
It works by sending HTTP requests defined in YAML templates and matching
responses against conditions you define.

### Installation

```bash
# Go-based install (preferred):
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Or via binary release:
# https://github.com/projectdiscovery/nuclei/releases

# Update templates (do this daily before running):
nuclei -update-templates

# Verify install:
nuclei -version
# nuclei v3.x.x
```

### Template Library Location

```bash
# Default template path:
ls ~/nuclei-templates/

# Key directories:
# http/           — HTTP-based checks
# dns/            — DNS misconfiguration checks
# ssl/            — TLS/certificate checks
# exposed-panels/ — Exposed admin panels, login pages
# cves/           — Known CVE checks
# exposures/      — Credential and secret exposure checks
# misconfiguration/ — Common misconfiguration checks
```

---

## Part 2 — Running Nuclei

### Basic Usage

```bash
# Scan a single target with all templates:
nuclei -u https://target.example.com

# Scan a list of URLs:
nuclei -list urls.txt

# Scan with specific tags (more targeted):
nuclei -u https://target.example.com -tags xss,sqli,ssrf

# Scan with specific template directory:
nuclei -u https://target.example.com -t http/exposures/

# Rate limiting (critical for programme compliance):
nuclei -u https://target.example.com -rate-limit 10 -concurrency 5
# -rate-limit 10: max 10 requests per second
# -concurrency 5: max 5 parallel checks

# Output to file:
nuclei -u https://target.example.com -o results.txt -jsonl
```

### Scope Control

**Never run Nuclei without scope control.** Always confirm templates will
only send requests to in-scope targets.

```bash
# Scan only specific subdomains from recon output:
cat scope-subdomains.txt | httpx -silent | nuclei -list /dev/stdin -rate-limit 10

# Exclude specific patterns (third-party services):
nuclei -list urls.txt -exclude-hosts "cloudfront.net,akamaihd.net,s3.amazonaws.com"
```

### Severity Filtering

```bash
# Only show critical and high severity:
nuclei -u https://target.example.com -severity critical,high

# All severities, grouped by severity:
nuclei -u https://target.example.com -stats
```

---

## Part 3 — Triaging Nuclei Output

Nuclei generates false positives. Every finding must be manually verified.

### Triage Workflow

```
For each Nuclei finding:

1. Read the template name and description:
   What vulnerability class is this checking?

2. Open the matched URL in Burp Suite.
   Replicate the exact request the template sent.

3. Inspect the response.
   Does the evidence match the template's description?

4. Assess exploitability.
   Can this be turned into a real impact?

5. Decision:
   - Confirmed exploitable → write report
   - Confirmed but low impact → flag, chain later
   - False positive → discard, note why
```

### Common False Positive Sources

| Template type | Common FP cause |
|---|---|
| Exposed config files | CDN caching old 404 with 200 status |
| Default credentials | Login page exists but credentials fail |
| CVE checks | Version string match without actual vulnerability |
| Header-based checks | Security header present in a different case |
| SQL injection | Error message similarity without actual injection |

---

## Part 4 — Writing Custom Nuclei Templates

This is where Nuclei becomes powerful. Off-the-shelf templates check known
patterns. A custom template checks the specific behaviour you found.

### Template Structure

```yaml
id: my-custom-template

info:
  name: "Descriptive Name of Vulnerability"
  author: your-handle
  severity: high
  description: "One-sentence description of what this checks."
  tags: custom,web,info-disclosure

requests:
  - method: GET
    path:
      - "{{BaseURL}}/api/v1/admin/users"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: word
        words:
          - '"email"'
          - '"role"'
          - '"admin"'
        condition: and
```

### Template Variables

| Variable | Resolves to |
|---|---|
| `{{BaseURL}}` | `https://target.example.com` |
| `{{Host}}` | `target.example.com` |
| `{{Path}}` | The current path component |
| `{{RootURL}}` | `https://target.example.com/` |

### Matcher Types

```yaml
# Status code matcher:
matchers:
  - type: status
    status: [200, 201]

# Word matcher (response body):
matchers:
  - type: word
    words:
      - "AWS_SECRET_ACCESS_KEY"
      - "password"
    condition: or
    part: body

# Regex matcher:
matchers:
  - type: regex
    regex:
      - 'AKIA[A-Z0-9]{16}'  # AWS access key
    part: body

# Header matcher:
matchers:
  - type: word
    words:
      - "X-Debug: true"
    part: header

# Binary AND condition:
matchers-condition: and
matchers:
  - type: status
    status: [200]
  - type: word
    words:
      - '"admin": true'
```

### Practical Example — IDOR Check Template

```yaml
id: idor-user-profile-access

info:
  name: "IDOR — User Profile Access Without Authentication"
  author: your-handle
  severity: high
  description: "Checks if /api/v1/users/FUZZ is accessible without auth."
  tags: idor,access-control,custom

requests:
  - method: GET
    path:
      - "{{BaseURL}}/api/v1/users/1"
      - "{{BaseURL}}/api/v1/users/2"
      - "{{BaseURL}}/api/v1/users/admin"

    headers:
      Accept: application/json
    # Intentionally no Authorization header

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: word
        words:
          - '"email"'
          - '"username"'
        condition: or
        part: body
```

### Template for Secret Exposure

```yaml
id: api-response-secret-leak

info:
  name: "API Response Contains Internal Secret"
  author: your-handle
  severity: critical
  description: "API endpoint leaks internal credentials in JSON response."
  tags: exposure,secrets,custom

requests:
  - method: GET
    path:
      - "{{BaseURL}}/api/v1/config"
      - "{{BaseURL}}/api/v1/settings"
      - "{{BaseURL}}/api/debug/config"

    matchers-condition: or
    matchers:
      - type: regex
        regex:
          - 'AKIA[A-Z0-9]{16}'
          - '"secret_key"\s*:\s*"[^"]+'
          - '"db_password"\s*:\s*"[^"]+'
        part: body

      - type: word
        words:
          - "secret_key"
          - "private_key"
          - "api_secret"
          - "client_secret"
        condition: and
        part: body
```

---

## Part 5 — Integrating Nuclei into a Pipeline

Full pipeline setup comes in Day 265. Today: the Nuclei piece.

```bash
#!/usr/bin/env bash
# nuclei-scope-scan.sh
# Usage: ./nuclei-scope-scan.sh example.com

TARGET="$1"
TIMESTAMP=$(date +%Y%m%d-%H%M)
OUTPUT_DIR="./results/${TARGET}/${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

echo "[*] Running Nuclei against ${TARGET}"

# Step 1: Subdomain → live host check (output from pipeline)
cat "${TARGET}-subdomains.txt" | httpx -silent -o "${OUTPUT_DIR}/live-hosts.txt"

# Step 2: Nuclei against live hosts with rate limiting
nuclei \
  -list "${OUTPUT_DIR}/live-hosts.txt" \
  -severity critical,high,medium \
  -rate-limit 10 \
  -concurrency 5 \
  -o "${OUTPUT_DIR}/nuclei-results.txt" \
  -jsonl \
  -stats \
  -silent

echo "[*] Done. Results in ${OUTPUT_DIR}/nuclei-results.txt"
echo "[*] $(wc -l < "${OUTPUT_DIR}/nuclei-results.txt") findings (requires manual triage)"
```

---

## Key Takeaways

1. **Nuclei finds known patterns; your brain finds unknown ones.** Use Nuclei
   to eliminate the mechanical checklist work — exposed configs, version
   disclosures, common CVEs. Use your time for logic flaws and chains.
2. **Rate limiting is not optional.** Slamming a programme with unrestricted
   Nuclei requests violates RoE and may get your account banned. Always set
   `-rate-limit` and `-concurrency` to values the programme allows.
3. **Every Nuclei finding is a lead, not a confirmed bug.** Triage every result
   manually before writing a report. False-positive reports burn Signal.
4. **Custom templates are the differentiator.** Off-the-shelf templates catch
   what everyone else catches. A template you wrote for a pattern you discovered
   catches something unique to you.
5. **Update templates daily.** The Nuclei community adds checks for newly
   disclosed CVEs within hours. `nuclei -update-templates` every morning.

---

## Exercises

1. Install Nuclei. Update the template library. Run it against DVWA or Juice
   Shop in your lab. Triage every result. How many are true positives?

2. Write a custom Nuclei template that checks for exposed `.git` directories
   (`/.git/config` returns a 200 with `[core]` in the body). Test it against
   a lab server where you have planted a `.git` directory.

3. Write a custom Nuclei template that detects the CORS misconfiguration pattern:
   request with `Origin: evil.com` header returns `Access-Control-Allow-Origin: evil.com`
   and `Access-Control-Allow-Credentials: true`.

4. Run Nuclei against the gate lab from Day 165 (if still running). Compare
   what Nuclei finds automatically versus what you found manually. What did
   Nuclei miss? What did you miss that Nuclei caught?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q264.1, Q264.2 …).
> Follow-up questions use hierarchical numbering (Q264.1.1, Q264.1.2 …).

---

## Navigation

← Previous: [Day 263 — Choosing the Right Program](DAY-0263-Choosing-the-Right-Program.md)
→ Next: [Day 265 — Recon Pipeline Automation](DAY-0265-Recon-Pipeline-Automation.md)
