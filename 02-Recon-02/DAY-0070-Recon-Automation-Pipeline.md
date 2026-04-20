---
title: "Recon Automation Pipeline — amass → httpx → nuclei → Report"
tags: [recon, automation, pipeline, amass, httpx, nuclei, bash, python,
       subdomain-enumeration, vulnerability-scanning, bug-bounty, T1595]
module: 02-Recon-02
day: 70
related_topics:
  - Domain DNS and Certificate Transparency (Day 054)
  - Active Recon Lab (Day 069)
  - Bug Bounty Scope Analysis (Day 071)
  - Bug Bounty Recon Methodology (Day 072)
---

# Day 070 — Recon Automation Pipeline

## Goals

By the end of this lesson you will be able to:

1. Explain the design principles of a good recon automation pipeline.
2. Build a working pipeline: amass → dnsx → httpx → nuclei → report.
3. Parallelise tool execution safely without overloading targets.
4. Parse and deduplicate tool output programmatically.
5. Produce a structured, actionable report from pipeline output.

---

## Prerequisites

- [Day 054 — Domain, DNS and Certificate Transparency](../02-Recon-01/DAY-0054-Domain-DNS-and-Certificate-Transparency.md)
- [Day 069 — Active Recon Lab](DAY-0069-Active-Recon-Lab.md)

---

## Main Content

> "Manual recon is for understanding. Automated recon is for coverage.
> You need both. The automation handles breadth; you handle depth."
>
> — Ghost

### 1. Pipeline Design Principles

A recon pipeline is a chain of tools where each tool's output feeds the next.
Design principles:

```
1. Idempotent:   Re-running produces the same output. New runs append, not overwrite.
2. Resumable:    If a step fails, restart from that step without repeating prior work.
3. Auditable:    Every tool run is logged with timestamp, command, and output path.
4. Rate-limited: No step overwhelms the target or triggers abuse detection.
5. Deduplicating: Sort and deduplicate at every hand-off point.
6. Actionable:   Final output is prioritised findings, not raw tool dump.
```

---

### 2. Tool Stack

Install all tools before continuing:

```bash
# amass — subdomain enumeration
go install github.com/owasp-amass/amass/v4/...@master@latest

# dnsx — DNS resolution and probing
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# httpx — HTTP probing and fingerprinting
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# nuclei — vulnerability scanning
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates    # Download template library

# subfinder — passive subdomain enumeration
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# waybackurls — historical URL harvesting
go install github.com/tomnomnom/waybackurls@latest

# anew — append new lines only (deduplication)
go install github.com/tomnomnom/anew@latest
```

---

### 3. Stage 1 — Subdomain Enumeration

#### 3.1 subfinder (passive, fast)

```bash
# Passive subdomain enumeration — no direct contact with target
subfinder -d target.com -o subs_passive.txt -silent

# With all sources configured (add API keys to ~/.config/subfinder/provider-config.yaml)
subfinder -d target.com -all -o subs_passive.txt -silent
```

Configure API keys for maximum coverage:

```yaml
# ~/.config/subfinder/provider-config.yaml
virustotal:
  - YOUR_VT_API_KEY
securitytrails:
  - YOUR_ST_API_KEY
shodan:
  - YOUR_SHODAN_API_KEY
github:
  - YOUR_GITHUB_TOKEN
certspotter:
  - YOUR_CERTSPOTTER_KEY
```

#### 3.2 amass (active + passive)

```bash
# Passive enumeration (safe — no direct queries to target)
amass enum -passive -d target.com -o subs_amass_passive.txt

# Active enumeration (DNS brute force + zone transfer attempts)
# WARNING: creates log entries — confirm scope allows this
amass enum -active -d target.com \
     -brute -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
     -o subs_amass_active.txt
```

#### 3.3 Merge and deduplicate

```bash
# Combine all subdomain sources
cat subs_passive.txt subs_amass_passive.txt subs_amass_active.txt | \
    sort -u > all_subs_raw.txt

echo "[+] Total unique subdomains: $(wc -l < all_subs_raw.txt)"
```

---

### 4. Stage 2 — DNS Resolution

Filter out subdomains that do not resolve — no point probing dead hosts.

```bash
# Resolve all subdomains — keep only those with valid DNS answers
cat all_subs_raw.txt | \
    dnsx -silent -a -resp-only | \
    sort -u > resolved_ips.txt

# Keep subdomains that resolve (not just their IPs)
cat all_subs_raw.txt | \
    dnsx -silent -a | \
    awk '{print $1}' | \
    sort -u > resolved_subs.txt

echo "[+] Resolved: $(wc -l < resolved_subs.txt) / $(wc -l < all_subs_raw.txt)"

# Extract unique IPs for network scanning
cat all_subs_raw.txt | dnsx -a -resp-only -silent | sort -u > unique_ips.txt
```

---

### 5. Stage 3 — HTTP Probing

httpx identifies which resolved hosts have live web services.

```bash
# Probe all resolved subdomains for HTTP/HTTPS
cat resolved_subs.txt | \
    httpx \
    -silent \
    -status-code \
    -title \
    -tech-detect \
    -server \
    -content-length \
    -follow-redirects \
    -threads 50 \
    -rate-limit 100 \
    -json \
    -o httpx_results.json

# Extract just the live URLs for further processing
cat httpx_results.json | \
    jq -r '.url' | \
    sort -u > live_urls.txt

echo "[+] Live web services: $(wc -l < live_urls.txt)"
```

Parse httpx results for interesting targets:

```python
#!/usr/bin/env python3
"""parse_httpx.py — Extract interesting targets from httpx JSON output"""
import json
import sys


def parse_httpx(filename: str) -> None:
    interesting = []
    with open(filename) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            url = entry.get("url", "")
            status = entry.get("status_code", 0)
            title = entry.get("title", "")
            tech = entry.get("tech", [])
            server = entry.get("webserver", "")

            # Flag interesting findings
            flags = []
            if status == 403:
                flags.append("403-bypass-candidate")
            if any(t in str(tech).lower() for t in ["wordpress", "drupal", "joomla"]):
                flags.append("cms-target")
            if any(kw in title.lower() for kw in ["admin", "login", "dashboard", "portal"]):
                flags.append("auth-page")
            if any(kw in url.lower() for kw in ["api", "graphql", "swagger", "actuator"]):
                flags.append("api-surface")
            if server and any(v in server.lower() for v in ["apache/2.2", "nginx/1.14", "iis/7"]):
                flags.append("old-server-version")

            if flags:
                interesting.append({
                    "url": url,
                    "status": status,
                    "title": title,
                    "tech": tech,
                    "flags": flags,
                })

    print(f"[+] Interesting targets: {len(interesting)}")
    for item in sorted(interesting, key=lambda x: len(x["flags"]), reverse=True):
        print(f"\n{item['url']}")
        print(f"  Status: {item['status']} | Title: {item['title']}")
        print(f"  Flags:  {', '.join(item['flags'])}")
        print(f"  Tech:   {item['tech']}")


if __name__ == "__main__":
    parse_httpx(sys.argv[1] if len(sys.argv) > 1 else "httpx_results.json")
```

---

### 6. Stage 4 — Vulnerability Scanning with nuclei

nuclei runs templates against live targets and reports findings.

```bash
# Update templates first
nuclei -update-templates

# Template categories relevant to recon/initial access:
# exposures/    → exposed files, configs, admin panels
# technologies/ → version detection
# takeovers/    → subdomain takeover candidates
# misconfiguration/ → misconfigs in cloud, headers, etc.
# vulnerabilities/  → known CVE checks

# Run nuclei against live targets
nuclei \
    -l live_urls.txt \
    -t exposures/ \
    -t technologies/ \
    -t takeovers/ \
    -t misconfiguration/ \
    -severity low,medium,high,critical \
    -rate-limit 50 \
    -bulk-size 25 \
    -concurrency 10 \
    -o nuclei_results.json \
    -json \
    -silent

# Run only critical and high severity
nuclei \
    -l live_urls.txt \
    -severity high,critical \
    -rate-limit 30 \
    -o nuclei_critical.json \
    -json

# Run takeover templates specifically
nuclei \
    -l live_urls.txt \
    -t takeovers/ \
    -o nuclei_takeovers.json \
    -json
```

**Parse nuclei output:**

```bash
# Show only high/critical findings
cat nuclei_results.json | jq -r \
    'select(.info.severity == "high" or .info.severity == "critical") |
     "\(.info.severity | ascii_upcase)\t\(.host)\t\(.info.name)"' | \
    sort

# Count by severity
cat nuclei_results.json | jq -r '.info.severity' | sort | uniq -c | sort -rn
```

---

### 7. Stage 5 — Wayback URL Harvesting

Historical URLs from the Wayback Machine often reveal endpoints that no longer
appear in the current application.

```bash
# Harvest URLs for all live domains
cat live_urls.txt | \
    sed 's|https\?://||' | \
    sed 's|/.*||' | \
    sort -u | \
    while read domain; do
        echo "[*] waybackurls: $domain"
        waybackurls "$domain" 2>/dev/null
    done | \
    sort -u > wayback_urls.txt

echo "[+] Wayback URLs: $(wc -l < wayback_urls.txt)"

# Extract unique parameters
cat wayback_urls.txt | \
    grep "?" | \
    sed 's/=.*/=FUZZ/' | \
    sort -u > wayback_params.txt

echo "[+] Unique parameter URLs: $(wc -l < wayback_params.txt)"

# Extract interesting file types
cat wayback_urls.txt | \
    grep -iE "\.(sql|env|bak|log|xml|json|conf|config|yml|yaml|tar|zip)$" > \
    wayback_interesting_files.txt
```

---

### 8. Complete Pipeline Script

```bash
#!/bin/bash
# recon_pipeline.sh — complete automated recon pipeline
# Usage: ./recon_pipeline.sh <domain> [output_dir]
# Requirements: subfinder, amass, dnsx, httpx, nuclei, waybackurls
# Estimated time: 15-45 minutes depending on scope

set -euo pipefail

DOMAIN="${1:?Usage: $0 <domain> [output_dir]}"
OUTDIR="${2:-recon_${DOMAIN}_$(date +%Y%m%d_%H%M%S)}"
RATE_LIMIT=100  # requests per second — adjust for target

mkdir -p "$OUTDIR"/{subs,dns,http,nuclei,wayback,reports}
LOG="$OUTDIR/pipeline.log"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

# ─── Stage 1: Subdomain Enumeration ─────────────────────────────────────────
log "Stage 1: Subdomain enumeration for $DOMAIN"

log "  subfinder (passive)"
subfinder -d "$DOMAIN" -all -silent -o "$OUTDIR/subs/subfinder.txt" 2>>"$LOG" || true

log "  amass (passive)"
amass enum -passive -d "$DOMAIN" -o "$OUTDIR/subs/amass_passive.txt" 2>>"$LOG" || true

log "  certificate transparency"
curl -s "https://crt.sh/?q=%.${DOMAIN}&output=json" 2>/dev/null | \
    python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    seen = set()
    for e in data:
        name = e.get('name_value','').strip()
        for n in name.split('\n'):
            n = n.strip().lstrip('*.')
            if n and n not in seen:
                seen.add(n)
                print(n)
except Exception as e:
    pass
" > "$OUTDIR/subs/crtsh.txt" 2>>"$LOG" || true

# Merge and deduplicate
cat "$OUTDIR"/subs/*.txt 2>/dev/null | \
    grep -E "^[a-zA-Z0-9._-]+\.$DOMAIN$" | \
    sort -u > "$OUTDIR/subs/all_subs.txt"
log "  Total subdomains: $(wc -l < "$OUTDIR/subs/all_subs.txt")"

# ─── Stage 2: DNS Resolution ──────────────────────────────────────────────────
log "Stage 2: DNS resolution"
cat "$OUTDIR/subs/all_subs.txt" | \
    dnsx -silent -a -resp-only | \
    sort -u > "$OUTDIR/dns/resolved_ips.txt"

cat "$OUTDIR/subs/all_subs.txt" | \
    dnsx -silent -a | \
    awk '{print $1}' | \
    sort -u > "$OUTDIR/dns/resolved_subs.txt"

log "  Resolved: $(wc -l < "$OUTDIR/dns/resolved_subs.txt")"

# ─── Stage 3: HTTP Probing ───────────────────────────────────────────────────
log "Stage 3: HTTP probing"
cat "$OUTDIR/dns/resolved_subs.txt" | \
    httpx -silent -status-code -title -tech-detect -server \
    -follow-redirects -threads 50 \
    -rate-limit "$RATE_LIMIT" \
    -json -o "$OUTDIR/http/httpx_results.json" 2>>"$LOG"

cat "$OUTDIR/http/httpx_results.json" | \
    python3 -c "
import json, sys
for line in sys.stdin:
    try:
        e = json.loads(line)
        print(e['url'])
    except:
        pass
" | sort -u > "$OUTDIR/http/live_urls.txt"

log "  Live web services: $(wc -l < "$OUTDIR/http/live_urls.txt")"

# ─── Stage 4: nuclei Scanning ─────────────────────────────────────────────────
log "Stage 4: nuclei vulnerability scanning"
nuclei -l "$OUTDIR/http/live_urls.txt" \
    -t exposures/ -t technologies/ -t takeovers/ -t misconfiguration/ \
    -severity low,medium,high,critical \
    -rate-limit "$RATE_LIMIT" \
    -bulk-size 25 -concurrency 10 \
    -json -o "$OUTDIR/nuclei/all_findings.json" \
    -silent 2>>"$LOG" || true

HIGH_CRIT=$(cat "$OUTDIR/nuclei/all_findings.json" 2>/dev/null | \
            python3 -c "
import json, sys
count = 0
for line in sys.stdin:
    try:
        e = json.loads(line)
        if e.get('info',{}).get('severity','') in ('high','critical'):
            count += 1
    except:
        pass
print(count)
" 2>/dev/null || echo 0)
log "  High/Critical findings: $HIGH_CRIT"

# ─── Stage 5: Wayback URLs ───────────────────────────────────────────────────
log "Stage 5: Wayback URL harvesting"
waybackurls "$DOMAIN" 2>/dev/null | sort -u > "$OUTDIR/wayback/urls.txt" || true
cat "$OUTDIR/wayback/urls.txt" | grep "?" | \
    sed 's/=.*/=FUZZ/' | sort -u > "$OUTDIR/wayback/params.txt"
log "  Wayback URLs: $(wc -l < "$OUTDIR/wayback/urls.txt")"

# ─── Stage 6: Report ─────────────────────────────────────────────────────────
log "Stage 6: Generating report"

python3 - << EOF
import json
from datetime import datetime

domain = "$DOMAIN"
outdir = "$OUTDIR"

with open(f"{outdir}/dns/resolved_subs.txt") as f:
    subs = [l.strip() for l in f if l.strip()]

with open(f"{outdir}/http/live_urls.txt") as f:
    urls = [l.strip() for l in f if l.strip()]

findings = []
try:
    with open(f"{outdir}/nuclei/all_findings.json") as f:
        for line in f:
            try:
                findings.append(json.loads(line))
            except:
                pass
except FileNotFoundError:
    pass

high_crit = [f for f in findings
             if f.get('info', {}).get('severity', '') in ('high', 'critical')]
high_crit.sort(key=lambda x: x.get('info',{}).get('severity',''), reverse=True)

report = f"""# Recon Report — {domain}

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Pipeline:** subfinder → dnsx → httpx → nuclei → waybackurls

---

## Summary

| Metric | Count |
|--------|-------|
| Subdomains discovered | {len(subs)} |
| Live web services | {len(urls)} |
| nuclei findings (all) | {len(findings)} |
| High / Critical findings | {len(high_crit)} |

---

## High / Critical Findings

"""

for f in high_crit[:20]:
    sev = f.get('info', {}).get('severity', '').upper()
    name = f.get('info', {}).get('name', '')
    host = f.get('host', '')
    report += f"- **[{sev}]** {name} — `{host}`\n"

report += "\n---\n\n## Live Web Services\n\n"
for url in urls[:50]:
    report += f"- {url}\n"

report += "\n---\n\n## Subdomain List\n\n"
for sub in subs[:100]:
    report += f"- {sub}\n"

with open(f"{outdir}/reports/recon_report.md", 'w') as f:
    f.write(report)

print(f"[+] Report: {outdir}/reports/recon_report.md")
EOF

log "Pipeline complete. Output: $OUTDIR/"
log "Summary:"
log "  Subdomains:      $(wc -l < "$OUTDIR/dns/resolved_subs.txt")"
log "  Live services:   $(wc -l < "$OUTDIR/http/live_urls.txt")"
log "  nuclei findings: $(wc -l < "$OUTDIR/nuclei/all_findings.json" 2>/dev/null || echo 0)"
log "  Report:          $OUTDIR/reports/recon_report.md"
```

---

### 9. Continuous Recon — Monitoring for New Attack Surface

For bug bounty programmes you target repeatedly, run the pipeline on a schedule
and alert on new findings:

```bash
# crontab entry — run pipeline daily at 3am
# 0 3 * * * /opt/recon/recon_pipeline.sh target.com /opt/recon/results >> /var/log/recon.log 2>&1

# Monitor for new subdomains
diff previous_subs.txt current_subs.txt | grep "^>" | awk '{print $2}'

# Alert on new nuclei high/critical findings
python3 - << 'EOF'
import json

old_findings = set()
try:
    with open('previous_nuclei.json') as f:
        for line in f:
            try:
                e = json.loads(line)
                old_findings.add(e.get('host','') + '|' + e.get('template-id',''))
            except:
                pass
except FileNotFoundError:
    pass

new_findings = []
with open('current_nuclei.json') as f:
    for line in f:
        try:
            e = json.loads(line)
            key = e.get('host','') + '|' + e.get('template-id','')
            if key not in old_findings:
                sev = e.get('info', {}).get('severity', '')
                if sev in ('high', 'critical'):
                    new_findings.append(e)
        except:
            pass

if new_findings:
    print(f"[!] {len(new_findings)} NEW HIGH/CRITICAL FINDINGS:")
    for f in new_findings:
        print(f"  [{f.get('info',{}).get('severity','').upper()}] "
              f"{f.get('info',{}).get('name','')} — {f.get('host','')}")
EOF
```

---

## Key Takeaways

1. **A pipeline is not a silver bullet — it is a force multiplier.** The pipeline
   handles breadth and repetition. You still need to manually investigate what it
   finds. Automated scans miss logic bugs, context-dependent issues, and complex
   chains entirely.
2. **Rate limiting is a feature, not a constraint.** A pipeline without rate
   limits will trigger abuse detection, block your IP, or violate programme
   rules. Build it in from day one.
3. **nuclei findings need manual triage.** Templates produce false positives.
   Every `high` or `critical` finding must be manually confirmed before reporting.
   An automated false positive wastes your credibility with the programme.
4. **Continuous monitoring is where automated recon pays compound returns.**
   The first run gives you breadth. Each subsequent run finds new attack surface
   created by developers making changes — and you find it before other researchers.
5. **The pipeline output is the beginning of your work, not the end.** The report
   tells you where to look. The actual vulnerability hunting starts after the
   pipeline completes.

---

## Exercises

### Exercise 1 — Build and Run the Pipeline

1. Install all required tools (subfinder, dnsx, httpx, nuclei).
2. Run `recon_pipeline.sh` against a lab target or a bug bounty programme
   you are authorised on.
3. How many subdomains were discovered?
4. How many live web services were found?
5. Were any nuclei findings produced? Confirm one manually.

---

### Exercise 2 — Customise for a Technology Stack

Modify the pipeline for a target you know runs WordPress:

1. Add wpscan to Stage 4 instead of nuclei.
2. Add the WordPress-specific nuclei templates.
3. What additional information does the WordPress-focused pipeline produce?

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 069 — Active Recon Lab](DAY-0069-Active-Recon-Lab.md)*
*Next: [Day 071 — Bug Bounty Scope Analysis](DAY-0071-Bug-Bounty-Scope-Analysis.md)*
