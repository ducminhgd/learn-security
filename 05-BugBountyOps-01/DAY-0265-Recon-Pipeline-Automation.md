---
title: "Recon Pipeline Automation — amass → httpx → nuclei → notify"
tags: [recon, automation, pipeline, amass, httpx, nuclei, notify, subfinder,
       bash, monitoring, continuous-recon, bug-bounty, operations]
module: 05-BugBountyOps-01
day: 265
related_topics:
  - Nuclei Templates and Automation (Day 264)
  - Active Recon and Bug Bounty Scope (Days 063–075)
  - Recon Automation Pipeline (Day 070)
  - Bug Bounty Methodology Synthesis (Day 275)
---

# Day 265 — Recon Pipeline Automation

> "The researchers who earn consistently are not the ones who hack harder —
> they are the ones who never stop watching. When a company adds a new
> subdomain at 2 a.m., that subdomain has a window of hours where it is
> fully exposed. Whoever has automated monitoring catches it. Whoever is
> doing manual point-in-time recon misses it entirely."
>
> — Ghost

---

## Goals

By the end of today's session you will be able to:

1. Build a full automated recon pipeline from subdomain discovery to notification.
2. Configure continuous monitoring for new assets on a target programme.
3. Integrate httpx for live host validation and basic fingerprinting.
4. Pipe Nuclei into the pipeline with scope and rate controls.
5. Set up Slack/Discord/email notifications for new findings.

**Time budget:** 4–5 hours.

---

## Prerequisites

| Requirement | Covered in |
|---|---|
| Subdomain enumeration (amass, subfinder) | Day 054 |
| Active recon and endpoint fuzzing | Days 063–069 |
| Nuclei setup and templates | Day 264 |

---

## Part 1 — Pipeline Architecture

```
[Target programme scope]
         │
         ▼
  Subdomain Discovery
  (amass + subfinder + crt.sh)
         │
         ▼
  Live Host Validation
  (httpx — filters dead hosts)
         │
         ▼
  Technology Fingerprinting
  (httpx -tech-detect, whatweb)
         │
         ▼
  Endpoint Discovery
  (ffuf, dirsearch on interesting hosts)
         │
         ▼
  Vulnerability Scanning
  (nuclei — templated checks)
         │
         ▼
  New Finding Detection
  (diff against previous run)
         │
         ▼
  Notification
  (Slack / Discord / email / ntfy)
```

---

## Part 2 — Tool Stack

Install all tools before Day 276:

```bash
# ProjectDiscovery toolkit (all Go-based):
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/notify/cmd/notify@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# amass (subdomain enumeration):
go install -v github.com/owasp-amass/amass/v4/...@master

# ffuf (directory fuzzing):
go install github.com/ffuf/ffuf/v2@latest

# SecLists (wordlists):
git clone https://github.com/danielmiessler/SecLists ~/SecLists

# Update nuclei templates:
nuclei -update-templates
```

---

## Part 3 — Building the Pipeline

### Step 1 — Subdomain Discovery

```bash
#!/usr/bin/env bash
# recon/subdomain-enum.sh
# Usage: ./subdomain-enum.sh example.com

DOMAIN="$1"
OUTPUT="./data/${DOMAIN}"
mkdir -p "$OUTPUT"

echo "[*] Running subfinder..."
subfinder -d "$DOMAIN" -silent -o "${OUTPUT}/subfinder.txt"

echo "[*] Running amass passive..."
amass enum -passive -d "$DOMAIN" -o "${OUTPUT}/amass.txt"

echo "[*] Querying crt.sh..."
curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" | \
  jq -r '.[].name_value' | \
  sed 's/\*\.//g' | \
  sort -u > "${OUTPUT}/crtsh.txt"

echo "[*] Merging and deduplicating..."
cat "${OUTPUT}/subfinder.txt" \
    "${OUTPUT}/amass.txt" \
    "${OUTPUT}/crtsh.txt" | \
  sort -u > "${OUTPUT}/all-subdomains.txt"

echo "[*] Total unique subdomains: $(wc -l < "${OUTPUT}/all-subdomains.txt")"
```

### Step 2 — Live Host Validation

```bash
#!/usr/bin/env bash
# recon/live-hosts.sh
# Usage: ./live-hosts.sh example.com

DOMAIN="$1"
OUTPUT="./data/${DOMAIN}"

echo "[*] Probing live hosts with httpx..."
cat "${OUTPUT}/all-subdomains.txt" | httpx \
  -silent \
  -status-code \
  -title \
  -tech-detect \
  -follow-redirects \
  -threads 50 \
  -rate-limit 50 \
  -o "${OUTPUT}/live-hosts.txt"

echo "[*] Live hosts found: $(wc -l < "${OUTPUT}/live-hosts.txt")"

# Extract just URLs for next pipeline stages:
cat "${OUTPUT}/live-hosts.txt" | awk '{print $1}' > "${OUTPUT}/live-urls.txt"
```

### Step 3 — Endpoint Discovery (Selective)

Run directory fuzzing only on the most interesting targets:

```bash
#!/usr/bin/env bash
# recon/endpoint-fuzz.sh
# Usage: ./endpoint-fuzz.sh <url>

URL="$1"
DOMAIN=$(echo "$URL" | awk -F[/:] '{print $4}')
OUTPUT="./data/endpoints/${DOMAIN}"
mkdir -p "$OUTPUT"

echo "[*] Fuzzing endpoints on ${URL}..."
ffuf \
  -u "${URL}/FUZZ" \
  -w ~/SecLists/Discovery/Web-Content/raft-medium-directories.txt \
  -mc 200,201,204,301,302,403 \
  -fc 404 \
  -rate 20 \
  -o "${OUTPUT}/ffuf-results.json" \
  -of json \
  -silent

echo "[*] Found $(cat "${OUTPUT}/ffuf-results.json" | jq '.results | length') endpoints"
```

### Step 4 — Nuclei Scan

```bash
#!/usr/bin/env bash
# recon/nuclei-scan.sh
# Usage: ./nuclei-scan.sh example.com

DOMAIN="$1"
TIMESTAMP=$(date +%Y%m%d-%H%M)
OUTPUT="./data/${DOMAIN}/nuclei/${TIMESTAMP}"
mkdir -p "$OUTPUT"

echo "[*] Running Nuclei..."
nuclei \
  -list "./data/${DOMAIN}/live-urls.txt" \
  -severity critical,high,medium \
  -rate-limit 10 \
  -concurrency 5 \
  -t ~/nuclei-templates/http/exposures/ \
  -t ~/nuclei-templates/http/misconfiguration/ \
  -t ~/nuclei-templates/cves/ \
  -t ~/nuclei-templates/http/exposed-panels/ \
  -t ~/custom-templates/ \
  -o "${OUTPUT}/findings.txt" \
  -jsonl \
  -stats

echo "[*] Nuclei complete: $(wc -l < "${OUTPUT}/findings.txt") raw findings"
```

### Step 5 — Delta Detection (New Findings Only)

The most important piece. New subdomains and new findings need to fire alerts.

```bash
#!/usr/bin/env bash
# recon/detect-new.sh
# Usage: ./detect-new.sh example.com

DOMAIN="$1"
CURRENT="./data/${DOMAIN}/all-subdomains.txt"
PREVIOUS="./data/${DOMAIN}/all-subdomains-prev.txt"
NEW_SUBS="./data/${DOMAIN}/new-subdomains.txt"

if [ ! -f "$PREVIOUS" ]; then
  cp "$CURRENT" "$PREVIOUS"
  echo "[*] First run — baseline saved."
  exit 0
fi

# Find new subdomains:
comm -23 <(sort "$CURRENT") <(sort "$PREVIOUS") > "$NEW_SUBS"

NEW_COUNT=$(wc -l < "$NEW_SUBS")
if [ "$NEW_COUNT" -gt 0 ]; then
  echo "[!] ${NEW_COUNT} NEW subdomains detected for ${DOMAIN}:"
  cat "$NEW_SUBS"
  # Trigger notification (see Step 6)
  cat "$NEW_SUBS" | notify -provider-config ~/notify-config.yaml \
    -bulk -id "new-subdomain-${DOMAIN}"
fi

# Save current as new previous:
cp "$CURRENT" "$PREVIOUS"
```

### Step 6 — Notify Configuration

```yaml
# ~/notify-config.yaml
slack:
  - id: "bug-bounty-alerts"
    slack_webhook_url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    slack_username: "ReconBot"
    slack_channel: "#new-findings"
    slack_format: "{{data}}"

discord:
  - id: "bug-bounty-discord"
    discord_webhook_url: "https://discord.com/api/webhooks/YOUR/WEBHOOK"
    discord_username: "ReconBot"
    discord_format: "{{data}}"

# Telegram alternative:
telegram:
  - id: "recon-telegram"
    telegram_api_key: "YOUR_BOT_TOKEN"
    telegram_chat_id: "YOUR_CHAT_ID"
    telegram_format: "{{data}}"
```

```bash
# Send a notification:
echo "New finding: SSRF on api.example.com" | \
  notify -provider-config ~/notify-config.yaml -id "bug-bounty-alerts"
```

---

## Part 4 — Master Pipeline Script

```bash
#!/usr/bin/env bash
# recon/run-pipeline.sh
# Usage: ./run-pipeline.sh example.com [--notify]

DOMAIN="$1"
NOTIFY="${2:-}"
TIMESTAMP=$(date +%Y%m%d-%H%M)

echo "=== Recon Pipeline: ${DOMAIN} | ${TIMESTAMP} ==="

# Step 1: Subdomain discovery
./recon/subdomain-enum.sh "$DOMAIN"

# Step 2: Live host validation
./recon/live-hosts.sh "$DOMAIN"

# Step 3: New subdomain detection (fire alerts)
./recon/detect-new.sh "$DOMAIN"

# Step 4: Nuclei scan
./recon/nuclei-scan.sh "$DOMAIN"

echo "=== Pipeline complete for ${DOMAIN} ==="
echo "Live hosts: $(wc -l < ./data/${DOMAIN}/live-urls.txt)"
echo "Nuclei findings (latest): $(ls -t ./data/${DOMAIN}/nuclei/ | head -1 | xargs -I{} \
  wc -l < ./data/${DOMAIN}/nuclei/{}/findings.txt)"
```

### Cron Schedule for Continuous Monitoring

```bash
# Run recon pipeline every 6 hours for all active targets:
# crontab -e
0 */6 * * * /path/to/recon/run-pipeline.sh example.com --notify 2>&1 \
  >> /var/log/recon-pipeline.log
```

---

## Part 5 — Operational Discipline

Automation is powerful but dangerous without discipline.

**Never automate without:**
1. A scope file defining exactly which domains/subdomains to include.
2. A rate limit that respects the programme's RoE.
3. Manual triage of every finding before reporting.
4. Exclusion of known third-party infrastructure.

**Pipeline hygiene:**
```bash
# Review every pipeline run before acting on results:
tail -50 /var/log/recon-pipeline.log    # check for errors
cat ./data/example.com/new-subdomains.txt  # verify new subs are in scope
wc -l ./data/example.com/nuclei/*/findings.txt  # count findings needing triage
```

---

## Key Takeaways

1. **Continuous monitoring turns bug bounty from event-based into ambient.**
   The pipeline runs while you sleep. New assets appear. You wake up with leads.
2. **Delta detection is the most valuable automation feature.** Finding 500
   subdomains is table stakes. Detecting 2 new subdomains added last night is
   signal — new assets are often the least hardened.
3. **The pipeline frees your brain for the creative work.** Automation handles
   known checks. Your 4–6 focused testing hours should be entirely on logic
   flaws, chains, and techniques no template has ever seen.
4. **Rate limiting must be enforced at the pipeline level.** A misconfigured
   pipeline running overnight can cause a programme to ban your IP or terminate
   your account. Build the limits in, do not rely on yourself remembering.
5. **Notify is your early warning system.** The first researcher to examine
   a new subdomain wins the race. Automation plus notification collapses that
   window from days to minutes.

---

## Exercises

1. Build the complete pipeline from Part 3 and run it against a VDP target
   with broad wildcard scope. Let it run for 24 hours. Document:
   (a) Total subdomains found.
   (b) New subdomains appearing after the first run.
   (c) Nuclei findings requiring manual triage.

2. Configure the Notify integration with either Slack, Discord, or Telegram.
   Trigger a test notification manually to confirm it works end-to-end.

3. Write a custom Nuclei template for one vulnerability class from your
   specialisation. Add it to the pipeline's custom template directory.
   Run the pipeline against a lab target and confirm the template fires.

4. Simulate a "new subdomain appeared" scenario: add a new entry to a
   test domain's all-subdomains.txt and run detect-new.sh. Confirm a
   notification fires with the correct content.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q265.1, Q265.2 …).
> Follow-up questions use hierarchical numbering (Q265.1.1, Q265.1.2 …).

---

## Navigation

← Previous: [Day 264 — Nuclei Templates and Automation](DAY-0264-Nuclei-Templates-and-Automation.md)
→ Next: [Day 266 — Burp Extensions for Bug Bounty](DAY-0266-Burp-Extensions-for-Bug-Bounty.md)
