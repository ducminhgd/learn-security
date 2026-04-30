---
title: "Second Programme Sprint Day 7 — Nuclei Custom Templates and Pipeline Run"
tags: [live-programme, bug-bounty, second-sprint, Nuclei, automation, custom-templates, practice]
module: 05-BugBountyOps-03
day: 347
related_topics:
  - Second Programme Sprint Day 6 (Day 346)
  - Nuclei Templates and Automation (Day 264)
  - Recon Pipeline Automation (Day 265)
---

# Day 347 — Second Programme Sprint Day 7: Nuclei Custom Templates and Pipeline Run

---

## Goals

Write programme-specific Nuclei templates based on what you know about the
target's tech stack. Run the full automation pipeline and review outputs.

**Time budget:** 4–5 hours.

---

## Target Tech Stack Analysis

```
Framework / CMS: ___
Language: ___
Database: ___
Auth library: ___
Third-party services: ___

Known vulnerabilities for this stack (CVEs / common misconfigs):
  ___
  ___
```

---

## Custom Nuclei Template 1 — Programme-Specific

```yaml
id: TARGET2-custom-idor

info:
  name: TARGET2 IDOR on Resource Endpoint
  author: ghost-student
  severity: high
  description: Tests for BOLA on /api/v1/RESOURCE/{id} endpoint
  tags: idor,bola,custom

requests:
  - method: GET
    path:
      - "{{BaseURL}}/api/v1/RESOURCE/1"
      - "{{BaseURL}}/api/v1/RESOURCE/2"
      - "{{BaseURL}}/api/v1/RESOURCE/100"
    headers:
      Authorization: "Bearer {{token}}"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "email"
          - "user_id"
        condition: or

    extractors:
      - type: regex
        regex:
          - '"user_id":\s*(\d+)'
```

---

## Custom Nuclei Template 2 — CVE or Known Issue

```yaml
id: TARGET2-exposed-debug

info:
  name: Exposed Debug / Actuator Endpoint
  author: ghost-student
  severity: medium
  description: >
    Checks for Spring Boot Actuator or debug endpoints exposed
    on the target application.
  tags: exposure,config,custom

requests:
  - method: GET
    path:
      - "{{BaseURL}}/actuator"
      - "{{BaseURL}}/actuator/env"
      - "{{BaseURL}}/actuator/beans"
      - "{{BaseURL}}/debug"
      - "{{BaseURL}}/_debug"

    matchers-condition: or
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "systemProperties"
          - "classLoader"
          - "spring.datasource"
```

---

## Full Pipeline Run

```bash
# 1. Fresh subdomain delta (new hosts since Day 341?)
subfinder -d TARGET2.com -silent | sort > p2-subs-day347.txt
diff p2-subs.txt p2-subs-day347.txt | grep '^>' | sed 's/^> //' > p2-new-subs.txt
echo "New subdomains since Day 341: $(wc -l < p2-new-subs.txt)"

# 2. Live check on new subs
cat p2-new-subs.txt | httpx -silent -status-code -o p2-new-live.txt

# 3. Run Nuclei — community + custom templates
nuclei -l p2-live.txt \
  -t ~/nuclei-templates/ \
  -t ~/custom-templates/TARGET2/ \
  -severity medium,high,critical \
  -rate-limit 20 \
  -o p2-nuclei-day347.txt

# 4. Review
grep -v "INFO" p2-nuclei-day347.txt | sort -t '[' -k2
```

```
New subdomains found: ___
Nuclei results: ___
Custom template hits: ___
True positives requiring manual verification: ___
```

---

## Manual Verification of Nuclei Hits

```
Hit #1: ___  Template: ___
  Manual verification: ___
  Confirmed: Y/N  →  Severity: ___

Hit #2: ___  Template: ___
  Manual verification: ___
  Confirmed: Y/N  →  Severity: ___
```

---

## Finding Log

```
Finding from custom template: ___  Severity: ___
Finding from manual follow-up: ___  Severity: ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q347.1, Q347.2 …).

---

## Navigation

← Previous: [Day 346 — Second Programme Sprint Day 6](DAY-0346-Second-Programme-Sprint-Day-06.md)
→ Next: [Day 348 — Second Programme Sprint Day 8](DAY-0348-Second-Programme-Sprint-Day-08.md)
