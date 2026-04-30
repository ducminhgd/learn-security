---
title: "Live Programme Practice Day 12 — Nuclei Pipeline Run and Triage Sprint"
tags: [practice, live-programme, Nuclei, pipeline, automation, triage,
       delta-detection, bug-bounty, methodology]
module: 05-BugBountyOps-01
day: 287
related_topics:
  - Live Programme Practice Day 11 (Day 286)
  - Nuclei Templates and Automation (Day 264)
  - Recon Pipeline Automation (Day 265)
  - Tracking Findings and Notes (Day 268)
---

# Day 287 — Live Programme Practice Day 12: Nuclei Pipeline Run and Triage Sprint

> "Automation is how you scale. Today you run the pipeline end-to-end on your
> current target, triage everything it surfaces, and submit any new findings.
> The point is not the results Nuclei gives you — the point is your ability
> to quickly separate signal from noise and act on signal within the same
> session."
>
> — Ghost

---

## Goals

Run the complete recon pipeline. Triage all output. Submit findings that survive triage.

**Time budget:** 5–6 hours.

---

## Block 1 — Pipeline Run (90 min)

```bash
# 1. Update Nuclei templates first:
nuclei -update-templates

# 2. Refresh subdomain enumeration:
./recon/subdomain-enum.sh $TARGET

# 3. Check for new subdomains since last run:
./recon/detect-new.sh $TARGET
# NEW subdomains found: ___
# Each new subdomain: is it in scope? ___

# 4. Validate live hosts:
./recon/live-hosts.sh $TARGET
echo "Live hosts: $(wc -l < ./data/$TARGET/live-urls.txt)"

# 5. Run Nuclei with rate limiting:
nuclei \
  -list ./data/$TARGET/live-urls.txt \
  -severity critical,high,medium \
  -rate-limit 10 \
  -concurrency 5 \
  -t ~/nuclei-templates/http/exposures/ \
  -t ~/nuclei-templates/http/misconfiguration/ \
  -t ~/nuclei-templates/cves/ \
  -t ~/custom-templates/ \
  -o pipeline-results-$(date +%Y%m%d).txt \
  -jsonl

echo "Raw findings: $(wc -l < pipeline-results-*.txt)"
```

---

## Block 2 — Triage Sprint (120 min)

For each Nuclei finding, apply the triage workflow:

```
Finding: ___
Template: ___
Severity: ___

Step 1: Read template description — what does this check?
Step 2: Open matched URL in Burp → replicate request
Step 3: Inspect response — does evidence match description?
Step 4: Assess exploitability — real impact?
Step 5: Decision: Report / Hold / False Positive

Result: ___
```

Summary:
```
Total raw findings: ___
True positives: ___
False positives: ___
False positive rate: ___% (if high, which templates are generating FPs?)
```

---

## Block 3 — Submit Triaged Findings (60 min)

For each true positive:

```
[ ] Write full report using Day 283 template
[ ] CVSS calculated: ___
[ ] Reproduction confirmed
[ ] Submitted

Reports submitted today: ___
```

---

## Block 4 — Custom Template Development (60 min)

Based on the past 12 days of testing, write one custom Nuclei template
for a pattern you found manually that Nuclei missed:

```yaml
# custom-templates/[programme]-pattern.yaml
id: ___
info:
  name: "___"
  severity: ___
  description: "___"
  tags: custom,___

requests:
  - method: GET
    path:
      - "{{BaseURL}}/___"
    matchers:
      - type: ___
        ___
```

---

## Session Debrief

```
Pipeline completed successfully: Y/N
New subdomains discovered: ___
Nuclei true positives: ___
Reports submitted: ___
Custom template written: Y/N  Description: ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q287.1, Q287.2 …).

---

## Navigation

← Previous: [Day 286 — Live Programme Practice Day 11](DAY-0286-Live-Programme-Practice-Day-11.md)
→ Next: [Day 288 — Live Programme Practice Day 13](DAY-0288-Live-Programme-Practice-Day-13.md)
