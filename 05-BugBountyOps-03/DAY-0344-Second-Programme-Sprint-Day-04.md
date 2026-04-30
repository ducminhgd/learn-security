---
title: "Second Programme Sprint Day 4 — Cloud and Infrastructure Testing"
tags: [live-programme, bug-bounty, second-sprint, cloud, infrastructure, S3, practice]
module: 05-BugBountyOps-03
day: 344
related_topics:
  - Second Programme Sprint Day 3 (Day 343)
  - HTB Cloud Series Day 5 (Day 310)
  - Weak Area Reinforcement Day 8 (Day 323)
---

# Day 344 — Second Programme Sprint Day 4: Cloud and Infrastructure Testing

---

## Goals

Test the cloud infrastructure and any exposed services on Programme 2.
Check for S3 misconfiguration, SSRF to metadata, and exposed cloud endpoints.

**Time budget:** 5–6 hours.

---

## Cloud Presence Detection

```bash
# Identify cloud provider from DNS / headers
host TARGET2.com
curl -I https://TARGET2.com | grep -i 'server\|x-amz\|via\|cloud'

# S3 bucket discovery
# From HTML source: look for s3.amazonaws.com references
curl -s https://TARGET2.com | grep -oE '[a-zA-Z0-9-]+\.s3[.-][a-zA-Z0-9.-]+amazonaws\.com'

# Common bucket name patterns
for pattern in TARGET2 TARGET2-assets TARGET2-uploads TARGET2-static TARGET2-media TARGET2-dev; do
  aws s3 ls s3://$pattern --no-sign-request 2>&1 | grep -v "NoSuchBucket\|Access Denied" \
    && echo "[+] Public bucket: $pattern"
done
```

```
Cloud provider: AWS / Azure / GCP / Other
CDN: Cloudflare / CloudFront / Fastly
S3 buckets found: ___
Public read: Y/N  |  Public write: Y/N
Sensitive content in bucket: ___
```

---

## SSRF Testing (Programme 2)

```
SSRF-susceptible endpoints identified:
  ___  (URL parameter / import / webhook / image fetch)

SSRF test results:
  127.0.0.1:         ___
  169.254.169.254:   ___  (AWS metadata)
  OOB callback:      ___  (interactsh hit: Y/N)

Cloud metadata access: Y/N
  Credentials obtained: Y/N
  IAM role: ___
```

---

## Exposed Service Enumeration

```bash
# Check non-standard ports on primary domain
nmap -sV -p 8080,8443,8888,3000,4000,5000,9000,9200,6379,27017 TARGET2.com

# Shodan query (external view)
# shodan host TARGET_IP

# Check for exposed admin panels
for path in /admin /manage /console /_admin /wp-admin /phpmyadmin /kibana; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://TARGET2.com$path")
  [ "$code" != "404" ] && echo "$path → $code"
done
```

```
Exposed services: ___
Admin panels reachable: ___
Interesting non-standard ports: ___
```

---

## Security Headers Audit

```bash
curl -I https://TARGET2.com | grep -E \
  'Content-Security-Policy|X-Frame-Options|X-Content-Type-Options|\
Strict-Transport-Security|Referrer-Policy|Permissions-Policy'
```

```
CSP present: Y/N  |  CSP blocks inline scripts: Y/N
X-Frame-Options: ___  (missing = clickjacking possible)
HSTS: Y/N  |  Max-age: ___
X-Content-Type-Options: nosniff Y/N

Missing headers (informational finding):
  ___
```

---

## Finding Log

```
Finding #1: ___  Severity: ___  Evidence: ___
Finding #2: ___  Severity: ___  Evidence: ___

Total findings Programme 2 so far (Days 341–344): ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q344.1, Q344.2 …).

---

## Navigation

← Previous: [Day 343 — Second Programme Sprint Day 3](DAY-0343-Second-Programme-Sprint-Day-03.md)
→ Next: [Day 345 — Second Programme Sprint Day 5](DAY-0345-Second-Programme-Sprint-Day-05.md)
