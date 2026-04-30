---
title: "First Programme Sprint Day 3 — Injection and API Testing"
tags: [live-programme, bug-bounty, injection, SQLi, SSRF, API, practice]
module: 05-BugBountyOps-03
day: 333
related_topics:
  - First Programme Sprint Day 2 (Day 332)
  - Web Exploitation (R-02)
  - API Security (R-04)
---

# Day 333 — First Programme Sprint Day 3: Injection and API Testing

---

## Goals

Test for injection vulnerabilities and enumerate the API surface of the target.
Document all endpoints, parameters, and response behaviours.

**Time budget:** 5–6 hours.

---

## API Discovery

```bash
# Extract API endpoints from JS files
katana -u https://TARGET.com -js-crawl -silent | grep -E '/api/'

# getallurls (gau) — historical URLs
gau TARGET.com | grep -E '/api/|/v[0-9]/'

# ffuf — common API paths
ffuf -u https://TARGET.com/FUZZ -w /wordlists/api-endpoints.txt \
  -fc 404 -mc all -o api-fuzz.json

# Check for API documentation
curl -s https://TARGET.com/swagger.json
curl -s https://TARGET.com/openapi.yaml
curl -s https://TARGET.com/api-docs
curl -s https://TARGET.com/graphql  -X POST -d '{"query":"{__schema{types{name}}}"}'
```

```
API version: v1 / v2 / other
Base path: ___
Auth method: Bearer / API key / Cookie / None
Documentation found: Y/N  (URL: ___)
Interesting endpoints: ___
```

---

## SQL Injection Testing Log

```
Parameter tested: ___  Endpoint: ___
Method: GET / POST / Header / Cookie

Detection payloads tried:
  '                   Result: ___
  ''                  Result: ___
  ' AND 1=1--         Result: ___
  ' AND 1=2--         Result: ___
  ' AND SLEEP(5)--    Result: ___ (time: ___ sec)

Error messages observed:
  ___

SQLi type confirmed: Error-based / Boolean-blind / Time-blind / Union / None
Automated scan: sqlmap -u "URL" -p PARAM --level 3 --risk 2
  sqlmap result: ___
```

---

## SSRF Testing Log

```
Endpoints with URL/host parameters:
  Endpoint: ___  Parameter: ___

SSRF tests:
  http://127.0.0.1:80/   Result: ___
  http://BURP_COLLAB/    Result: ___  (OOB callback: Y/N)
  http://169.254.169.254/ Result: ___

Internal services reached: ___
Data returned: ___
```

---

## API-Specific Testing

```
BOLA / IDOR on object IDs:
  Endpoint: ___  Object type: ___
  Other user's ID: ___  Accessible: Y/N

Mass assignment:
  Endpoint: ___  (registration / profile update / order creation)
  Extra fields injected: ___
  Result: ___

GraphQL (if present):
  Introspection enabled: Y/N
  Hidden fields found: ___
  Injection in argument: Y/N
  Result: ___

Verb tampering:
  Original method: POST
  Changed to: PUT / PATCH / GET → different behaviour: ___

HTTP parameter pollution:
  email=a@x.com&email=b@x.com → which wins: ___
```

---

## Findings Log

```
Finding #1:
  Type: ___
  Endpoint: ___
  Payload: ___
  Evidence: ___
  Severity: ___

Finding #2:
  Type: ___
  Endpoint: ___
  Evidence: ___
  Severity: ___

No findings today: Y/N
  If yes — dead end analysis:
    Technique most likely to work on this target: ___
    Technique to pivot to tomorrow: ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q333.1, Q333.2 …).

---

## Navigation

← Previous: [Day 332 — First Programme Sprint Day 2](DAY-0332-First-Programme-Sprint-Day-02.md)
→ Next: [Day 334 — First Programme Sprint Day 4](DAY-0334-First-Programme-Sprint-Day-04.md)
