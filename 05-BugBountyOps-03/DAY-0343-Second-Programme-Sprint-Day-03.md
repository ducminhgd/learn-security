---
title: "Second Programme Sprint Day 3 — API and Authentication Deep Test"
tags: [live-programme, bug-bounty, second-sprint, API, authentication, JWT, practice]
module: 05-BugBountyOps-03
day: 343
related_topics:
  - Second Programme Sprint Day 2 (Day 342)
  - HTB API Series Day 5 (Day 305)
  - Weak Area Reinforcement Day 5 (Day 320)
---

# Day 343 — Second Programme Sprint Day 3: API and Authentication Deep Test

---

## Goals

Conduct a full API and authentication assessment on Programme 2.
Apply the improved checklists from the reinforcement block (Days 316–325).

**Time budget:** 5–6 hours.

---

## API Enumeration (Programme 2)

```bash
# All endpoints from JS + crawl + historical
katana -u https://TARGET2.com -js-crawl -d 5 -silent | tee p2-endpoints.txt
gau TARGET2.com >> p2-endpoints.txt
sort -u p2-endpoints.txt | grep -E '/api/|/v[0-9]+/' > p2-api-endpoints.txt

# Parameter discovery on API endpoints
ffuf -u "https://TARGET2.com/api/v1/FUZZ" \
  -w /wordlists/api-words.txt -mc 200,201,204,401,403 -o p2-api-fuzz.json
```

```
API base path: ___
Endpoints found: ___
Authenticated endpoints: ___
Unauthenticated endpoints: ___
API documentation: Y/N  (URL: ___)
```

---

## Authentication Deep Test

### JWT Analysis

```
JWT found: Y/N
  Location: Authorization header / Cookie: ___
  Decode:
    Header: ___
    Payload: ___
    Algorithm: ___

Attacks tried:
  [ ] alg:none — Result: ___
  [ ] HS256/RS256 confusion — Result: ___
  [ ] Weak secret crack (jwt_tool):
      python3 jwt_tool.py TOKEN -C -d /wordlists/common.txt
      Result: ___
  [ ] kid injection (if kid claim present):
      kid: "../../../../dev/null" → sign with empty string
      Result: ___
  [ ] jwk injection (add attacker-controlled jwk to header):
      Result: ___

Finding: ___  Severity: ___
```

### Session Token Analysis

```
Token format: ___
Entropy sufficient: Y/N
HttpOnly: Y/N  |  Secure: Y/N  |  SameSite: ___

Post-logout token validity: ___
  Test: copy token before logout → send request after logout → accepted: Y/N
```

---

## API Authorization Testing (BOLA/BFLA)

```
Object with IDs found:
  Resource: ___  ID pattern: ___  (numeric / UUID / slug)

Account 1 ID: ___
Account 2 ID: ___

Cross-account access tests:
  GET /api/v1/resources/ACCOUNT2_ID  with Account1 auth: ___
  PATCH /api/v1/resources/ACCOUNT2_ID  with Account1 auth: ___
  DELETE /api/v1/resources/ACCOUNT2_ID  with Account1 auth: ___

Autorize results: ___  (red = missing access control)

BFLA — admin actions tested:
  Endpoint: ___  As regular user: accessible Y/N
```

---

## Finding Log

```
Finding #1: ___  Type: ___  Severity: ___
Finding #2: ___  Type: ___  Severity: ___

Evidence complete: Y/N
Report drafted: Y/N
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q343.1, Q343.2 …).

---

## Navigation

← Previous: [Day 342 — Second Programme Sprint Day 2](DAY-0342-Second-Programme-Sprint-Day-02.md)
→ Next: [Day 344 — Second Programme Sprint Day 4](DAY-0344-Second-Programme-Sprint-Day-04.md)
