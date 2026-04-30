---
title: "Live Programme Practice Day 6 — API Surface Testing"
tags: [practice, live-programme, API, REST, GraphQL, BOLA, mass-assignment,
       rate-limiting, bug-bounty, methodology]
module: 05-BugBountyOps-01
day: 281
related_topics:
  - Live Programme Practice Day 5 (Day 280)
  - OWASP API Top 10 (Day 146)
  - BOLA and BFLA (Day 148)
  - GraphQL Attack Lab (Day 150)
---

# Day 281 — Live Programme Practice Day 6: API Surface Testing

> "Every modern web application has an API. Most are documented poorly,
> versioned inconsistently, and secured even worse. The API is usually where
> the bugs live — because developers build the UI carefully and the API
> as an afterthought."
>
> — Ghost

---

## Goals

Complete an API-focused testing session applying OWASP API Top 10 methodology.

**Time budget:** 5–6 hours.

---

## Block 1 — API Discovery and Enumeration (60 min)

```bash
# Check for API documentation:
for path in swagger.json openapi.json api-docs v1/swagger v2/swagger \
            api/swagger api/docs swagger-ui.html redoc graphql; do
  echo -n "$path: "
  curl -s -o /dev/null -w "%{http_code}" https://$TARGET/$path
  echo
done

# Check for versioned APIs:
for ver in v1 v2 v3 api/v1 api/v2 api/v3 rest/v1; do
  echo -n "$ver: "
  curl -s -o /dev/null -w "%{http_code}" https://$TARGET/$ver/
  echo
done

# Check for GraphQL:
curl -s -X POST https://$TARGET/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{__typename}"}'
```

API endpoints documented:
```
1. ___
2. ___
3. ___
```

---

## Block 2 — OWASP API Top 10 Checklist (120 min)

```
API1 — Broken Object Level Authorization (BOLA)
[ ] Access another user's resources via API with your token
    Endpoint tested: ___  Result: ___

API2 — Broken Authentication
[ ] Missing token validation on any endpoint
    Result: ___

API3 — Broken Object Property Level Authorization
[ ] Can you see properties in API responses not shown in UI?
    Result: ___
[ ] Mass assignment: inject unexpected properties in PUT/POST
    Result: ___

API4 — Unrestricted Resource Consumption
[ ] Can you trigger expensive operations without rate limiting?
    Result: ___

API5 — Broken Function Level Authorization (BFLA)
[ ] Admin API endpoints accessible to regular users?
    Endpoint: ___  Result: ___

API6 — Unrestricted Access to Sensitive Business Flows
[ ] Business-critical flows (purchase, withdrawal) without rate limiting?
    Result: ___

API7 — Server Side Request Forgery
[ ] (Covered in Day 280)

API8 — Security Misconfiguration
[ ] Debug endpoints (/debug, /trace, /actuator)?
    Result: ___

API9 — Improper Inventory Management
[ ] Deprecated API version accessible?
    Result: ___

API10 — Unsafe Consumption of APIs
[ ] API using external data without validation?
    Result: ___
```

---

## Block 3 — GraphQL Testing (60 min, if applicable)

```bash
# Run introspection query:
curl -s -X POST https://$TARGET/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name fields { name } } } }"}'

# If introspection disabled, try field suggestion:
curl -s -X POST https://$TARGET/graphql \
  -d '{"query": "{ user { privateField } }"}'
# Look for "Did you mean..." suggestions — reveals field names

# Test field-level auth bypass:
# Add sensitive fields (password, token, role) to a user query
```

---

## Block 4 — Findings Consolidation (60 min)

```
[ ] Review all findings from Days 276–281
[ ] Draft the top 3 most promising reports
[ ] Assess chain potential between findings
[ ] Prioritise which to submit first

Top findings this week:
1. Title: ___  Severity: ___  Status: ___
2. Title: ___  Severity: ___  Status: ___
3. Title: ___  Severity: ___  Status: ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q281.1, Q281.2 …).

---

## Navigation

← Previous: [Day 280 — Live Programme Practice Day 5](DAY-0280-Live-Programme-Practice-Day-05.md)
→ Next: [Day 282 — Live Programme Practice Day 7](DAY-0282-Live-Programme-Practice-Day-07.md)
