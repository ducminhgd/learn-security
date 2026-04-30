---
title: "Burp Extensions for Bug Bounty — Active Scan++, Autorize, Param Miner, J2EEScan"
tags: [burp-suite, extensions, Active-Scan-plus-plus, Autorize, Param-Miner, J2EEScan,
       bug-bounty, automation, access-control, parameter-discovery, web-testing]
module: 05-BugBountyOps-01
day: 266
related_topics:
  - Burp Suite Setup Proxy Repeater (Day 022)
  - Burp Lab Episode 1 (Day 023)
  - Access Control and IDOR (Days 101–112)
  - Recon Pipeline Automation (Day 265)
---

# Day 266 — Burp Extensions for Bug Bounty

> "Burp out of the box is a good tool. Burp with the right extensions is a
> force multiplier. Autorize runs your access control checks automatically
> while you browse. Param Miner finds parameters you never would have looked
> for. These extensions do not replace your skill — they amplify it.
> Understand what each one does and does not check before you trust its output."
>
> — Ghost

---

## Goals

By the end of today's session you will be able to:

1. Install and configure the four core bug bounty extensions.
2. Use Autorize to automate IDOR and broken access control detection.
3. Use Param Miner to discover hidden and unkeyed parameters.
4. Use Active Scan++ for enhanced active scanning coverage.
5. Use J2EEScan for Java EE / Spring-specific checks.

**Time budget:** 3–4 hours.

---

## Prerequisites

| Requirement | Covered in |
|---|---|
| Burp Suite proxy and Repeater | Days 022–024 |
| Access control and IDOR | Days 101–112 |
| HTTP parameters and headers | Days 017–028 |

---

## Part 1 — Extension Installation

All four extensions are available in the BApp Store within Burp:

```
Burp Suite → Extensions → BApp Store → Search for each name → Install
```

Or install from JAR for community (non-Pro) Burp:

```
Burp Suite → Extensions → Installed → Add → Select JAR file
```

| Extension | Author | Purpose |
|---|---|---|
| Active Scan++ | PortSwigger Research | Enhanced checks beyond Burp's built-in scanner |
| Autorize | Regala | Automated broken access control testing |
| Param Miner | PortSwigger Research | Hidden parameter and cache key discovery |
| J2EEScan | ilmila | Java EE framework-specific vulnerability checks |

---

## Part 2 — Autorize: Automated Access Control Testing

Autorize intercepts every request you make as a high-privileged user and
automatically replays each one using a low-privileged user's session. It
flags any response that returns the same content — indicating a missing
access control check.

### Setup

1. Log in with a **victim** account (User B — lower privileges).
2. Copy the victim's `Cookie` header value.
3. Open Autorize → Configuration tab.
4. Paste the victim's cookie into the "Cookie of low privileged user" field.
5. Enable Autorize (green button).
6. Browse the application as a **high-privileged** user (User A — admin/moderator).
7. Autorize automatically replays every request using User B's cookie.

```
Autorize status indicators:
  Bypassed! (red)    — response with victim cookie matches original
  Enforced! (green)  — response with victim cookie is different (403, empty, etc.)
  Is Enforced? (yellow) — response differs but needs manual review
```

### What to Look For

- Any "Bypassed!" finding on a sensitive endpoint is a potential IDOR
  or broken access control.
- Paths like `/api/v1/admin/*`, `/api/v1/users/*/profile`, `/account/settings`
  are highest priority.

### Autorize Filters

Configure Autorize to filter out noise:

```
Ignore extension: .css .js .png .jpg .ico .svg .woff .ttf .gif .json
Ignore endpoint containing: /static/ /assets/ /media/ /cdn/
Filter status codes: Exclude 304 (not modified, irrelevant for auth checks)
```

### Exporting Results

```
Autorize → Export → CSV
```

Columns you care about: Method, URL, Original Status, Modified Status,
Length Difference. Sort by "Modified Status == 200" to find bypassed endpoints.

---

## Part 3 — Param Miner: Hidden Parameter Discovery

Web applications often have undocumented parameters that affect behaviour.
Param Miner mines headers, query parameters, and POST body parameters using
a large wordlist combined with intelligent inference.

### Setup

Install Param Miner from BApp Store. No special configuration needed.

### Usage

**Right-click on any request in Proxy History → Param Miner → Guess (params / headers / cookies)**

```
Options in Param Miner:
  Guess headers    — Look for hidden/undocumented request headers
  Guess params     — Add query or body parameters to the request
  Guess cookies    — Hidden cookie names
```

Param Miner sends requests with each candidate parameter and compares
responses to the baseline. Any statistically significant difference flags
the parameter as potentially interesting.

### What Param Miner Finds

- **Cache keys:** Hidden parameters that affect responses but are not
  included in cache keys — enables web cache poisoning.
  Example: `utm_source`, `X-Forwarded-Host`, `X-Original-URL`

- **Undocumented features:** Hidden flags that enable debug output, change
  output format, or enable admin features.
  Example: `debug=1`, `format=raw`, `export=csv`

- **CORS / origin headers:** Undocumented `Origin` variants that bypass
  CORS restrictions.

### Example: Finding a Web Cache Poisoning Vector

```
1. Open a cached page (static file or public endpoint with caching).
2. Right-click → Param Miner → Guess headers.
3. Param Miner runs automatically.
4. Result: X-Forwarded-Host detected — responses differ when set.
5. Verify: does the application reflect X-Forwarded-Host in a
   Location header or in a <link> or <script> src attribute?
6. If yes: cache poisoning vector.
```

---

## Part 4 — Active Scan++: Enhanced Scanning

Active Scan++ adds detection for vulnerability classes that Burp's built-in
scanner misses or underscores:

- XML injection (XXE in unexpected places)
- Code injection (SSTI, eval-based)
- Deserialisation issues
- CORS misconfiguration
- Header injection (CRLF)
- Template injection via Twig / Jinja2 / Smarty

### Usage

Active Scan++ integrates transparently. Once installed, it enhances Burp's
active scan automatically. When you run a Burp active scan, Active Scan++
adds its checks on top.

```
Proxy History → Select request → Right-click → Scan → Active Scan
(Active Scan++ runs alongside Burp scanner automatically)
```

### Key Additional Checks

| Check | What it finds |
|---|---|
| HTTP header injection | CRLF injection via user-controlled headers |
| SSRF | URL parameters that trigger server-side fetches |
| XXE | XML endpoints with DTD processing enabled |
| SSTI | Server-side template engines evaluating user input |
| RCE via deserialisation | Java/PHP/Python deserialisation in endpoints |

---

## Part 5 — J2EEScan: Java EE Specific Checks

If the target uses Java EE, Spring, Struts, or WebLogic, J2EEScan adds
framework-specific checks:

- Spring Actuator endpoints (`/actuator`, `/env`, `/heapdump`)
- Struts2 OGNL injection (CVE patterns)
- Apache Shiro deserialization
- JBoss remote code execution
- ViewState tampering (JSF)
- WebLogic deserialization (T3 protocol detection)

### Usage

Like Active Scan++, J2EEScan integrates with Burp's active scanner.
Additionally, it adds passive checks that fire as you browse.

```
Manual trigger: Proxy History → request → Right-click → Extensions → J2EEScan → Scan
```

### Spring Actuator Fingerprinting

```bash
# Before running J2EEScan, confirm target uses Spring:
curl -s https://target.example.com/actuator | jq .
# If you get a JSON response with "_links", Spring Actuator is exposed.

# Check for sensitive endpoints:
for ep in env beans heapdump mappings logfile info health; do
  echo -n "${ep}: "
  curl -s -o /dev/null -w "%{http_code}" https://target.example.com/actuator/${ep}
  echo
done
```

---

## Part 6 — Extension Workflow Integration

Effective extension use requires a workflow:

```
1. Start Burp, configure proxy.
2. Enable Autorize with victim account cookie.
3. Browse the entire application as admin/high-priv user.
4. After browsing session, review Autorize findings.
   Tag "Bypassed!" results for manual verification.
5. On interesting endpoints, right-click → Param Miner → Guess params + headers.
6. Let Param Miner run in background while you continue manual testing.
7. After 30 minutes, review Param Miner results.
8. Run Active Scan on 5–10 most interesting endpoints.
9. Review J2EEScan passive findings from the Issues tab.
```

---

## Key Takeaways

1. **Autorize reduces access control testing from hours to minutes.** Log in
   with two accounts, browse once, and it checks every endpoint for IDOR/BAC
   automatically. Manual verification remains required — but Autorize surfaces
   the candidates.
2. **Param Miner is your cache poisoning radar.** If a target uses a CDN and
   Param Miner detects hidden headers that affect responses, you likely have a
   cache poisoning vector. This is consistently one of the highest-payout
   technique categories.
3. **Active Scan++ does not replace manual testing.** It catches what Burp
   misses in the template injection and header injection space. It does not
   catch logic flaws, authentication chains, or second-order vulnerabilities.
4. **J2EEScan is essential when the target runs Java.** Spring Actuator exposure
   alone has produced hundreds of critical findings across major programmes.
   Check it in the first 10 minutes on any Java target.
5. **Extensions generate noise.** Every finding from every extension requires
   manual verification. Never report an extension finding without reproducing
   it by hand and confirming impact.

---

## Exercises

1. Set up Autorize with a low-privilege account on Juice Shop or DVWA.
   Browse the application as an admin. Export Autorize results. How many
   "Bypassed!" findings are true positives?

2. Use Param Miner against the cache poisoning lab (Day 129 — if still running).
   Does Param Miner detect the unkeyed header before you tell it to look?
   How does its output compare to manual testing?

3. Install all four extensions. Against a Spring Boot lab app (or any Java
   app), trigger J2EEScan passive checks. Does it detect any actuator endpoints?

4. On any lab target, combine Autorize + Param Miner in the same session.
   Document: (a) What each extension found independently.
   (b) Did either extension's finding lead to the other? (e.g., a Param Miner
   hidden parameter that opens a new Autorize bypass?)

---

## Questions

> Add your questions here. Each question gets a Global ID (Q266.1, Q266.2 …).
> Follow-up questions use hierarchical numbering (Q266.1.1, Q266.1.2 …).

---

## Navigation

← Previous: [Day 265 — Recon Pipeline Automation](DAY-0265-Recon-Pipeline-Automation.md)
→ Next: [Day 267 — ffuf and Custom Wordlists](DAY-0267-ffuf-and-Custom-Wordlists.md)
