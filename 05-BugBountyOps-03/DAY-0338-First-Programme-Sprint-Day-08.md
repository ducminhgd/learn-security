---
title: "First Programme Sprint Day 8 — Deep Recon and Third-Party Integrations"
tags: [live-programme, bug-bounty, deep-recon, third-party, OAuth, integrations, practice]
module: 05-BugBountyOps-03
day: 338
related_topics:
  - First Programme Sprint Day 7 (Day 337)
  - Recon Pipeline Automation (Day 265)
  - Weak Area Reinforcement Day 5 (Day 320)
---

# Day 338 — First Programme Sprint Day 8: Deep Recon and Third-Party Integrations

---

## Goals

Perform deep reconnaissance on lower-priority subdomains and
third-party integration points not tested in Days 331–337.
Third-party integrations (OAuth providers, payment processors, SSO) are
frequently misconfigured because they fall between ownership boundaries.

**Time budget:** 5–6 hours.

---

## Part 1 — Deep Subdomain Analysis

```bash
# Revisit live hosts list — focus on anything previously skipped
# Criteria: status 200/301 but not investigated, staging/dev/beta/internal labels

cat live-hosts.json | jq '.[] | select(.status_code == 200)' | \
  grep -E 'staging|dev|beta|internal|admin|api|test|preprod'

# Technology stack detection on remaining hosts
httpx -l remaining-hosts.txt -tech-detect -title -status-code

# Port scan on interesting subdomains (non-standard ports)
nmap -p 80,443,8080,8443,8888,3000,4000,5000,9000 interesting-host.TARGET.com

# JavaScript file analysis — extract endpoints from all live hosts
katana -list live-hosts-urls.txt -js-crawl -d 3 -silent | \
  grep -E '\.js$' | sort -u | head -50

# Analyse each JS file for API endpoints, keys, secrets
for js in $(cat js-files.txt); do
  curl -s "$js" | grep -E 'api_key|secret|password|token|AKIA|eyJ' \
    | grep -v "test\|example\|placeholder"
done
```

```
New subdomains worth investigating: ___
Technologies found on new hosts: ___
Secrets found in JS: ___
```

---

## Part 2 — Third-Party OAuth Integration Testing

```
OAuth providers integrated with target:
  [ ] Google  [ ] GitHub  [ ] Facebook  [ ] Microsoft  [ ] Slack  [ ] Other: ___

For each OAuth integration:
  Authorization URL: ___
  state parameter: present / absent
  redirect_uri validation: strict / loose / absent
  scope requested: ___
  response_type: code / token (implicit = red flag)
```

### OAuth Attack Log

```
Integration: ___  Provider: ___

Test 1 — Missing state:
  Remove state parameter from auth request → does provider complain? Y/N
  Craft CSRF attack: ___
  Result: ___

Test 2 — redirect_uri manipulation:
  Tested values:
    ___TARGET.com/callback          Result: ___
    TARGET.com.attacker.com/callback  Result: ___
    TARGET.com/callback?x=          Result: ___
    TARGET.com/../evil               Result: ___

Test 3 — Token in response (implicit flow):
  response_type changed to token → ___

Finding: ___  Severity: ___
```

---

## Part 3 — Payment / Checkout Integration

```
Payment processor: Stripe / PayPal / Braintree / custom
Integration type: client-side token / server-side
Test account available: Y/N

Tests run:
  [ ] Price manipulation in POST body
  [ ] Currency manipulation (USD → CNY)
  [ ] Quantity manipulation
  [ ] Coupon stacking
  [ ] Payment response replay
  [ ] Direct access to /order-confirmation without payment

Finding: ___  Severity: ___
```

---

## Part 4 — Webhook Endpoints

```
Webhook endpoints found:
  ___

Tests:
  [ ] SSRF via webhook URL registration
  [ ] No HMAC signature verification (can forge payloads)
  [ ] Webhook replay (reuse old signed payload)
  [ ] Event type manipulation (change event_type to admin action)

Finding: ___  Severity: ___
```

---

## Daily Findings Log

```
New finding #1: ___  Severity: ___  Evidence: ___
New finding #2: ___  Severity: ___  Evidence: ___

Pending triage on previous submissions:
  Report #___: Status: ___  Notes: ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q338.1, Q338.2 …).

---

## Navigation

← Previous: [Day 337 — First Programme Sprint Day 7](DAY-0337-First-Programme-Sprint-Day-07.md)
→ Next: [Day 339 — First Programme Sprint Day 9](DAY-0339-First-Programme-Sprint-Day-09.md)
