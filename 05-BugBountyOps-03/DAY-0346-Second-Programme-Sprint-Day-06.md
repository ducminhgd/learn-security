---
title: "Second Programme Sprint Day 6 — Unexplored Features and Mobile/App Testing"
tags: [live-programme, bug-bounty, second-sprint, mobile, features, deep-test, practice]
module: 05-BugBountyOps-03
day: 346
related_topics:
  - Second Programme Sprint Day 5 (Day 345)
  - Mobile Security (A-04)
  - API Security (R-04)
---

# Day 346 — Second Programme Sprint Day 6: Unexplored Features and Mobile/App Testing

---

## Goals

Test application features not covered in Days 341–345.
If a mobile app is in scope, perform initial APK/API analysis.

**Time budget:** 5–6 hours.

---

## Feature Coverage Audit

```
Features present in the application:
  [ ] Search / filter       — tested: Y/N
  [ ] Comments / messaging  — tested: Y/N
  [ ] File upload           — tested: Y/N
  [ ] Export / download     — tested: Y/N
  [ ] Admin panel           — tested: Y/N
  [ ] Account settings      — tested: Y/N
  [ ] Notifications         — tested: Y/N
  [ ] Password change/reset — tested: Y/N
  [ ] 2FA setup / disable   — tested: Y/N
  [ ] Account deletion      — tested: Y/N
  [ ] Invitations / sharing — tested: Y/N
  [ ] Integrations / OAuth  — tested: Y/N
  [ ] Billing / payment     — tested: Y/N

Untested features selected for today: ___
```

---

## Feature Testing Log

### Feature 1: ___

```
Description: ___
How it works: ___

Attack approaches tried:
  [ ] ___  → Result: ___
  [ ] ___  → Result: ___
  [ ] ___  → Result: ___

Finding: Y/N  Type: ___  Severity: ___
```

### Feature 2: ___

```
Description: ___
Attack approaches: ___
Finding: Y/N  Type: ___  Severity: ___
```

---

## Mobile App Testing (if in scope)

```
Mobile app in scope: Y/N
Platform: Android / iOS

Android APK Analysis:
  APK downloaded from: ___  (Play Store / programme page)

  # Decompile with jadx
  jadx -d output/ app.apk

  # Look for hardcoded secrets
  grep -rE 'api_key|secret|password|AKIA|Bearer|token' output/

  # Look for cleartext HTTP traffic
  grep -rE 'http://' output/

  # Inspect AndroidManifest.xml
  cat output/resources/AndroidManifest.xml | grep -E 'exported|permission|intent'

  Secrets found: ___
  Exported activities (potential entry points): ___
  Cleartext traffic: Y/N

  Certificate pinning present: Y/N
  Bypass technique (if needed): ___
    frida -U -f PACKAGE -l ssl-unpin.js --no-pause
    OR objection -g PACKAGE explore → android sslpinning disable

  Interesting API calls captured after unpinning: ___
```

---

## 2FA Bypass Testing

```
2FA mechanism: SMS / TOTP / Email OTP / Hardware key

Tests:
  [ ] Attempt login without providing 2FA code
    Result: ___

  [ ] Submit empty 2FA code
    Result: ___

  [ ] Reuse a previously valid code
    Result: ___

  [ ] Brute-force 6-digit code (if no lockout)
    Rate limit: Y/N  |  Lockout after: ___ attempts
    Result: ___

  [ ] Response manipulation: change "requires_2fa": true to false
    Result: ___

  [ ] Skip 2FA endpoint entirely (request post-2FA resource directly)
    Result: ___

Finding: ___  Severity: ___
```

---

## Finding Log

```
Finding #1: ___  Severity: ___
Finding #2: ___  Severity: ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q346.1, Q346.2 …).

---

## Navigation

← Previous: [Day 345 — Second Programme Sprint Day 5](DAY-0345-Second-Programme-Sprint-Day-05.md)
→ Next: [Day 347 — Second Programme Sprint Day 7](DAY-0347-Second-Programme-Sprint-Day-07.md)
