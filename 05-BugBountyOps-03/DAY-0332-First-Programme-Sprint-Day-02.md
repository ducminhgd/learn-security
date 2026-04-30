---
title: "First Programme Sprint Day 2 — Authentication and Access Control Testing"
tags: [live-programme, bug-bounty, authentication, IDOR, access-control, practice]
module: 05-BugBountyOps-03
day: 332
related_topics:
  - First Programme Sprint Day 1 (Day 331)
  - Authentication Attacks (R-03)
  - Access Control Review (Day 195)
---

# Day 332 — First Programme Sprint Day 2: Authentication and Access Control Testing

---

## Goals

Test authentication mechanisms and access control on the selected programme.
Focus on highest-impact, highest-probability bugs for this type of application.

**Time budget:** 5–6 hours.

---

## Authentication Surface Mapping

```
Login mechanisms found:
  [ ] Password-based login
  [ ] SSO / OAuth (provider: ___)
  [ ] MFA (type: SMS / TOTP / hardware key)
  [ ] Magic link / passwordless
  [ ] API key

Session mechanism:
  [ ] Cookie-based  (name: ___)
  [ ] JWT  (location: header / cookie)
  [ ] Opaque token

Logout: ___  (does it invalidate server-side?)

Password reset: ___  (link-based / code-based / security questions)
```

---

## Authentication Testing Log

### Login Form

```
SQL injection test: ___  Result: ___
Username enumeration (timing): ___
  POST /login with valid user: ___ ms
  POST /login with invalid user: ___ ms
  Difference > 50ms: Y/N → potential timing oracle

MFA bypass:
  [ ] Test empty MFA code
  [ ] Test MFA code from previous valid session
  [ ] Test brute-force if no rate limit detected
  Result: ___
```

### Password Reset

```
Token format: ___  (UUID? sequential? base64-username?)
Token length: ___
Token expiry: ___
Token reuse: ___  (can same token be used twice?)
Account enumeration via different responses: Y/N
Host header injection in reset email: Y/N
  Payload: Host: attacker.com
  Email received: link domain changed? ___
```

### Session Management

```
JWT checks:
  Algorithm: ___
  alg:none accepted: Y/N
  Weak secret: Y/N  (tried: jwt_tool wordlist)
  Token contents: ___

Cookie checks:
  HttpOnly: Y/N
  Secure: Y/N
  SameSite: Strict / Lax / None / not set
  Predictable token: Y/N

Logout invalidation:
  Token still valid after logout: Y/N → session token not revoked
```

---

## Access Control (IDOR) Testing Log

```
Endpoints with numeric or UUID parameters in path / query:
  Endpoint: ___  Parameter: ___  Your value: ___  Tested values: ___
  Result: ___

Horizontal IDOR:
  Account 1 resource: ___
  Account 2 resource: ___  (access with Account 1 credentials)
  Data exposed: ___

Vertical privilege escalation:
  Admin endpoints found: ___
  Accessible as regular user: ___
  Data / action exposed: ___

Autorize Burp extension setup:
  [ ] Configured with two-session headers
  [ ] Red = access control missing
  Autorize findings: ___
```

---

## Findings Log

```
Finding #1:
  Endpoint: ___
  Type: ___
  Evidence: ___
  Severity estimate: ___
  Report ready: Y/N

Finding #2:
  Endpoint: ___
  Type: ___
  Evidence: ___
  Severity estimate: ___
  Report ready: Y/N
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q332.1, Q332.2 …).

---

## Navigation

← Previous: [Day 331 — First Programme Sprint Day 1](DAY-0331-First-Programme-Sprint-Day-01.md)
→ Next: [Day 333 — First Programme Sprint Day 3](DAY-0333-First-Programme-Sprint-Day-03.md)
