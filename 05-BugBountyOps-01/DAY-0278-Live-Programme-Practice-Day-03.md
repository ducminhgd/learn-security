---
title: "Live Programme Practice Day 3 — Authentication and Session Testing"
tags: [practice, live-programme, authentication, JWT, OAuth, session, bug-bounty,
       access-control, account-takeover, methodology]
module: 05-BugBountyOps-01
day: 278
related_topics:
  - Live Programme Practice Day 2 (Day 277)
  - JWT Advanced Attacks (Day 169)
  - OAuth Abuse Deep Dive (Day 171)
  - Account Takeover Chains (Day 174)
---

# Day 278 — Live Programme Practice Day 3: Authentication and Session Testing

> "Authentication is the front door. If it is broken, everything behind it
> is exposed regardless of how well the rest is built. Test auth before
> anything else. Not because it is most likely to be broken — but because
> the impact when it is broken is highest."
>
> — Ghost

---

## Goals

By the end of today's session you will have tested the complete authentication
surface and documented any leads.

**Time budget:** 5–6 hours.

---

## Checklist — Authentication Surface

Work through systematically. Check each off only after actually testing it.

### JWT Testing (if applicable)

```
[ ] Decode the JWT: jwt.io or python3 -c "import base64,json; ..."
    Header algorithm: ___
    Claims present: ___

[ ] Test algorithm confusion (RS256 → HS256):
    Get the public key from: /api/auth/keys, /.well-known/jwks.json, or header
    Forge with HS256 using the public key as secret
    Result: ___

[ ] Test alg: none:
    Forge token with {"alg":"none","typ":"JWT"}
    Result: ___

[ ] Test kid path traversal:
    kid: ../../../../dev/null  (with empty HMAC secret)
    Result: ___

[ ] Test expired token acceptance:
    Modify exp claim to a past timestamp
    Result: ___
```

### OAuth Testing (if applicable)

```
[ ] Identify authorization endpoint and redirect_uri parameter
[ ] Test redirect_uri bypass:
    - Add path: https://legit.example.com/callback/../evil
    - Add subdomain: https://evil.legit.example.com
    - Partial match: https://legit.example.com.evil.com
    Result: ___

[ ] CSRF on authorization endpoint:
    Missing state parameter? ___
    State is guessable/fixed? ___
    Result: ___

[ ] Token leakage via Referer header:
    Does the access_token appear in the URL? (implicit flow)
    Result: ___
```

### Session Management

```
[ ] Session token entropy test:
    Collect 10 session tokens from 10 different account logins
    Visible pattern? ___

[ ] Session fixation:
    Does login regenerate the session token? ___

[ ] Concurrent session limit:
    Multiple simultaneous sessions from different IPs allowed? ___

[ ] Session timeout:
    After how many minutes of inactivity does session expire? ___
```

### Password Reset

```
[ ] Endpoint: ___
[ ] Token in URL? (Referer leakage risk) ___
[ ] Token entropy: looks random? Length? ___
[ ] Host header injection:
    Add header: Host: evil.attacker.com
    Does reset email link use attacker domain? ___
[ ] Rate limiting on reset endpoint: ___
[ ] Token reuse (use same token twice): ___
```

### Account Registration / Enumeration

```
[ ] Different error messages for existing vs non-existing usernames: ___
[ ] Email case sensitivity (User@example.com vs user@example.com): ___
[ ] Username normalisation issues: ___
[ ] Race condition on account creation: ___
```

---

## Findings Log

For any finding that passes manual verification:

```
Finding #___ : ___
Status: Draft / Ready to submit
Evidence: (paste request/response)
Impact: ___
```

---

## Session Debrief

```
Auth model tested: ___
Issues found: ___
Most promising lead: ___
Next session focus: ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q278.1, Q278.2 …).

---

## Navigation

← Previous: [Day 277 — Live Programme Practice Day 2](DAY-0277-Live-Programme-Practice-Day-02.md)
→ Next: [Day 279 — Live Programme Practice Day 4](DAY-0279-Live-Programme-Practice-Day-04.md)
