---
title: "Live Programme Practice Day 2 — Endpoint Discovery and Technology Mapping"
tags: [practice, live-programme, endpoint-discovery, ffuf, technology-stack,
       burp-suite, methodology, reconnaissance, bug-bounty]
module: 05-BugBountyOps-01
day: 277
related_topics:
  - Live Programme Practice Day 1 (Day 276)
  - ffuf and Custom Wordlists (Day 267)
  - Burp Extensions for Bug Bounty (Day 266)
  - Parameter Discovery and JS Analysis (Day 066)
---

# Day 277 — Live Programme Practice Day 2: Endpoint Discovery and Technology Mapping

> "You found the surface. Now you find the depth. Every endpoint is a door.
> You are not trying to open them today — you are building the map. A complete
> map is worth more than ten opened doors."
>
> — Ghost

---

## Goals

By the end of today's session you will have:

1. Completed endpoint fuzzing on your top 3 priority targets.
2. Built a custom wordlist from the target's JS files.
3. Established Burp proxy and configured all extensions.
4. Mapped the authentication flow and identified the auth model.
5. Documented all discovered endpoints for testing prioritisation.

**Time budget:** 5–6 hours.

---

## Block 1 — Custom Wordlist Build (60 min)

```bash
# Mine JS files from the target:
katana -u https://$PRIMARY_TARGET \
  -d 3 \
  -ef css,png,jpg,svg,ico,woff \
  -o katana-output.txt

cat katana-output.txt | grep -oP '(?<=["\x60])/[a-zA-Z0-9/_.-]+' | \
  sort -u > js-paths.txt

# Merge with SecLists:
cat js-paths.txt \
  ~/SecLists/Discovery/Web-Content/raft-medium-directories.txt \
  ~/SecLists/Discovery/Web-Content/api/api-endpoints.txt | \
  sort -u > custom-wordlist.txt

echo "Custom wordlist: $(wc -l < custom-wordlist.txt) entries"
```

---

## Block 2 — Endpoint Fuzzing (90 min)

Run against all 3 priority targets from Day 276:

```bash
# Per target, run with tuned filters:
# Step 1: Get baseline
curl -s -o /dev/null -w "%{http_code} %{size_download}" https://$TARGET/nonexistent12345

# Step 2: Fuzz with custom wordlist
ffuf -u "https://$TARGET/FUZZ" \
  -w custom-wordlist.txt \
  -rate 20 \
  -ac \
  -mc 200,201,204,301,302,401,403,500 \
  -o endpoints-$TARGET.json -of json

# Step 3: Review distribution
cat endpoints-$TARGET.json | jq -r '.results[] | "\(.status) \(.length) \(.url)"' | \
  sort | head -50
```

Discovered endpoints summary:
```
Target 1 ($TARGET1):
  Total: ___  Interesting: ___
  Top 5: ___, ___, ___, ___, ___

Target 2 ($TARGET2):
  Total: ___  Interesting: ___
  Top 5: ___, ___, ___, ___, ___
```

---

## Block 3 — Burp Suite Configuration and Browsing (90 min)

```
[ ] Configure Burp proxy (port 8080)
[ ] Install CA certificate in browser
[ ] Set scope to current programme targets only
[ ] Enable Autorize with low-privilege account cookie
[ ] Enable Active Scan++ and J2EEScan passive checks

Browsing session:
[ ] Register two test accounts (attacker + victim)
[ ] Note your account IDs and session tokens
[ ] Browse every feature as a logged-in user
[ ] Watch Autorize for any "Bypassed!" flags
[ ] Run Param Miner on 3–5 interesting endpoints in background
```

Burp browsing findings:
```
Autorize Bypassed! results: ___
Param Miner findings: ___
Interesting endpoints noted manually: ___
```

---

## Block 4 — Authentication Flow Mapping (60 min)

Map the complete authentication model:

```
Auth type: JWT / Session cookie / API key / Other: ___
Token location: Authorization header / Cookie / URL parameter
JWT algorithm (if JWT): ___
Session cookie flags: HttpOnly: Y/N  Secure: Y/N  SameSite: ___
Password reset endpoint: ___
MFA: Y/N  Type: ___
OAuth/SSO: Y/N  Provider: ___
```

Auth attack candidates identified:
```
1. ___
2. ___
3. ___
```

---

## Block 5 — Session and Daily Debrief

```
Endpoints discovered: ___
Custom wordlist entries (target-specific additions): ___
Most interesting endpoint found: ___
Auth model summary: ___
Potential leads for tomorrow: ___
Session duration: ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q277.1, Q277.2 …).

---

## Navigation

← Previous: [Day 276 — Live Programme Practice Day 1](DAY-0276-Live-Programme-Practice-Day-01.md)
→ Next: [Day 278 — Live Programme Practice Day 3](DAY-0278-Live-Programme-Practice-Day-03.md)
