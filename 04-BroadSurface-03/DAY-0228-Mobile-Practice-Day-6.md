---
title: "Mobile Practice Day 6 — Bug Bounty Recon on a Live Mobile Programme"
tags: [android, ios, bug-bounty, practice, recon, scope-analysis, live-programme,
       endpoint-discovery, HackerOne, methodology]
module: 04-BroadSurface-03
day: 228
related_topics:
  - Mobile Bug Bounty Methodology (Day 220)
  - Mobile API Attack Surface (Day 219)
  - Bug Bounty Recon Methodology (Day 72)
  - Bug Bounty Platforms Overview (Day 261)
---

# Day 228 — Mobile Practice Day 6: Bug Bounty Recon on a Live Programme

> "This is not a lab. This is the actual work. Read the programme policy.
> Download the app. Decompile it. Set up the proxy. You have everything
> you need. The only thing I can not give you is the hours — that part
> is yours."
>
> — Ghost

---

## Goals

By the end of today's practice session you will have:

1. Identified one live public bug bounty programme with meaningful Android scope.
2. Downloaded, decompiled, and statically analysed the target app.
3. Configured Burp + Frida and intercepted live API traffic.
4. Built an endpoint inventory and IDOR test list.
5. Documented all findings — including non-findings (what you tested and ruled out).

**Time budget:** 6–8 hours.

**⚠️ Ethics reminder:** Only test accounts you own and control. Do not test
IDOR by accessing other real users' data. If you find a vulnerability, do not
confirm impact beyond your own account. Report promptly.

---

## Step 1 — Programme Selection (30 min)

```
1. Go to https://hackerone.com/programs
2. Filter: Asset Type = Android or iOS
3. Filter: Bounty = Any
4. Sort by: Recently updated (active programmes)

Selection criteria:
- Android APK listed explicitly in scope
- API subdomain (api.example.com) in scope
- Recent activity (reports acknowledged within 2 weeks)
- Payout table present
- Private invite OK if you have one; public programmes preferred for now

Note the programme name, the in-scope assets, and the explicit OOS exclusions.
```

---

## Step 2 — App Acquisition and Static Recon (2 hours)

```bash
# Download from Play Store via your device
adb pull <apk-path> target.apk

# Or use gplaydl or raccoon (legal download tools for apps you own)

# Static analysis checklist:
apktool d target.apk -o decoded/
jadx target.apk -d jadx_out/

# Manifest audit
cat decoded/AndroidManifest.xml

# Secret hunting
cd jadx_out/
rg -i "(api_key|AWS|firebase|stripe|twilio|sendgrid)" --type java -n
rg '"https?://[^"]+' --type java -o | sort -u | grep -v "google\|android\|schema"

# Endpoint enumeration (Retrofit or equivalent)
rg "@(GET|POST|PUT|DELETE|PATCH)" --type java -A 1 | grep '"/'
```

Document: what did you find? What endpoints did you identify?

---

## Step 3 — Dynamic Analysis (2 hours)

```bash
# Frida server start
adb shell su -c "/data/local/tmp/frida-server &"

# Pinning bypass
frida -U -f <package> -l ssl_bypass.js --no-pause

# Burp intercept
# Confirm HTTPS traffic visible in Burp
# Use all features of the app for 30 min

# Export Burp site map:
# Target → Site Map → right-click domain → Save selected items
```

Build API inventory in a spreadsheet:

| Method | Path | Auth? | Params | Notes |
|---|---|---|---|---|
| POST | /v2/login | No | email, password | — |
| … | … | … | … | … |

---

## Step 4 — Testing (2 hours)

For each endpoint with a user-specific ID:

```bash
# Test IDOR: login as Account A, access Account B's data
curl -H "Authorization: Bearer $TOKEN_A" \
     "https://api.target.com/v2/users/$USER_B_ID/profile"

# Mass assignment: add extra fields to every POST body
# Rate limiting: 50 requests to login endpoint
# Version abuse: change v2 to v1 in all paths
```

---

## Step 5 — Report (1 hour)

For any finding:

1. Write a draft report following the format from Day 220.
2. Assign CVSS score.
3. Confirm: is the finding in scope?
4. Confirm: do you have a reproducible PoC using only your own account?

If nothing found today: that is normal. Document what you tested.
A "null result" is still useful — you know those paths are cleaner.

---

## Reflection

1. Programme selection: why did you choose this programme?
2. What was the most interesting thing in the decompiled code?
3. What is the highest-risk API endpoint you found and why?
4. Did you find anything reportable? If yes: what is your confidence level?
5. Would you return to this programme? Why or why not?

---

## Navigation

← Previous: [Day 227 — Mobile Practice Day 5](DAY-0227-Mobile-Practice-Day-5.md)
→ Next: [Day 229 — Mobile Practice Day 7](DAY-0229-Mobile-Practice-Day-7.md)
