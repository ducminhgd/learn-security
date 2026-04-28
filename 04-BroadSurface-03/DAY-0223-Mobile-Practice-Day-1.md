---
title: "Mobile Practice Day 1 — HackTheBox Mobile Challenges: APK Static Analysis Sprint"
tags: [android, practice, CTF, HackTheBox, static-analysis, jadx, secret-hunting,
       AndroidManifest, beginner-mobile]
module: 04-BroadSurface-03
day: 223
related_topics:
  - Android Static Analysis (Day 212)
  - Android Static Analysis Lab (Day 213)
  - Mobile Bug Bounty Methodology (Day 220)
---

# Day 223 — Mobile Practice Day 1: Static Analysis Sprint

> "Practice days are not rest days. They are the days you find out if you
> actually learned it or just read it. Pick up the APK. Open the decompiler.
> Don't touch the hints until you have genuinely tried."
>
> — Ghost

---

## Goals

By the end of today's practice session you will have:

1. Completed at least 2 HackTheBox Android challenges using only static analysis.
2. Found at least 1 hardcoded secret and 1 exported component issue.
3. Written a one-page finding summary for each challenge.
4. Identified gaps in your static analysis workflow and noted them.

**Time budget:** 6–8 hours.

---

## Practice Targets

### Target 1 — HackTheBox: APK Challenge (Difficulty: Easy)

**Platform:** HackTheBox (https://www.hackthebox.com/)

```
Category: Mobile
Search for: "APK" or filter by Mobile challenges
Recommended (if available): "APKrypt", "Manager", "Pinned"
```

**Workflow for today:**

```bash
# 1. Download the challenge APK from HTB
# 2. Static analysis only — no emulator, no Frida

# Decompile
jadx challenge.apk -d jadx_out/
apktool d challenge.apk -o decoded/

# Read manifest
cat decoded/AndroidManifest.xml | grep -E "exported|scheme|debuggable"

# Hunt secrets
cd jadx_out/
rg -i "(api_key|password|secret|token|flag)" --type java -n
rg '"https?://' --type java -n
rg "FLAG\{" --type java -n   # flags in CTF challenges are sometimes hardcoded

# Check resources
cat decoded/res/values/strings.xml | grep -i "flag\|key\|secret"
cat decoded/assets/*.json 2>/dev/null
```

### Target 2 — HTB or DIVA Challenge

Attempt one of the DIVA (Damn Insecure and Vulnerable App) challenges:

```
DIVA challenges (from the DIVA app's challenge list):
1. Insecure Logging
2. Hardcoding Issues
3. Insecure Data Storage (Part 1–4)
4. Input Validation Issues
5. Access Control Issues

Today's focus: challenges 1, 2, and 3-Part-1
```

**DIVA APK setup:**

```bash
wget https://github.com/payatu/diva-android/raw/master/DivaApplication.apk
adb install DivaApplication.apk

# Challenge 1 — Insecure Logging
# Goal: find what the app logs to logcat
adb logcat | grep "diva\|DIVA" &
# Interact with the app — what sensitive data appears in logcat?

# Challenge 2 — Hardcoding Issues
# Goal: find hardcoded credentials in the APK source
# Use jadx → search for string comparisons near the hardcoded PIN input
```

---

## Self-Study: Read One Public Write-Up

Find a published mobile CTF write-up and read it end-to-end:

```
Recommended resources:
- https://www.hackerone.com/hacktivity  (filter by Mobile)
- Google: "HTB Android challenge writeup 2024"
- GitHub: search "android ctf writeup jadx"
```

**Take notes:**
- What tool did they use first?
- What was the key insight that cracked the challenge?
- What technique could you apply in a real bug bounty?

---

## Reflection Journal Entry

After the session, write in your notes:

1. **What I found:** list each finding with the file name and line number.
2. **How long it took:** time from APK download to flag/finding.
3. **What slowed me down:** where did I get stuck and why?
4. **What I would do faster next time:** one process improvement.
5. **Weakness identified:** which technique from Days 211–222 do I need to
   review before tomorrow?

---

## Navigation

← Previous: [Day 222 — Mobile Detection and Hardening](DAY-0222-Mobile-Detection-and-Hardening.md)
→ Next: [Day 224 — Mobile Practice Day 2](DAY-0224-Mobile-Practice-Day-2.md)
