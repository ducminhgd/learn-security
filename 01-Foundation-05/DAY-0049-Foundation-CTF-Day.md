---
title: "Foundation CTF Day"
tags: [foundation, CTF, challenge, solo, web, crypto, Linux, auth, network]
module: 01-Foundation-05
day: 49
related_topics:
  - Foundation Complete Review (Day 048)
  - Foundation Competency Gate (Day 050)
---

# Day 049 — Foundation CTF Day

## Goals

One day. Solo. No hints until you have spent at least 30 minutes on each
challenge. The skills are in you — this is the test.

By completing this CTF you will demonstrate:

1. Network and HTTP traffic analysis.
2. Linux privilege escalation from a low-privilege shell.
3. Cryptographic flaw exploitation.
4. Web application vulnerability identification and exploitation.
5. Authentication bypass.

---

## Prerequisites

- [Day 048 — Foundation Complete Review](DAY-0048-Foundation-Complete-Review.md)
- All of F-01 through F-05 content (Days 001–047)

---

## CTF Environment Setup

```bash
# All challenges run in Docker. One compose file — clean reset any time.
git clone https://github.com/ghost-training/foundation-ctf  # (internal lab repo)
cd foundation-ctf
docker compose up -d

# Alternatively, use these public platforms for similar challenges:
# Web challenges:   https://portswigger.net/web-security/all-labs
# Linux privesc:    https://tryhackme.com/room/linprivesc
# Crypto:           https://cryptopals.com/sets/1 + sets/2
# Auth:             https://portswigger.net/web-security/authentication
```

---

## Challenge 1 — Network Layer

### Category
Network / Forensics

### Difficulty
Beginner — Estimated time: 30 minutes

### Scenario
A packet capture was taken during an incident. The analyst believes
credentials were sent in cleartext over the network.

### Your Task
Download `capture.pcap` from the CTF environment:

```bash
# Available at:
wget http://localhost:8090/challenges/network/capture.pcap
```

1. Open in Wireshark.
2. Follow TCP streams.
3. Find the cleartext credential.
4. Submit the flag embedded in the credential.

### Hint Progression
1. Filter: `tcp.port == 80` — look at HTTP streams.
2. `File → Export Objects → HTTP` will show you transferred content.
3. The credentials are in a POST body. Look for `password=`.

### Flag Format
`FLAG{network_cleartext_capture}`

---

## Challenge 2 — Linux Privilege Escalation

### Category
Linux / Privilege Escalation

### Difficulty
Intermediate — Estimated time: 45 minutes

### Scenario
You have a shell as `www-data` on a web server. Your goal is `/root/flag.txt`.

```bash
# Connect to the lab box:
ssh ctf@localhost -p 2222
# Password: ctfplayer
# You land as: www-data
```

### Your Task

Enumerate and escalate to root. One or more of these vectors are present:
- SUID binary exploitable via GTFOBins
- Sudo rule allowing a shell escape
- World-writable cron script running as root
- Linux capability granting filesystem access

Read `/root/flag.txt` and submit the flag.

### Hint Progression
1. Run: `find / -perm -4000 -type f 2>/dev/null` and `sudo -l`
2. Check `ls -la /etc/cron.d/ /var/spool/cron/`
3. `getcap -r / 2>/dev/null`

### Flag Format
`FLAG{linux_privesc_root}`

---

## Challenge 3 — Cryptography

### Category
Crypto

### Difficulty
Intermediate — Estimated time: 45 minutes

### Scenario
An application signs its session cookies using `sha256(secret + session_data)`.
You have one valid cookie for a `user` role session. Forge a cookie for `admin`.

### Setup

```bash
# The signing oracle is running at:
http://localhost:8091/api/sign

# You can verify cookies at:
http://localhost:8091/api/verify

# Captured valid cookie (role=user):
COOKIE="session=user_id=5&role=user"
MAC="a1b2c3d4e5f6..."  # Provided in challenge files
```

### Your Task

1. Identify the MAC construction vulnerability.
2. Use `hashpumpy` to forge a valid MAC for `role=admin` appended to the
   original message.
3. Submit the forged cookie to `/admin` and retrieve the flag.

```python
import hashpumpy, requests

original_message = b"user_id=5&role=user"
known_mac = "a1b2c3d4e5f6..."     # Given
secret_length = ???                # You need to determine this (try 8–32)
data_to_append = b"&role=admin"

new_mac, new_message = hashpumpy.hashpump(known_mac, original_message, data_to_append, secret_length)

resp = requests.get(
    "http://localhost:8091/admin",
    cookies={"session": new_message.hex(), "mac": new_mac}
)
print(resp.text)
```

### Hint Progression
1. What is a Merkle–Damgård length extension attack? (Day 030)
2. Brute-force the secret length from 8 to 32 — only one will verify correctly.
3. The flag is in the response body of `/admin`.

### Flag Format
`FLAG{length_extension_mac_forged}`

---

## Challenge 4 — Web Application

### Category
Web

### Difficulty
Intermediate — Estimated time: 60 minutes

### Scenario
A simple e-commerce application. You have a standard user account.
Your goal is to read another user's order history.

```
URL: http://localhost:8092
Login: alice / password123
```

### Your Task

1. Log in as `alice`.
2. Find the order history endpoint.
3. Exploit the access control flaw to read orders that do not belong to Alice.
4. Find the order containing the flag and submit it.

### Hint Progression
1. Look at the order URL in Alice's history. What parameter identifies the order?
2. Try changing that parameter incrementally. What do you see?
3. The flag is in order ID 1 (the admin's first test order).

### Flag Format
`FLAG{idor_horizontal_access_control}`

---

## Challenge 5 — Authentication Bypass

### Category
Web / Auth

### Difficulty
Advanced — Estimated time: 60 minutes

### Scenario
A JWT-authenticated API. You are logged in as a regular user.
Become admin by exploiting the JWT implementation.

```
URL: http://localhost:8093
Login endpoint: POST /api/login
  {"username": "alice", "password": "password123"}
Admin panel: GET /api/admin
```

### Your Task

The application uses JWT. The public key is exposed at `/api/public-key`.
Gain access to `/api/admin`.

Approach:
1. Obtain your user JWT.
2. Fetch the public key.
3. Determine which JWT attack applies.
4. Forge a JWT with `role: admin`.
5. Access `/api/admin` with the forged JWT.

### Hint Progression
1. Decode the JWT header. What `alg` does it claim? What algorithm should the
   server be using given it exposes a public key?
2. The server reads `alg` from the token header. What key would it use to
   verify an `HS256` token?
3. Use `jwt_tool.py <TOKEN> -X k -pk public.pem`

### Flag Format
`FLAG{jwt_algorithm_confusion_admin}`

---

## Challenge 6 — Bonus: The Chain

### Category
Multi-stage

### Difficulty
Expert — Estimated time: 90 minutes

### Scenario
Everything you have is: a URL and a username. No password. No starting point.
There are three flags chained: each flag gives you a hint for the next.

```
URL: http://localhost:8094
Username: user@corp.com
```

**Flag 1** is accessible to any authenticated user.
**Flag 2** requires escalated application privilege.
**Flag 3** requires host-level access.

### No hints for this one.

This is the real test. Figure it out.

---

## Scoring and Debrief

| Challenge | Points | Skill |
|---|---|---|
| 1 — Network | 100 | Traffic analysis |
| 2 — Linux privesc | 200 | Enumeration + exploitation |
| 3 — Crypto | 200 | Length extension attack |
| 4 — Web IDOR | 200 | Access control bypass |
| 5 — JWT | 250 | Algorithm confusion |
| 6 — The Chain | 500 | Multi-stage, all skills |

**Passing score: 750 / 1450**

After completing or attempting all challenges, write a one-paragraph debrief
for each:
- What vulnerability was present?
- What is the root cause?
- How would a defender detect and prevent it?

---

## Rules

1. No hints until 30 minutes of genuine effort on a challenge.
2. No tools you cannot explain. If you use `jwt_tool`, know exactly what
   flag you are passing and why.
3. Document every step. A flag without a write-up is a guess.
4. The bonus chain has no hints — but it has everything you have learned.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 048 — Foundation Complete Review](DAY-0048-Foundation-Complete-Review.md)*
*Next: [Day 050 — Foundation Competency Gate](DAY-0050-Foundation-Competency-Gate.md)*
