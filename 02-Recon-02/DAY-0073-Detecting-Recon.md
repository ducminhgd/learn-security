---
title: "Detecting Recon — Honeypots, Canary Tokens, Log Analysis for Crawlers"
tags: [defensive, blue-team, recon-detection, honeypots, canary-tokens, log-analysis,
       Sigma, port-scan-detection, threat-hunting, T1046, T1595, detection-engineering]
module: 02-Recon-02
day: 73
related_topics:
  - Detecting Recon (Blue Team perspective)
  - nmap from First Principles (Day 063)
  - Security Monitoring Architecture (B-01)
  - Reducing Your Org Attack Surface (Day 061)
  - MITRE ATT&CK T1046, T1595
---

# Day 073 — Detecting Recon

## Goals

By the end of this lesson you will be able to:

1. Explain the four detection signals available during a recon phase:
   network, web, DNS, and application logs.
2. Write a Sigma rule that detects a port scan from an nmap or masscan signature.
3. Deploy a canary token and describe the alert it produces when triggered.
4. Analyse a web server access log and identify crawler/fuzzer traffic patterns.
5. Explain the defender's inherent advantage during recon (and its limitations).

---

## Prerequisites

- [Day 061 — Reducing Your Org Attack Surface](../02-Recon-01/DAY-0061-Reducing-Your-Org-Attack-Surface.md)
- [Day 063 — nmap from First Principles](DAY-0063-nmap-from-First-Principles.md)
- [Day 065 — Directory and Endpoint Fuzzing](DAY-0065-Directory-and-Endpoint-Fuzzing.md)

---

## Main Content

> "The attacker has to be right once to find a way in. You have to be right
> every time to keep them out. But detection is different — you only need to
> see them once to know they are there."
>
> — Ghost

### 1. The Defender's Advantage in Recon Phase

Active recon creates detectable signals at every layer:

```
Layer           Signal                  Detection method
─────────────── ──────────────────────  ──────────────────────────────────────
Network         SYN packets at scale    Firewall logs, IDS rule, packet capture
DNS             Subdomain enumeration   DNS query logs (high volume, NXDOMAIN)
HTTP            Directory fuzzing       Web server access logs (404 storm)
Application     Auth probe              Application logs (login failures)
Cloud           Metadata endpoint       AWS CloudTrail, access logs
```

The attacker who has read Days 051–072 is trying to be quiet. But no amount
of stealth eliminates all signals. Your job as a defender is to detect the
ones that matter.

---

### 2. Network-Level Detection — Port Scans

#### 2.1 What Port Scans Look Like in Firewall Logs

```
# Firewall log format (iptables/nftables)
TIMESTAMP      SRC_IP        DST_IP       PROTO  SRC_PORT  DST_PORT  ACTION
2026-04-17T03:14:01  1.2.3.4   10.0.0.5   TCP    54312     22        ACCEPT
2026-04-17T03:14:01  1.2.3.4   10.0.0.5   TCP    54313     23        REJECT
2026-04-17T03:14:01  1.2.3.4   10.0.0.5   TCP    54314     25        REJECT
2026-04-17T03:14:01  1.2.3.4   10.0.0.5   TCP    54315     53        REJECT
...
(1000 entries within 1 second, same source IP, sequential destination ports)
```

**Pattern:**
- Same source IP
- Incrementing destination port (sequential scan) or random (masscan)
- High rate: 100+ connections per second

#### 2.2 Sigma Rule — Port Scan Detection

Sigma rules are vendor-neutral detection signatures that can be converted to
Splunk, Elastic, Graylog, or any SIEM.

```yaml
# sigma/port_scan_detection.yml
title: Port Scan Detected — Multiple Connection Attempts
status: stable
description: >
  Detects a single source IP making connection attempts to many different
  destination ports within a short time window. Matches nmap SYN scan,
  connect scan, and masscan patterns.
author: Ghost Training Programme
date: 2026/04/17
tags:
  - attack.reconnaissance
  - attack.t1046
logsource:
  category: firewall
  product: generic
detection:
  selection:
    dst_port|lt: 1024     # Interesting port range
  condition:
    timeframe: 5s
    groupby:
      - src_ip
      - dst_ip
    count(dst_port) > 50   # 50+ different ports in 5 seconds
falsepositives:
  - Legitimate network scanners operated by the security team
  - Load balancers performing health checks
level: medium
fields:
  - src_ip
  - dst_ip
  - dst_port
  - count_ports
```

```yaml
# sigma/masscan_signature.yml
title: Masscan Detected — TTL and Window Size Signature
status: experimental
description: >
  Detects TCP SYN packets with masscan-specific characteristics:
  window size of 1024 and TTL of 128 (Windows) or 64 (Linux) without variance.
author: Ghost Training Programme
tags:
  - attack.reconnaissance
  - attack.t1046
logsource:
  category: network
  product: zeek
detection:
  selection:
    tcp.flags: "S"        # SYN only
    tcp.window_size: 1024  # masscan default window size
  condition: selection
  timeframe: 1s
  groupby:
    - src_ip
  count() > 100
falsepositives:
  - Unknown
level: high
```

---

### 3. DNS-Level Detection — Subdomain Enumeration

#### 3.1 Subdomain Brute Force Pattern

When an attacker runs amass or subfinder with brute force enabled, your DNS
servers will see:

```
3:14:01.001  QUERY  0001.target.com      A  1.2.3.4 → NXDOMAIN
3:14:01.002  QUERY  0002.target.com      A  1.2.3.4 → NXDOMAIN
3:14:01.003  QUERY  0003.target.com      A  1.2.3.4 → NXDOMAIN
... (5000 queries in under a minute from the same source IP)
```

**Pattern:** Hundreds of NXDOMAIN responses for the same base domain from
a single source IP.

#### 3.2 DNS Query Log Analysis

```bash
# Parse Zeek DNS logs (dns.log format)
# Format: ts uid id.orig_h id.resp_h proto trans_id query qtype rcode answers

# Find sources with high NXDOMAIN rate
cat dns.log | awk '$13 == "NXDOMAIN" {print $3}' | \
    sort | uniq -c | sort -rn | head -20

# Find high-volume DNS query sources
cat dns.log | awk '{print $3, $9}' | \
    sort | uniq -c | sort -rn | head -20

# Find queries for non-existent subdomains of your domain
cat dns.log | \
    awk '$9 ~ /\.target\.com$/ && $13 == "NXDOMAIN" {print $3, $9}' | \
    sort | uniq -c | sort -rn
```

#### 3.3 Sigma Rule — DNS Brute Force

```yaml
# sigma/dns_subdomain_bruteforce.yml
title: DNS Subdomain Brute Force
status: stable
description: >
  Detects high-volume NXDOMAIN responses from a single source, indicating
  subdomain enumeration via brute force. Matches amass, subfinder, and
  similar tool patterns.
tags:
  - attack.reconnaissance
  - attack.t1595
logsource:
  product: zeek
  service: dns
detection:
  selection:
    dns.rcode: NXDOMAIN
  condition:
    timeframe: 60s
    groupby:
      - src_ip
    count() > 200
level: medium
```

---

### 4. HTTP-Level Detection — Directory Fuzzing

#### 4.1 What Directory Fuzzing Looks Like in Access Logs

A standard nginx/Apache access log during a ffuf/feroxbuster scan:

```
1.2.3.4 - - [17/Apr/2026:03:15:01 +0000] "GET /admin HTTP/1.1" 404 167
1.2.3.4 - - [17/Apr/2026:03:15:01 +0000] "GET /admin.php HTTP/1.1" 404 167
1.2.3.4 - - [17/Apr/2026:03:15:01 +0000] "GET /backup HTTP/1.1" 404 167
1.2.3.4 - - [17/Apr/2026:03:15:01 +0000] "GET /backup.zip HTTP/1.1" 404 167
1.2.3.4 - - [17/Apr/2026:03:15:01 +0000] "GET /config HTTP/1.1" 404 167
...
(500 entries in under 10 seconds, all 404, sequential wordlist order)
```

**Pattern:**
- Same source IP
- Sequential wordlist-looking paths
- High 404 rate
- Often generic User-Agent: `ffuf/2.0.0-dev`, `python-requests/2.28.0`,
  `Go-http-client/1.1`, or missing User-Agent entirely

#### 4.2 Access Log Analysis Script

```python
#!/usr/bin/env python3
"""
detect_fuzz.py — Analyse nginx/Apache access logs for directory fuzzing
Usage: python3 detect_fuzz.py /var/log/nginx/access.log
"""
from __future__ import annotations
import re
import sys
from collections import defaultdict
from datetime import datetime


LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) (?P<size>\d+)'
    r'(?:\s+"[^"]*" "(?P<ua>[^"]*)")?'
)


def parse_log(filename: str) -> None:
    # Track per-IP stats in a 60-second window
    ip_stats: dict[str, dict] = defaultdict(lambda: {
        "total": 0, "404s": 0, "paths": set(), "start_time": None
    })

    with open(filename) as f:
        for line in f:
            m = LOG_PATTERN.match(line.strip())
            if not m:
                continue

            ip = m.group("ip")
            status = int(m.group("status"))
            path = m.group("path")
            ua = m.group("ua") or ""

            stats = ip_stats[ip]
            stats["total"] += 1
            stats["paths"].add(path)
            if status == 404:
                stats["404s"] += 1

    print(f"{'IP':<18} {'Total':<8} {'404s':<8} {'Unique paths':<15} {'Suspicion'}")
    print("-" * 65)

    for ip, stats in sorted(ip_stats.items(), key=lambda x: x[1]["404s"], reverse=True):
        total = stats["total"]
        fours = stats["404s"]
        paths = len(stats["paths"])

        if total < 10:
            continue

        # Calculate suspicion score
        suspicion = "LOW"
        if fours > 100 and fours / total > 0.7:
            suspicion = "HIGH - likely fuzzing"
        elif fours > 50 and paths > 40:
            suspicion = "MEDIUM - possible fuzzing"
        elif total > 200 and paths > 150:
            suspicion = "MEDIUM - high volume"

        if suspicion != "LOW":
            print(f"{ip:<18} {total:<8} {fours:<8} {paths:<15} {suspicion}")


if __name__ == "__main__":
    parse_log(sys.argv[1] if len(sys.argv) > 1 else "/var/log/nginx/access.log")
```

#### 4.3 nginx Rate Limiting (Mitigation + Detection)

```nginx
# nginx.conf — rate limiting to slow down fuzzers
http {
    # Define zone: 10MB memory, 30 requests/second per IP
    limit_req_zone $binary_remote_addr zone=per_ip:10m rate=30r/s;

    server {
        location / {
            # Allow bursts of 10, then queue
            limit_req zone=per_ip burst=10 nodelay;
            # Log when rate limit is hit
            limit_req_log_level warn;
        }
    }
}
```

When a fuzzer hits the rate limit, nginx returns 503 and logs:

```
[warn] limiting requests, excess: 45.0 by zone "per_ip", client: 1.2.3.4
```

This creates a detectable log signal AND slows down the fuzzer.

---

### 5. Canary Tokens — Tripwires for Recon

Canary tokens are honeypot URLs, files, or credentials that alert you the
moment they are accessed. They are specifically designed to catch recon.

#### 5.1 What Makes a Good Canary

A canary token placed in your web application should:
- Be in a place an attacker would naturally find it during recon
- Alert immediately on access
- Not be accessible through normal application use (so any access = attacker)

#### 5.2 Deploying Canary Tokens (canarytokens.org)

```
Service: https://canarytokens.org (free, by Thinkst)

Token types:
  - URL token:      A URL that alerts when visited
  - DNS token:      A hostname that alerts when resolved
  - Web bug token:  An image that alerts when loaded
  - AWS token:      AWS credentials that alert when used
  - Azure token:    Azure credentials that alert when used
  - PDF token:      A PDF that alerts when opened
  - Word doc:       A Word doc that alerts when opened
```

**Deployment strategy for recon detection:**

```bash
# 1. Create a canary URL token at canarytokens.org
# URL:  https://canarytokens.org/generate → select "URL"
# Note: your alert email
# Output: https://canarytokens.org/static/stuff/tags/UNIQUEID/submit.aspx

# 2. Plant the canary in places attackers will find it:

# As a fake credentials file linked from an exposed git commit:
# In .env (if you have one that is intentionally decoy):
cat > /var/www/html/test/.env << 'EOF'
# Legacy config
DB_PASSWORD=canary_password_xyz
ADMIN_API_KEY=canary_api_key_abc
INTERNAL_URL=https://canarytokens.org/static/stuff/tags/YOURTOKEN/submit.aspx
EOF

# As a web path that sounds interesting to fuzzers:
# /api/v1/admin/config — returns the canary URL in a redirect

# As a fake API key in a JavaScript file:
# const INTERNAL_API_ENDPOINT = "https://internal-api.target.com/v3/?token=CANARYFLAG";
# (The internal-api hostname is a DNS canary token)

# 3. Alert fires when the token is hit — you immediately know:
# - Source IP of the attacker
# - Time of access
# - User agent (often reveals the tool: ffuf, nuclei, etc.)
```

#### 5.3 Honeytokens in Code (Git Canaries)

```python
# Place in a file with a name that sounds interesting to git scrapers
# e.g., config/secrets.py.old or .env.backup

# This API key is a canary token (DNS type)
# Any API call using this key will alert the security team
INTERNAL_ADMIN_KEY = "sk-live-canary-notareal-key-123abc"
DATABASE_URL = "postgresql://admin:password123@db-internal.target.com:5432/prod"
# ↑ db-internal.target.com is a DNS canary — any DNS query triggers an alert
```

---

### 6. Full Detection Architecture

For a production environment, combine all detection layers:

```
Layer            Tool                        Sigma Rule
──────────────   ─────────────────────────   ───────────────────────────────────
Network          Zeek + firewall logs         T1046: port scan rate rule
DNS              DNS server query logging     T1595: NXDOMAIN volume rule
HTTP             nginx/Apache access logs     T1595.003: 404 storm rule
Application      App-level logging            T1078: credential stuffing rule
Honeypot         canarytokens.org             Alert on any access
SIEM             Elastic/Graylog/Splunk       Correlate all sources
```

#### 6.1 Elastic SIEM Detection Rule for Port Scans

```json
{
  "rule": {
    "name": "Port Scan Detected",
    "type": "threshold",
    "query": "event.category:network AND network.direction:inbound AND event.action:connection_attempted",
    "threshold": {
      "field": "destination.port",
      "value": 50,
      "cardinality": [{"field": "source.ip", "value": 1}]
    },
    "window_start": "5s",
    "severity": "medium",
    "tags": ["T1046", "Reconnaissance"]
  }
}
```

---

### 7. The Defender's Playbook When Recon Is Detected

```
DETECT: Port scan alert fires for 1.2.3.4 → 10.0.0.0/24
         1000 SYNs in 5 seconds

RESPOND:
  Step 1: Do not block immediately. Observe.
          A hasty block tells the attacker they were detected and need
          to change TTPs. Observation yields more intelligence.

  Step 2: Cross-reference the source IP:
          - Is 1.2.3.4 a known security scanner (Shodan, Qualys)?
          - Is it from a known bug bounty platform?
          - Is it on a threat intel blacklist?

  Step 3: Correlate across layers:
          - Is 1.2.3.4 also appearing in web access logs?
          - Did 1.2.3.4 trigger any DNS canary tokens?
          - Did 1.2.3.4 hit any canary URLs?

  Step 4: Decision:
          - Bug bounty researcher: note, do not block; track their findings
          - Unknown hostile scanner: block at perimeter; add to threat intel
          - Internal team: whitelist if authorised scan

  Step 5: Document:
          - Log the IP, time, scan type, and decision
          - This is your incident timeline if this escalates
```

---

## Key Takeaways

1. **Every active recon technique from Days 063–072 creates detectable signals.**
   A SYN scan leaves firewall log entries. A fuzz attack leaves a 404 storm.
   A subdomain brute force leaves NXDOMAIN volume spikes. Nothing is invisible.
2. **Canary tokens give you zero-false-positive alerts.** A token placed in a
   `/config/secrets.env` file that no legitimate user accesses — any access is
   an attacker. No SIEM query needed.
3. **Detection does not mean prevention.** Detecting a port scan does not stop
   the attacker from finding your open ports. Pair detection with hardening.
4. **Sigma rules are portable.** Write once; convert to Splunk, Elastic, Graylog.
   The detection logic is tool-independent.
5. **Observe before you block.** A hasty firewall block tips off the attacker.
   Watching their recon tells you their TTPs, their tooling, and possibly their
   intent — before they attempt exploitation.

---

## Exercises

### Exercise 1 — Build a Canary Token Tripwire

1. Create a free canary token at canarytokens.org (URL type).
2. Plant it in a `test/.env` file on a local web server.
3. Run ffuf against the local server: `ffuf -u http://localhost/FUZZ -w wordlist.txt`
4. Did ffuf find the `.env` file and trigger the canary alert?
5. What information did the alert contain (IP, User-Agent, timestamp)?

---

### Exercise 2 — Write a Sigma Rule

Write a Sigma rule that detects ffuf directory fuzzing based on:
- More than 200 HTTP 404 responses from a single IP in 30 seconds
- Target: nginx access log

Format it as valid YAML Sigma syntax, including logsource, detection,
condition, and falsepositives sections.

---

### Exercise 3 — Log Analysis

Analyse the sample access log below and identify:
1. Is there evidence of directory fuzzing?
2. What tool was likely used?
3. What time did the scan start and end?
4. Which path was successfully found (non-404)?

```
1.2.3.4 - - [17/Apr/2026:03:15:00 +0000] "GET / HTTP/1.1" 200 4521 "-" "Mozilla/5.0"
1.2.3.4 - - [17/Apr/2026:03:15:01 +0000] "GET /.env HTTP/1.1" 404 162 "-" "ffuf/2.1.0"
1.2.3.4 - - [17/Apr/2026:03:15:01 +0000] "GET /admin HTTP/1.1" 301 162 "-" "ffuf/2.1.0"
1.2.3.4 - - [17/Apr/2026:03:15:01 +0000] "GET /backup HTTP/1.1" 404 162 "-" "ffuf/2.1.0"
1.2.3.4 - - [17/Apr/2026:03:15:01 +0000] "GET /config HTTP/1.1" 404 162 "-" "ffuf/2.1.0"
1.2.3.4 - - [17/Apr/2026:03:15:02 +0000] "GET /login HTTP/1.1" 404 162 "-" "ffuf/2.1.0"
1.2.3.4 - - [17/Apr/2026:03:15:08 +0000] "GET /wp-admin HTTP/1.1" 404 162 "-" "ffuf/2.1.0"
1.2.3.4 - - [17/Apr/2026:03:15:09 +0000] "GET /secret.txt HTTP/1.1" 200 88 "-" "ffuf/2.1.0"
```

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 072 — Bug Bounty Recon Methodology](DAY-0072-Bug-Bounty-Recon-Methodology.md)*
*Next: [Day 074 — Recon Review and Preparation](DAY-0074-Recon-Review-and-Preparation.md)*
