---
title: "nmap Service Detection, NSE and Evasion — -sV, -O, Scripts, Timing, Decoys"
tags: [recon, active-recon, nmap, service-detection, NSE, OS-detection, evasion,
       fragmentation, decoys, timing, T1046, T1497, fingerprinting]
module: 02-Recon-02
day: 64
related_topics:
  - nmap from First Principles (Day 063)
  - Web App Fingerprinting and Tech Stack (Day 067)
  - Detecting Recon (Day 073)
  - MITRE ATT&CK T1046, T1595.001
---

# Day 064 — nmap Service Detection, NSE and Evasion

## Goals

By the end of this lesson you will be able to:

1. Use `-sV` to probe service banners and explain how nmap matches probes to
   service signatures.
2. Use `-O` to fingerprint OS and explain the limitations of OS detection.
3. Identify and use at least five NSE script categories with practical examples.
4. Write a targeted NSE scan against a live lab target and extract useful
   vulnerability data.
5. Explain nmap's six timing templates and choose the appropriate one for a
   bug bounty target.
6. Implement basic IDS evasion: fragmentation, decoys, and source port spoofing.

---

## Prerequisites

- [Day 063 — nmap from First Principles](DAY-0063-nmap-from-First-Principles.md)

---

## Main Content

### 1. Service Detection (-sV)

After confirming which ports are open, the next question is: **what is actually
running on this port?**

Without `-sV`, nmap guesses the service by port number using its `nmap-services`
database (port 22 → ssh, port 80 → http). This is a guess based on convention.
Port 8443 might be running a custom application, not HTTPS.

With `-sV`, nmap sends probes and compares responses to its `nmap-service-probes`
database to fingerprint the actual service and version.

```bash
# Service version detection
sudo nmap -sV 10.10.10.5

# More aggressive — try harder probes (slower, more intrusive)
sudo nmap -sV --version-intensity 9 10.10.10.5
# --version-intensity 0-9 (default: 7)
# Higher intensity = more probes = more accurate but noisier
```

**Sample output:**

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    nginx 1.24.0
443/tcp  open  ssl/http nginx 1.24.0
3306/tcp open  mysql   MySQL 8.0.36-0ubuntu0.22.04.1
```

Why this matters for exploitation:
- `OpenSSH 8.9p1` → check for CVE-2023-38408 (key agent exploitation)
- `MySQL 8.0.36` → check for known SQLi patterns; is it internet-exposed?
- `nginx 1.24.0` → check for version-specific vulnerabilities

---

### 2. OS Detection (-O)

nmap fingerprints the operating system by analysing how the TCP/IP stack
responds to crafted probes. Characteristics used include: TCP window size,
TTL, ISN sequence, DF (Don't Fragment) bit behaviour, IPID patterns.

```bash
# OS detection (requires root)
sudo nmap -O 10.10.10.5

# Combine service + OS detection (common usage)
sudo nmap -sV -O 10.10.10.5

# Aggressive mode: OS + version + script + traceroute
sudo nmap -A 10.10.10.5
```

**Sample output:**

```
OS details: Linux 5.15 - 5.19
Network Distance: 2 hops
```

**Limitations:**
- OS detection is probabilistic, not definitive. Behind NAT or a load balancer,
  you may be fingerprinting the load balancer's OS, not the application server.
- Actively crafts unusual packets — more likely to trigger IDS.
- In bug bounty, -O adds noise with marginal return. Service banners give you
  enough to work with.

---

### 3. Nmap Scripting Engine (NSE)

NSE is where nmap goes from a port scanner to a vulnerability assessment platform.
Scripts are written in Lua and organised into categories.

#### 3.1 NSE Script Categories

| Category | Purpose | Risk Level |
|---|---|---|
| `auth` | Test authentication (default credentials, bypass) | Medium |
| `broadcast` | Send broadcast packets, enumerate network | Low |
| `brute` | Password brute-force against services | High — use carefully |
| `default` | Safe, commonly useful scripts (run with -sC) | Low |
| `discovery` | Enumerate additional info about services | Low |
| `dos` | Denial of service — **NEVER USE IN BUG BOUNTY** | Critical |
| `exploit` | Exploit vulnerabilities | High — authorised targets only |
| `external` | Call external services (DNS, Shodan) | Low |
| `fuzzer` | Send malformed data | High |
| `intrusive` | Potentially disruptive | Medium-High |
| `malware` | Detect backdoors | Low |
| `safe` | No negative side effects | Low |
| `version` | Service version detection (used by -sV) | Low |
| `vuln` | Check for known vulnerabilities | Medium |

#### 3.2 Running NSE Scripts

```bash
# Run default scripts (equivalent to -sC)
sudo nmap -sC 10.10.10.5

# Run a specific script
sudo nmap --script=http-title 10.10.10.5

# Run multiple scripts
sudo nmap --script=http-title,http-server-header,http-robots.txt 10.10.10.5

# Run a category
sudo nmap --script=vuln 10.10.10.5

# Run all safe + discovery scripts
sudo nmap --script="safe and discovery" 10.10.10.5

# Combine with port + service
sudo nmap -sV --script=default,vuln -p 80,443,8080 10.10.10.5
```

#### 3.3 High-Value NSE Scripts for Recon

**Web:**

```bash
# Enumerate HTTP endpoints
sudo nmap --script=http-enum 10.10.10.5 -p 80,443

# Extract page title (useful for bulk scanning)
sudo nmap --script=http-title --script-args http-title.url=/ 10.10.10.5

# Detect open redirect
sudo nmap --script=http-open-redirect 10.10.10.5

# Robots.txt
sudo nmap --script=http-robots.txt 10.10.10.5

# Methods allowed
sudo nmap --script=http-methods 10.10.10.5 -p 80

# WAF detection
sudo nmap --script=http-waf-detect 10.10.10.5 -p 80,443
sudo nmap --script=http-waf-fingerprint 10.10.10.5 -p 80,443
```

**TLS/SSL:**

```bash
# Full SSL/TLS analysis (cipher suites, cert details, weaknesses)
sudo nmap --script=ssl-enum-ciphers 10.10.10.5 -p 443

# Certificate info
sudo nmap --script=ssl-cert 10.10.10.5 -p 443

# Heartbleed check
sudo nmap --script=ssl-heartbleed 10.10.10.5 -p 443
```

**SMB (Windows targets):**

```bash
# SMB vulnerability scan
sudo nmap --script=smb-vuln-ms17-010 10.10.10.5 -p 445

# SMB OS discovery
sudo nmap --script=smb-os-discovery 10.10.10.5 -p 445

# SMB security mode
sudo nmap --script=smb-security-mode 10.10.10.5 -p 445
```

**SSH:**

```bash
# SSH host key algorithms
sudo nmap --script=ssh2-enum-algos 10.10.10.5 -p 22

# SSH default credentials
sudo nmap --script=ssh-brute --script-args userdb=users.txt,passdb=pass.txt \
     10.10.10.5 -p 22
# WARNING: only in authorised environments
```

**MySQL / PostgreSQL:**

```bash
# MySQL empty password check
sudo nmap --script=mysql-empty-password 10.10.10.5 -p 3306

# PostgreSQL brute
sudo nmap --script=pgsql-brute 10.10.10.5 -p 5432
```

#### 3.4 Script Arguments

```bash
# Pass arguments to scripts
sudo nmap --script=http-brute \
     --script-args http-brute.path=/login,http-brute.hostname=target.com \
     10.10.10.5 -p 80
```

---

### 4. The Combined Scan — Real Usage

In practice, combine flags for a single comprehensive scan:

```bash
# Bug bounty active recon scan — a reasonable default
sudo nmap -sS -sV -sC -p- --open --min-rate 500 -oA full_scan 10.10.10.5

# Breakdown:
# -sS          → SYN scan
# -sV          → service version detection
# -sC          → default NSE scripts
# -p-          → all 65535 ports
# --open       → only show open ports
# --min-rate 500 → send at least 500 packets/second (speeds up -p- significantly)
# -oA full_scan  → save all formats
```

**Two-phase approach (faster for large ranges):**

```bash
# Phase 1: fast scan to find open ports
sudo nmap -sS -p- --min-rate 5000 --open -oG phase1.gnmap 10.10.10.5

# Extract open ports
open_ports=$(grep "open" phase1.gnmap | awk -F'Ports:' '{print $2}' | \
             grep -oP '\d+/open' | awk -F'/' '{print $1}' | tr '\n' ',' | \
             sed 's/,$//')
echo "Open ports: $open_ports"

# Phase 2: deep scan only open ports
sudo nmap -sS -sV -sC -p "$open_ports" -oA phase2_deep 10.10.10.5
```

---

### 5. Timing Templates (-T)

nmap has six timing templates. They control parallelism, timeouts, and retry counts.

| Template | Name | Use Case | Scan Speed |
|---|---|---|---|
| `-T0` | Paranoid | IDS evasion — sends one probe every 5 minutes | Extremely slow |
| `-T1` | Sneaky | Slow evasion — 15 seconds between probes | Very slow |
| `-T2` | Polite | Reduce network load | Slow |
| `-T3` | Normal | Default | Moderate |
| `-T4` | Aggressive | Fast LAN scan; reasonable for internet targets | Fast |
| `-T5` | Insane | Maximum speed, some accuracy loss | Very fast |

**Bug bounty guidance:**

```bash
# For internet targets: -T3 (default) or -T4
# -T4 is fast but may trigger rate limiting on sensitive targets

# For internal lab targets: -T4 or -T5

# For evasion testing: -T1 or -T2

# Practical compromise: control rate manually
sudo nmap -sS -p- --min-rate 300 --max-retries 2 10.10.10.5
```

---

### 6. IDS Evasion Techniques

#### 6.1 Packet Fragmentation (-f)

Split TCP packets into smaller fragments. Older IDS systems that do not
reassemble fragments may miss the scan signature.

```bash
# Fragment packets into 8-byte chunks
sudo nmap -f 10.10.10.5

# Double fragmentation (16-byte maximum fragment size)
sudo nmap -ff 10.10.10.5

# Custom MTU size
sudo nmap --mtu 16 10.10.10.5
```

**Modern defence:** Stateful firewalls and IDS reassemble fragments before
inspection. Fragmentation is less effective than it once was.

#### 6.2 Decoy Scan (-D)

Makes your scan appear to come from multiple source IPs simultaneously.

```bash
# Scan using 3 decoy IPs + real IP
sudo nmap -D 10.10.10.100,10.10.10.101,10.10.10.102 10.10.10.5

# Use random decoys (nmap generates them)
sudo nmap -D RND:10 10.10.10.5
# Sends scan from 10 random IPs plus your real IP (ME)

# Mix specific decoys with random position of real IP
sudo nmap -D 10.10.10.100,ME,10.10.10.102 10.10.10.5
```

**Limitation:** The SYN/ACK from the target goes to the decoy IPs, not to
you. Open port results still work because the real RST from your IP confirms.
However, your real IP still appears in the firewall logs.

#### 6.3 Source Port Spoofing (-g)

Some firewall rules allow traffic from specific source ports (like 53 for DNS,
or 80 for HTTP). Specifying a source port can bypass naive rules.

```bash
# Scan using source port 53 (mimics DNS traffic)
sudo nmap -g 53 10.10.10.5

# Source port 80 (mimics HTTP return traffic)
sudo nmap -g 80 10.10.10.5
```

#### 6.4 Idle (Zombie) Scan (-sI)

The most powerful stealth technique: bounce the scan off a "zombie" host.
Your IP never appears in the target's logs.

```bash
# Find a zombie (needs low IPID rate — check with:)
sudo nmap -O -v --script=ipidseq <potential-zombie-ip>
# Look for "Incremental!" in IPID sequence

# Perform idle scan using zombie
sudo nmap -sI <zombie-ip> 10.10.10.5
```

**How it works:** Exploits predictable IPID values on the zombie. Your machine
sends spoofed SYN packets to the target pretending to be the zombie. If the
target port is open, it sends a SYN/ACK to the zombie, incrementing its IPID.
You probe the zombie's IPID to infer the result. Your IP is never seen by the
target.

**Practical note:** Finding a usable zombie on the modern internet is rare.
Most hosts randomise IPID.

---

### 7. Putting It Together — Bug Bounty Scan Workflow

```bash
#!/bin/bash
# bug_bounty_scan.sh — standard active recon scan
# Usage: ./bug_bounty_scan.sh <target_ip> <output_prefix>

TARGET=$1
OUTPUT=$2

echo "[*] Phase 1: Quick full-port SYN scan"
sudo nmap -sS -p- --min-rate 1000 --open -oG "${OUTPUT}_phase1.gnmap" "$TARGET"

echo "[*] Extracting open ports"
OPEN_PORTS=$(grep "open" "${OUTPUT}_phase1.gnmap" | \
             grep -oP '\d+/open' | awk -F'/' '{print $1}' | \
             sort -n | tr '\n' ',' | sed 's/,$//')
echo "[*] Open ports: $OPEN_PORTS"

echo "[*] Phase 2: Deep service + script scan"
sudo nmap -sS -sV -sC -p "$OPEN_PORTS" \
     --script="default,vuln,http-title,http-robots.txt,ssl-cert" \
     -oA "${OUTPUT}_phase2" "$TARGET"

echo "[+] Results saved to ${OUTPUT}_phase2.*"
```

---

## Key Takeaways

1. **`-sV` is a must-have for any meaningful recon.** Port-number-based guessing
   is wrong 20% of the time in real-world environments. Know what is actually
   running before building an attack plan.
2. **NSE scripts turn nmap into a recon platform.** The difference between a
   basic scan and an NSE-augmented scan is the difference between "port 443
   is open" and "port 443, TLS 1.3, certificate valid for *.target.com expiring
   2024-09-01, http-title: Admin Portal."
3. **IDS evasion is an arms race. Understand the technique; do not rely on it.**
   Modern enterprise IDS reassembles fragments, correlates source IPs, and
   detects timing patterns. Evasion techniques give you probabilistic advantage,
   not guaranteed invisibility.
4. **The two-phase approach is best practice.** Fast full-port scan to find
   open ports, then deep service/script scan against only those ports. Never
   run NSE scripts against all 65535 ports — it is slow and noisy.
5. **`-T4` is the sweet spot for internet targets.** `-T5` risks losing accuracy.
   `-T3` (default) is too slow for full port scans. Use `--min-rate` for
   fine-grained control.

---

## Exercises

### Exercise 1 — NSE Reconnaissance

On a lab target with a web server:

1. Run `sudo nmap --script=http-enum,http-title,http-methods,http-robots.txt -p 80,443 <target>`.
2. Document every piece of information returned.
3. Which findings would be most useful for planning a web application test?

---

### Exercise 2 — Two-Phase Scan

1. Run a phase-1 fast scan: `sudo nmap -sS -p- --min-rate 2000 --open -oG phase1.gnmap <target>`.
2. Extract the open port list with a one-liner.
3. Run a phase-2 deep scan against those ports only.
4. Compare total time vs running `sudo nmap -sV -sC -p-` directly.
   What is the time saving?

---

### Exercise 3 — TLS Analysis

Against a target with HTTPS:

1. Run `sudo nmap --script=ssl-enum-ciphers -p 443 <target>`.
2. Are any deprecated ciphers present (RC4, DES, 3DES, NULL)?
3. Is TLS 1.0 or 1.1 enabled? What is the CVE implication?
4. Run `sudo nmap --script=ssl-cert -p 443 <target>`. What is the certificate
   expiry date and what does the Subject Alternative Name field contain?

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 063 — nmap from First Principles](DAY-0063-nmap-from-First-Principles.md)*
*Next: [Day 065 — Directory and Endpoint Fuzzing](DAY-0065-Directory-and-Endpoint-Fuzzing.md)*
