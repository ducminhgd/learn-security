---
title: "Masscan and Fast Network Scanning — Internals, Rate Limiting, Combining with nmap"
tags: [recon, active-recon, masscan, network-scanning, port-scanning, stateless-scanning,
       rate-limiting, T1046, bug-bounty, large-scale-recon]
module: 02-Recon-02
day: 68
related_topics:
  - nmap from First Principles (Day 063)
  - nmap Service Detection NSE and Evasion (Day 064)
  - Active Recon Lab (Day 069)
  - MITRE ATT&CK T1046 (Network Service Scanning)
---

# Day 068 — Masscan and Fast Network Scanning

## Goals

By the end of this lesson you will be able to:

1. Explain how masscan achieves speeds nmap cannot — and why stateless scanning
   has trade-offs.
2. Perform a masscan sweep of a large IP range and correctly interpret the output.
3. Configure masscan's rate limiting to stay within safe operating bounds.
4. Chain masscan and nmap in a two-tool pipeline for maximum speed + accuracy.
5. Understand when masscan is appropriate vs when nmap is the right choice.

---

## Prerequisites

- [Day 063 — nmap from First Principles](DAY-0063-nmap-from-First-Principles.md)
- [Day 064 — nmap Service Detection, NSE and Evasion](DAY-0064-nmap-Service-Detection-NSE-and-Evasion.md)

---

## Main Content

### 1. Why Masscan Exists

nmap is thorough but stateful. It maintains connection state for each probe,
which limits its scan rate. For large ranges (thousands or millions of IPs),
nmap is too slow.

```
nmap scanning 1,000 IPs × 1,000 ports = 1,000,000 probes
With -T4 and reasonable network: ~10–15 minutes

masscan scanning 1,000 IPs × 1,000 ports = 1,000,000 probes
At 100,000 pps rate: ~10 seconds
```

masscan achieves this by being **stateless**: it fires SYN packets without
tracking state. It records SYN/ACK responses independently. This means
it can scan at millions of packets per second — limited only by your NIC
and network.

---

### 2. How masscan Works (Stateless SYN)

```
nmap (stateful):
  Send SYN → wait for response → record state → send RST → next port
  One packet tracked at a time per connection slot

masscan (stateless):
  Fire SYN packets at maximum rate to all targets simultaneously
  A separate receive loop records any incoming SYN/ACK
  No state maintained per connection — pure packet send + receive correlation
  SYN/ACK responses are matched by IP:port tuple, no timeout tracking
```

**Implications of stateless scanning:**

| Property | nmap (stateful) | masscan (stateless) |
|---|---|---|
| Speed | Moderate | Extremely fast |
| Accuracy | High | Good (but may miss responses at very high rates) |
| Service detection | Yes (-sV) | No |
| Script execution | Yes (NSE) | No |
| OS detection | Yes (-O) | No |
| UDP scanning | Yes | Limited |
| Rate limits | Via timing templates | Via --rate parameter |

masscan finds which ports are open. nmap tells you what is running on them.

---

### 3. Installation

```bash
# From package manager
sudo apt install masscan

# From source (most up-to-date)
git clone https://github.com/robertdavidgraham/masscan
cd masscan
make
sudo cp bin/masscan /usr/local/bin/

# Verify
masscan --version
```

---

### 4. Basic Usage

**masscan requires root** because it uses raw sockets (like nmap's SYN scan).

```bash
# Single IP, single port
sudo masscan 10.10.10.5 -p 80

# Single IP, port range
sudo masscan 10.10.10.5 -p 1-1000

# Multiple ports
sudo masscan 10.10.10.5 -p 80,443,8080,8443,22,21

# Full port range
sudo masscan 10.10.10.5 -p 0-65535

# CIDR range — top 100 ports
sudo masscan 10.10.10.0/24 -p 22,80,443,8080,8443,3306,5432,27017

# Multiple ranges
sudo masscan 10.10.10.0/24 10.10.20.0/24 -p 80,443
```

---

### 5. Rate Control — The Critical Parameter

This is where masscan can become dangerous if misconfigured.

```bash
# Default rate is 100 packets/second — safe but slow
sudo masscan 10.10.10.0/24 -p 1-65535

# Set a specific rate
sudo masscan 10.10.10.0/24 -p 1-65535 --rate 1000   # 1,000 pps
sudo masscan 10.10.10.0/24 -p 1-65535 --rate 10000  # 10,000 pps
sudo masscan 10.10.10.0/24 -p 1-65535 --rate 100000 # 100,000 pps
```

**Rate guidance by context:**

```
Context                  Safe rate          Notes
───────────────────────  ─────────────────  ──────────────────────────────────
Bug bounty — internet    100–1000 pps       Respect the target; never DoS
Internal lab network     10,000–100,000 pps Local network can handle it
CTF/HTB (single target)  1,000–5,000 pps   No need to go faster
Your own infrastructure  As fast as NIC     No limits
```

**Rule:** In bug bounty, treat masscan like a guest at a party — do not break
anything. Rate-limit to 500 pps for internet targets unless the programme
explicitly says otherwise.

---

### 6. Output Formats

```bash
# Default output (stdout)
sudo masscan 10.10.10.5 -p 80,443

# Save to file — text
sudo masscan 10.10.10.5 -p 1-65535 -oT scan.txt

# Save to file — grepable
sudo masscan 10.10.10.5 -p 1-65535 -oG scan.gnmap

# Save to file — JSON (recommended for parsing)
sudo masscan 10.10.10.5 -p 1-65535 -oJ scan.json

# XML output (nmap-compatible format)
sudo masscan 10.10.10.5 -p 1-65535 -oX scan.xml
```

**Sample JSON output:**

```json
[
{"ip": "10.10.10.5", "timestamp": "1710000000", "ports": [
  {"port": 22, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64},
  {"port": 80, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64},
  {"port": 443, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}
]}
]
```

---

### 7. Configuration File

For repeated scans or complex configurations, use a masscan config file:

```bash
# Create config file
cat > /opt/masscan/my_scan.conf << 'EOF'
# Target
range = 10.10.10.0/24

# Ports
ports = 0-65535

# Rate
rate = 1000

# Output
output-format = json
output-filename = /opt/masscan/results.json

# Interface (check yours with: ip addr)
interface = eth0

# Exclude our own IP from scan (important when scanning ranges)
excludefile = /opt/masscan/exclude.conf
EOF

# Run with config
sudo masscan -c /opt/masscan/my_scan.conf
```

**Exclude file** (prevent scanning critical infrastructure):

```bash
cat > /opt/masscan/exclude.conf << 'EOF'
# Never scan these — loopback and special ranges
127.0.0.0/8
0.0.0.0/8
255.255.255.255/32
# Add specific IPs/ranges to protect
192.168.1.1/32   # Your gateway
EOF
```

---

### 8. The masscan + nmap Pipeline

The most efficient approach to large-scale scanning:

1. **masscan** at high speed → identifies which ports are open (raw speed)
2. **nmap** targeted at open ports only → service detection, NSE, OS (accuracy)

```bash
#!/bin/bash
# fast_scan_pipeline.sh
# Usage: ./fast_scan_pipeline.sh <target_range> <output_prefix>

TARGET=$1
OUTPUT=$2
RATE=1000

echo "[*] Phase 1: masscan fast port discovery"
sudo masscan "$TARGET" -p 0-65535 --rate "$RATE" -oJ "${OUTPUT}_masscan.json"

echo "[*] Extracting open ports from masscan results"
# Parse JSON output and extract port numbers
OPEN_PORTS=$(python3 - << 'EOF'
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
ports = set()
for entry in data:
    for p in entry.get('ports', []):
        if p['status'] == 'open':
            ports.add(str(p['port']))
print(','.join(sorted(ports, key=int)))
EOF
"${OUTPUT}_masscan.json")

echo "[*] Open ports found: $OPEN_PORTS"

if [ -z "$OPEN_PORTS" ]; then
    echo "[!] No open ports found. Exiting."
    exit 1
fi

echo "[*] Extracting live hosts"
LIVE_HOSTS=$(python3 - << 'EOF'
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
ips = set()
for entry in data:
    ips.add(entry['ip'])
for ip in sorted(ips):
    print(ip)
EOF
"${OUTPUT}_masscan.json")

echo "$LIVE_HOSTS" > "${OUTPUT}_live_hosts.txt"

echo "[*] Phase 2: nmap deep scan on open ports of live hosts"
sudo nmap -sS -sV -sC \
     -iL "${OUTPUT}_live_hosts.txt" \
     -p "$OPEN_PORTS" \
     -oA "${OUTPUT}_nmap_deep"

echo "[+] Done."
echo "    masscan raw:   ${OUTPUT}_masscan.json"
echo "    live hosts:    ${OUTPUT}_live_hosts.txt"
echo "    nmap results:  ${OUTPUT}_nmap_deep.*"
```

---

### 9. masscan for Bug Bounty — Wildcard Scope

When a programme has a wildcard scope like `*.target.com`, you need to scan
not just the main domain but all subdomains' IPs.

```bash
# Step 1: resolve all subdomains to IPs
cat all_subdomains.txt | \
    dnsx -a -resp-only -silent | \
    sort -u > all_ips.txt

# Step 2: masscan all IPs
sudo masscan -iL all_ips.txt -p 80,443,8080,8443,8000,3000,5000 \
     --rate 500 -oJ all_ips_scan.json

# Step 3: identify unexpected open ports
# Anything not 80/443 on a web target is worth investigating
python3 - << 'EOF'
import json
with open('all_ips_scan.json') as f:
    data = json.load(f)
for entry in data:
    for p in entry.get('ports', []):
        if p['port'] not in [80, 443]:
            print(f"{entry['ip']}:{p['port']}")
EOF
```

---

### 10. Detecting masscan Scans (Blue Team)

Understanding what a masscan scan looks like to defenders helps you evade
(or detect if you are on the blue side):

```
Signature characteristics:
  - Source port randomised per packet (different from nmap which sometimes reuses)
  - Very high packet rate with no ACK completion
  - TTL of 128 (Windows default) or 64 (Linux) — does not change (stateless)
  - Window size: typically 1024 (masscan default)
  - All SYN packets, no SYN/ACK completion from the scanner
  
Firewall log pattern:
  10.10.10.100 → 10.10.10.5:1    SYN
  10.10.10.100 → 10.10.10.5:2    SYN
  10.10.10.100 → 10.10.10.5:3    SYN
  (no ACK completions)
  1000 packets in 1 second → port scan alert
```

Suricata signature for masscan detection:

```
alert tcp any any -> $HOME_NET any (
    msg: "Masscan scan detected";
    flags: S;
    flow: stateless;
    detection_filter: track by_src, count 100, seconds 5;
    sid: 9000001;
    rev: 1;
)
```

---

## Key Takeaways

1. **masscan's speed comes from being stateless.** It fires packets and records
   responses without maintaining per-connection state. This scales to millions
   of packets per second but sacrifices the ability to do service detection.
2. **The masscan + nmap pipeline is the best of both worlds.** masscan finds
   open ports in seconds; nmap identifies what is running on them accurately.
   Always pair them.
3. **Rate control is safety-critical in bug bounty.** 100,000 pps against a
   production web server is a DoS attack. Keep to 500–1000 pps for external
   internet targets.
4. **Use -oJ (JSON) output.** Text and grepable formats are harder to parse
   programmatically. JSON lets you extract IPs and ports with a 5-line Python
   script.
5. **masscan reveals the unexpected.** An SSH port (22) open on a web server
   IP, a MySQL port (3306) publicly accessible, a Redis port (6379) with no
   auth — these only appear if you look past the standard 80/443. Always scan
   the full port range.

---

## Exercises

### Exercise 1 — Rate Calibration

On your local lab:

1. Run `sudo masscan 192.168.x.x/24 -p 80,443 --rate 100` — note scan time.
2. Run again with `--rate 1000` — note scan time.
3. Run again with `--rate 10000` — note scan time.
4. At what rate do you start seeing missed results (false negatives)?

---

### Exercise 2 — The Pipeline

1. Run masscan against your lab: `sudo masscan <target_range> -p 0-65535 --rate 1000 -oJ scan.json`
2. Write a Python one-liner to extract all open port numbers from scan.json.
3. Run nmap against those ports only.
4. Compare total time (masscan + nmap) vs running `nmap -p- -sV` alone.

---

### Exercise 3 — Non-Standard Port Discovery

Against a multi-service lab environment (or HackTheBox machine):

1. Run masscan with full port range.
2. Identify any open port that is NOT in the top 1000 (the ports nmap scans
   by default).
3. For each non-standard port found: what service is running on it? Would
   nmap's default scan have found it?

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 067 — Web App Fingerprinting and Tech Stack](DAY-0067-Web-App-Fingerprinting-and-Tech-Stack.md)*
*Next: [Day 069 — Active Recon Lab](DAY-0069-Active-Recon-Lab.md)*
