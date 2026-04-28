---
title: "Network Credential Extraction from PCAP"
tags: [network, PCAP, credential-extraction, Wireshark, tshark, FTP, Telnet,
       HTTP-Basic, NTLM, Kerberos, credential-harvesting, T1040, T1552, ATT&CK]
module: 04-BroadSurface-04
day: 233
related_topics:
  - MITM and ARP Spoofing (Day 231)
  - SMB Relay and LLMNR Poisoning (Day 232)
  - Wireshark Lab (Day 7)
  - Linux PrivEsc Enumeration (Day 234)
---

# Day 233 — Network Credential Extraction from PCAP

> "A PCAP file is a time machine. Everything that crossed the wire is in
> there — in order, with timestamps, protocol-decoded. The question is not
> whether credentials are in the file. The question is which filter reveals
> them first. A network analyst who knows their filters finds credentials
> in minutes. An analyst who does not knows they have a capture and nothing
> else."
>
> — Ghost

---

## Goals

By the end of today's session you will be able to:

1. Extract cleartext credentials from a PCAP across six legacy protocols.
2. Identify and extract NTLM challenge-response pairs for offline cracking.
3. Detect and extract Kerberos tickets from network captures.
4. Use automated tools to accelerate credential extraction.
5. Write a credential extraction workflow that works on any unfamiliar PCAP.

**Time budget:** 4 hours.

---

## Prerequisites

| Requirement | Covered in |
|---|---|
| Wireshark capture fundamentals | Day 7 |
| MITM position (to generate the PCAP) | Day 231 |
| Hash cracking basics | Day 28 |

---

## Part 1 — The Credential Extraction Workflow

When you receive an unknown PCAP (from an engagement, a CTF, or a MITM
session), work through this sequence:

```
Step 1: Survey the capture
  tshark -r capture.pcap -qz io,phs
  → What protocols are present? How much of each?

Step 2: Identify cleartext protocols first (quick wins)
  → FTP, Telnet, HTTP Basic, POP3, IMAP, SMTP AUTH

Step 3: Extract NTLMv2 hashes for cracking
  → HTTP NTLM, SMB NTLM

Step 4: Check for Kerberos tickets
  → AS-REQ, TGS-REQ with encryptable data

Step 5: Check for TLS — can it be decrypted?
  → TLS session key log file, RSA private key (legacy)

Step 6: Extract all HTTP POST bodies and query strings
  → Web login forms, API tokens

Step 7: Extract DNS queries
  → What were they looking for? What resolved?
```

---

## Part 2 — Cleartext Protocol Extraction

### FTP — TCP 21

FTP sends credentials in plaintext. The `USER` and `PASS` commands are
visible in the TCP stream.

```bash
# Extract FTP credentials
tshark -r capture.pcap -Y "ftp.request.command == \"USER\" or \
  ftp.request.command == \"PASS\"" \
  -T fields -e frame.time -e ip.src -e ftp.request.arg

# Example output:
# 2024-01-15 10:23:01  192.168.1.20  admin
# 2024-01-15 10:23:01  192.168.1.20  SuperSecret123

# Follow the full FTP session (shows all commands + data)
tshark -r capture.pcap -z follow,tcp,ascii,<stream-number>
# Find stream number: tshark -r capture.pcap -Y "tcp.port == 21" -T fields -e tcp.stream | head -1
```

### Telnet — TCP 23

Telnet sends each keypress as a separate packet. Reassemble:

```bash
# Extract Telnet session (raw stream)
tshark -r capture.pcap -z follow,tcp,ascii,<telnet-stream-number> 2>/dev/null | \
  grep -A5 "login:\|Password:"

# Python script to reconstruct Telnet keystrokes:
python3 - <<'EOF'
import pyshark

cap = pyshark.FileCapture('capture.pcap', display_filter='telnet')
for pkt in cap:
    try:
        data = bytes.fromhex(pkt.telnet.data.replace(':', ''))
        print(data.decode('ascii', errors='replace'), end='')
    except AttributeError:
        pass
EOF
```

### HTTP Basic Authentication — TCP 80/8080

HTTP Basic Auth encodes credentials as `base64(user:password)` in the
`Authorization` header.

```bash
# Extract Authorization headers
tshark -r capture.pcap -Y "http.authorization" \
  -T fields -e frame.time -e ip.src -e ip.dst -e http.authorization

# Output: Basic YWRtaW46UGFzc3dvcmQxMjM=
# Decode:
echo "YWRtaW46UGFzc3dvcmQxMjM=" | base64 -d
# admin:Password123

# One-liner: extract and decode all Basic Auth headers
tshark -r capture.pcap -Y "http.authorization contains \"Basic\"" \
  -T fields -e http.authorization | \
  sed 's/Basic //' | \
  while read b64; do echo "$b64" | base64 -d; echo; done
```

### HTTP POST Forms — Login Pages

```bash
# Extract POST request bodies
tshark -r capture.pcap -Y "http.request.method == \"POST\"" \
  -T fields -e frame.time -e ip.src -e ip.dst \
  -e http.request.uri -e urlencoded-form.value

# Look for: username=, password=, user=, pass=, email=, token=
tshark -r capture.pcap -Y "http.request.method == \"POST\"" \
  -T fields -e text | \
  grep -iE "password|passwd|pwd|pass=|token"
```

### SMTP/POP3/IMAP — Email Credentials

```bash
# SMTP AUTH (plaintext or Base64 encoded)
tshark -r capture.pcap -Y "smtp.auth.username or smtp.auth.password" \
  -T fields -e smtp.auth.username -e smtp.auth.password

# POP3 USER/PASS
tshark -r capture.pcap -Y "pop.request.command == \"USER\" or \
  pop.request.command == \"PASS\"" \
  -T fields -e ip.src -e pop.request.parameter

# IMAP LOGIN
tshark -r capture.pcap -Y "imap.request.command == \"LOGIN\"" \
  -T fields -e ip.src -e imap.request
```

---

## Part 3 — NTLM Hash Extraction

NTLM is a challenge-response protocol. Even if you cannot read the password,
you can extract the challenge-response pair and feed it to hashcat.

### NTLM over HTTP (Webdav, OWA, IIS)

```bash
# Find HTTP NTLM exchanges
tshark -r capture.pcap -Y "ntlmssp" \
  -T fields -e frame.number -e ip.src -e ip.dst \
  -e ntlmssp.messagetype -e ntlmssp.auth.username

# Message types:
# 1 = NEGOTIATE (client)
# 2 = CHALLENGE (server) — contains the server challenge
# 3 = AUTHENTICATE (client) — contains the NTLMv2 response

# Use pcredz to automate extraction (all NTLM hashes in hashcat format)
python3 /opt/PCredz/Pcredz -f capture.pcap
```

### NTLM over SMB

```bash
# SMB NTLM (NTLMv2 hash in hashcat mode 5600 format)
# Manual extraction:
tshark -r capture.pcap -Y "ntlmssp.messagetype == 0x00000003" \
  -T fields \
  -e ntlmssp.auth.username \
  -e ntlmssp.auth.domain \
  -e ntlmssp.auth.nt_response

# tshark cannot directly format this as hashcat input
# Use impacket's pcapdump or pcredz instead:
python3 /opt/PCredz/Pcredz -f capture.pcap -t
# Output: username::domain:ServerChallenge:NTProofStr:blob
# This is exactly hashcat mode 5600 format
```

### Cracking the Extracted Hashes

```bash
# Mode 5600 = Net-NTLMv2
hashcat -m 5600 ntlm-hashes.txt /usr/share/wordlists/rockyou.txt

# Add rules for better coverage
hashcat -m 5600 ntlm-hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule \
  -r /usr/share/hashcat/rules/d3ad0ne.rule
```

---

## Part 4 — Kerberos Ticket Extraction

Kerberos is the default authentication protocol in Active Directory environments.
Certain ticket requests contain encrypted data that can be cracked offline
(Kerberoasting — from the network, not just from a domain machine).

```bash
# Find Kerberos traffic
tshark -r capture.pcap -Y "kerberos" \
  -T fields -e frame.number -e kerberos.msg_type -e kerberos.name_string

# Kerberos message types:
# 10 = AS-REQ (TGT request) — contains pre-auth data (crackable: AS-REP Roasting)
# 11 = AS-REP (TGT response)
# 12 = TGS-REQ (service ticket request) — contains encrypted TGS data
# 13 = TGS-REP (service ticket response) — contains RC4-encrypted blob (Kerberoasting)

# Extract AS-REP data for AS-REP Roasting (mode 18200)
tshark -r capture.pcap -Y "kerberos.msg_type == 11 and kerberos.encrypted_pa_data" \
  -T fields -e kerberos.cypher

# Extract TGS-REP for Kerberoasting (mode 13100)
tshark -r capture.pcap -Y "kerberos.msg_type == 13" \
  -T fields -e kerberos.cipher

# Use impacket's GetUserSPNs or ticketer to format for hashcat
```

---

## Part 5 — DNS Credential Indicators

DNS is rarely directly credential-bearing, but it reveals:
- What authentication servers were being contacted
- Which OAuth endpoints were accessed
- Internal host names useful for pivoting

```bash
# Extract all DNS queries
tshark -r capture.pcap -Y "dns.flags.response == 0" \
  -T fields -e frame.time -e ip.src -e dns.qry.name | sort -u

# Look for authentication-related domains:
# login.microsoftonline.com, accounts.google.com, oauth2.googleapis.com
# internal-ldap.corp, kdc.corp.local, dc01.corp.local

# Extract DNS answers (A records)
tshark -r capture.pcap -Y "dns.flags.response == 1 and dns.a" \
  -T fields -e dns.qry.name -e dns.a | sort -u
```

---

## Part 6 — Automated Tools

### PCredz

Scans a PCAP and extracts all credentials it finds — credit cards, NTLMv2
hashes, HTTP Basic, FTP, Kerberos, and more.

```bash
pip install PCredz
# Or: git clone https://github.com/lgandx/PCredz && cd PCredz

python3 Pcredz -f capture.pcap -v
# Outputs: each found credential with source/dest IP and protocol
```

### NetworkMiner (Windows/Mono)

GUI-based PCAP analyser. Extracts credentials, files, images, and sessions
from PCAP files automatically.

```bash
# On Linux with Mono:
mono /opt/NetworkMiner/NetworkMiner.exe capture.pcap
```

### Dsniff Suite

```bash
# dsniff — protocol-aware credential sniffer
# Can read from PCAP files:
dsniff -p capture.pcap

# mailsnarf — extract email from PCAP
mailsnarf -p capture.pcap

# urlsnarf — extract HTTP URLs
urlsnarf -p capture.pcap
```

---

## Part 7 — TLS Decryption (When Possible)

Modern credentials are TLS-encrypted. Decryption is possible if:
1. You have the server's RSA private key (legacy RSA key exchange only)
2. You have a TLS session key log file (from the browser or server process)
3. The server uses an exportable cipher suite (very rare today)

```bash
# With TLS session key log (most common modern method):
# Set SSLKEYLOGFILE environment variable before the session:
export SSLKEYLOGFILE=/tmp/tls-keys.log
curl https://target.com/login

# Decrypt in Wireshark:
# Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename
# Point to /tmp/tls-keys.log

# Command-line decryption:
tshark -r capture.pcap \
  -o tls.keylog_file:/tmp/tls-keys.log \
  -Y "http" \
  -T fields -e http.request.uri -e http.authorization
```

---

## Key Takeaways

1. **Legacy protocols are credential goldmines.** FTP, Telnet, and HTTP Basic
   Auth send credentials in the clear. Any network with these protocols has
   credentials waiting in every PCAP.
2. **NTLM hashes are crackable, not replayable directly.** NTLMv2 requires
   offline cracking. Relay (Day 232) bypasses this — but if you have a PCAP
   from a past session, cracking is your only option.
3. **PCredz saves hours.** Know your automated tools. Run them first, then
   do manual analysis to verify and extend what they found.
4. **DNS is a map of the environment.** Even when credentials are encrypted,
   DNS reveals authentication servers, AD domain names, internal subnets,
   and application endpoints. Never skip DNS analysis.
5. **TLS decryption requires preparation.** You cannot decrypt TLS from a
   historical PCAP unless you collected keys during the session. Prepare
   your environment before the engagement — `SSLKEYLOGFILE` on controlled
   machines, key extraction on servers you own.

---

## Exercises

1. Download a challenge PCAP from a CTF platform (CTFtime, PicoCTF, or
   HackTheBox). Work through the 7-step credential extraction workflow from
   Part 1. How many credential types can you find? Which step yields the
   most results?

2. Write a bash script that takes a PCAP filename as an argument and outputs:
   (a) all unique FTP credentials, (b) all decoded HTTP Basic Auth strings,
   (c) all NTLM usernames found. Use tshark as the engine.

3. Research: what is DPAPI (Data Protection API) and how does it relate to
   credential extraction? If you have a PCAP of a Windows machine communicating
   with a domain controller during login, can you extract DPAPI-protected
   data from the network traffic?

4. A captured PCAP contains only TLS traffic to `192.168.1.5:443`. You have
   no private key and no session key log. What are your remaining options for
   recovering any useful information from this capture? List all approaches,
   including any that require access beyond the PCAP file itself.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q233.1, Q233.2 …).
> Follow-up questions use hierarchical numbering (Q233.1.1, Q233.1.2 …).

---

## Navigation

← Previous: [Day 232 — SMB Relay and LLMNR Poisoning](DAY-0232-SMB-Relay-and-LLMNR-Poisoning.md)
→ Next: [Day 234 — Linux PrivEsc Enumeration](DAY-0234-Linux-PrivEsc-Enumeration.md)
