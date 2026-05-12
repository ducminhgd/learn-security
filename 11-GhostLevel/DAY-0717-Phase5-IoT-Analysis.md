---
title: "Phase 5 — IoT Target Analysis (sable-iot)"
tags: [ghost-level, iot, firmware-analysis, embedded-linux, arm,
  binwalk, module-11-ghost-level]
module: 11-GhostLevel
day: 717
prerequisites:
  - Day 716 — Phase 4: Domain Persistence
  - Day 701 — Hardware Security: UART and JTAG
  - Day 702 — Firmware Analysis
related_topics:
  - Day 718 — Phase 5: IoT Exploitation
---

# Day 717 — Phase 5: IoT Target Analysis (sable-iot)

> "Embedded Linux is just Linux with fewer libraries, older kernels,
> and developers who thought nobody would ever look at it. The mistakes
> are the same ones you find on a web server from 2005. The difference
> is the developer was certain this device would never be on the internet.
> It is always on the internet."
>
> — Ghost

---

> **ENGAGEMENT CLOCK — CHECK IN**
> Time elapsed: _______ hours | AD phase complete: Y / N

---

## Goals

Enumerate `sable-iot` (10.0.1.40). Obtain the firmware image. Extract and
analyse the filesystem. Identify at least one exploitable vulnerability before
moving to Day 718. Document all findings with evidence.

**Target time:** 3 hours on reconnaissance and firmware analysis.

---

## 1 — Network Enumeration

```bash
# ─── Scan sable-iot ───────────────────────────────────────────────────
proxychains nmap -sV -sC -O -p- --min-rate=2000 10.0.1.40 \
    -Pn 2>/dev/null | tee recon/sable-iot/nmap_full.txt

# Expected services to look for:
# 22  - SSH (old OpenSSH version?)
# 80  - HTTP (web management panel)
# 23  - Telnet (IoT devices often still run telnet)
# 8080 - Alternative HTTP
# 554 - RTSP (camera stream?)
# 1883/8883 - MQTT (IoT message broker)
# 5683 - CoAP
# Custom ports

# ─── Web panel enumeration ────────────────────────────────────────────
proxychains whatweb http://10.0.1.40/ 2>/dev/null
proxychains curl -sk http://10.0.1.40/ | head -50
proxychains curl -sk http://10.0.1.40/ -I

# ─── Directory enumeration ────────────────────────────────────────────
proxychains feroxbuster \
    -u http://10.0.1.40 \
    -w /usr/share/seclists/Discovery/Web-Content/common.txt \
    -o recon/sable-iot/web_dirs.txt \
    -k --quiet 2>/dev/null
```

```
SABLE-IOT ENUMERATION

Open ports:
  Port 22:  ________  Version: _______________________________
  Port 23:  ________  Version: _______________________________
  Port 80:  ________  Version: _______________________________
  Port 8080:________  Version: _______________________________
  Other: _______  Service: ___________________________________

Web panel:
  Server header: _______________________________________________
  Technology: _________________________________________________
  Login page found: Y / N  Path: _____________________________
  Default credentials tried: admin:admin / admin:password / root:root
    Result: ___________________________________________________

Interesting paths found:
  /firmware  : ________________________________________________
  /cgi-bin   : ________________________________________________
  /api       : ________________________________________________
  Other: ______________________________________________________

Device type / model visible: ____________________________________
Firmware version string: ________________________________________
```

---

## 2 — Firmware Acquisition

```bash
# ─── Method 1: HTTP download from management panel ────────────────────
proxychains curl -sk http://10.0.1.40/firmware -o firmware/sable_iot.bin
proxychains curl -sk http://10.0.1.40/cgi-bin/firmware.cgi \
    -o firmware/sable_iot.bin

# ─── Method 2: Authenticated download (if login required) ────────────
# Get session cookie first:
COOKIE=$(proxychains curl -sk -X POST http://10.0.1.40/login \
    -d "username=admin&password=admin" \
    -c - 2>/dev/null | grep -oP "session=\S+")

proxychains curl -sk http://10.0.1.40/firmware/download \
    -H "Cookie: $COOKIE" \
    -o firmware/sable_iot.bin

# ─── Method 3: TFTP server on the device ─────────────────────────────
proxychains tftp 10.0.1.40
# tftp> get firmware.bin
# tftp> quit

# ─── Method 4: Via pivot using sable-web access ───────────────────────
proxychains wget http://10.0.1.40/firmware -O firmware/sable_iot.bin

# ─── Verify the firmware ─────────────────────────────────────────────
file firmware/sable_iot.bin
md5sum firmware/sable_iot.bin
ls -lh firmware/sable_iot.bin
```

```
FIRMWARE ACQUISITION

Method used: ___________________________________________________
File obtained: Y / N
  Filename: firmware/sable_iot.bin
  Size: ________ bytes
  MD5: ________________________________________________________

file output: ___________________________________________________
  (expected: data / POSIX tar archive / compressed / firmware image)
```

---

## 3 — Firmware Analysis

```bash
mkdir -p firmware/extracted

# ─── Initial triage ───────────────────────────────────────────────────
# Check entropy to identify compressed/encrypted sections:
binwalk -E firmware/sable_iot.bin

# Show all signatures:
binwalk firmware/sable_iot.bin | tee recon/sable-iot/binwalk_scan.txt

# ─── Extract filesystem ───────────────────────────────────────────────
binwalk -e firmware/sable_iot.bin -C firmware/extracted/
# Or with full recursion:
binwalk --extract --depth=5 \
    firmware/sable_iot.bin -C firmware/extracted/

ls -la firmware/extracted/
```

```bash
# ─── Navigate the extracted filesystem ───────────────────────────────
ROOTFS=$(find firmware/extracted -name "etc" -type d | head -1 | \
    sed 's/\/etc//')
echo "Root FS: $ROOTFS"
ls "$ROOTFS"

# ─── Credential hunting ───────────────────────────────────────────────
# /etc/passwd and shadow
cat "$ROOTFS/etc/passwd" 2>/dev/null
cat "$ROOTFS/etc/shadow" 2>/dev/null

# Common IoT default credentials locations
find "$ROOTFS" \( -name "passwd" -o -name "shadow" -o -name "config*" \
    -o -name "*.conf" -o -name "*.cfg" \) 2>/dev/null | head -20

# Hard-coded credentials in binaries or scripts
grep -r -i "password\|passwd\|secret\|credential\|api_key\|token" \
    "$ROOTFS/etc" 2>/dev/null | grep -v "Binary file" | head -30

# ─── SSH key hunting ──────────────────────────────────────────────────
find "$ROOTFS" -name "id_rsa" -o -name "id_ed25519" \
    -o -name "authorized_keys" 2>/dev/null

# ─── Same SSH host key across devices (backdoor factory pattern) ──────
find "$ROOTFS" -path "*/ssh/ssh_host_*" 2>/dev/null
# If found: md5sum these keys → search for same key online (Shodan, censys)
```

```bash
# ─── Binary analysis ──────────────────────────────────────────────────
BINS=$(find "$ROOTFS" -type f -executable 2>/dev/null | head -30)

# Identify architecture:
file "$ROOTFS/bin/busybox" 2>/dev/null || \
    file $(find "$ROOTFS/bin" -type f 2>/dev/null | head -1)

# Dangerous functions in binaries:
for bin in "$ROOTFS/usr/sbin/"* "$ROOTFS/usr/bin/"*; do
    [ -f "$bin" ] && strings "$bin" 2>/dev/null | \
        grep -qiE "system\(|popen\(|gets\(|strcpy\(" && \
        echo "[!] Dangerous function: $bin"
done 2>/dev/null | head -20

# Web CGI scripts (command injection surface):
find "$ROOTFS" -path "*/cgi-bin/*" -type f 2>/dev/null | head -10
find "$ROOTFS" -name "*.cgi" -o -name "*.sh" 2>/dev/null | head -10
```

```
FIRMWARE ANALYSIS RESULTS

Filesystem type: squashfs / jffs2 / cramfs / ext4 / other: ________
Architecture: ARM / MIPS / x86 / other: ___________________________
OS type: BusyBox Linux / OpenWrt / other: __________________________
Kernel version: __________________________________________________

Credentials found:
  /etc/passwd users:
    root: ________________________________________________________
    admin: _______________________________________________________
    Other: _______________________________________________________

  Hardcoded credentials in configs:
    File: _________________  User: ________  Pass: ______________
    File: _________________  User: ________  Pass: ______________

SSH private keys: Y / N
  Path: _________________________________________________________
  Same key on multiple devices (shodan): Y / N / Untested

Interesting binaries / CGI scripts:
  _____________________________________________________________________
  _____________________________________________________________________

Web server: lighttpd / nginx / httpd / other: ______________________
  Config path: ____________________________________________________
  Web root: _______________________________________________________

CGI scripts found:
  Script 1: ________________  Command injection visible: Y / N
  Script 2: ________________  Command injection visible: Y / N
```

---

## 4 — Vulnerability Hypothesis

```
IOT VULNERABILITY HYPOTHESES

H1: Default credentials
  Evidence: ______________________________________________________
  Test: proxychains ssh root@10.0.1.40

H2: Hardcoded credentials from firmware
  Evidence: ______________________________________________________
  Test: login with extracted password to web panel or SSH

H3: Command injection in CGI script
  Evidence: ______________________________________________________
  Script: ________ Parameter: _____________
  Test: append ; id to the vulnerable parameter

H4: Path traversal in web panel
  Evidence: ______________________________________________________
  Test: GET /../../../../etc/passwd

H5: Old vulnerable service version
  Service: _______________________ CVE: _________________________
  Evidence from nmap: ____________________________________________

Best attack path for Day 718:
  Method: ________________________________________________________
  Entry point: ___________________________________________________
  Expected outcome: ______________________________________________
```

---

## Navigation

← Previous: [Day 716 — Phase 4: Domain Persistence](DAY-0716-Phase4-Domain-Persistence.md)
→ Next: [Day 718 — Phase 5: IoT Exploitation](DAY-0718-Phase5-IoT-Exploitation.md)
