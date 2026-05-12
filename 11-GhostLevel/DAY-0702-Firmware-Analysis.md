---
title: "Firmware Analysis — binwalk, Squashfs, and Backdoor Hunting"
tags: [firmware-analysis, binwalk, squashfs, embedded, iot, backdoor,
  module-11-ghost-level]
module: 11-GhostLevel
day: 702
prerequisites:
  - Day 701 — Hardware Security: UART, JTAG, and Firmware Extraction
  - Day 432 — Ghidra: Static Reverse Engineering Fundamentals
related_topics:
  - Day 703 — Advanced iOS: Binary Protections and Jailbreak
  - Day 704 — Zero-Day Mindset
---

# Day 702 — Firmware Analysis: binwalk, Squashfs, and Backdoor Hunting

> "Most IoT firmware is a Linux system image in a trench coat. Under the
> compression and the proprietary header, there is a root filesystem with
> the same files you would find on any Linux box — busybox, init scripts,
> hardcoded credentials, and the web server that runs the admin panel.
> You already know how to attack Linux. Now you learn to find it inside
> a firmware blob."
>
> — Ghost

---

## Goals

Extract and analyse a firmware image using binwalk. Navigate the extracted
filesystem. Identify hardcoded credentials, private keys, default passwords,
and backdoor accounts. Locate the web server binary and understand how to
find its vulnerabilities without source code.

**Prerequisites:** Days 701, 432.
**Estimated study time:** 4 hours.

---

## 1 — Firmware Image Formats

Firmware blobs combine several data structures into one binary:

```
TYPICAL EMBEDDED LINUX FIRMWARE LAYOUT

[ Bootloader (U-Boot) ]   → boot code, not usually our target
[ Kernel image (zImage/uImage) ] → Linux kernel, compressed
[ Root filesystem ]        → THIS IS THE TARGET
  Usually one of:
  - Squashfs (read-only, compressed)
  - JFFS2 (flash-friendly, journaled)
  - UBIFS (UBI block layer)
  - CramFS (legacy)
  - ROMFS (minimal)

Optional:
[ Web server resources ]
[ Second-stage rootfs ]
[ Vendor proprietary section ]
```

---

## 2 — binwalk: Firmware Extraction

### 2.1 Basic Analysis

```bash
# Download a sample firmware (for practice, use any public firmware from:
# https://openwrt.org, https://github.com/ReFirmLabs/binwalk/wiki/,
# or a vendor's public download page)

# Scan a firmware image for known signatures
binwalk firmware.bin

# Example output:
# DECIMAL       HEXADECIMAL     DESCRIPTION
# 0             0x0             U-Boot Legacy uImage
# 65536         0x10000         Linux kernel ARM image
# 917504        0xE0000         Squashfs filesystem, little-endian, ...
# 3276800       0x320000        JFFS2 filesystem, little endian

# Extract all recognised sections
binwalk -e firmware.bin
# Creates _firmware.bin.extracted/ with extracted files

# More aggressive extraction (recursive, unpack all archives)
binwalk --extract --matryoshka firmware.bin
```

### 2.2 Navigating the Extracted Filesystem

```bash
cd _firmware.bin.extracted/

# Find the squashfs (or jffs2) root
ls -la
# Look for: squashfs-root/, jffs2-root/, or similar

ls squashfs-root/
# Expected layout: bin/ dev/ etc/ lib/ sbin/ usr/ var/ www/
# → This is the device's root filesystem

# Key files to examine immediately:
cat squashfs-root/etc/passwd          # user accounts
cat squashfs-root/etc/shadow          # password hashes (if present)
cat squashfs-root/etc/init.d/*        # startup scripts
cat squashfs-root/etc/profile         # environment setup
ls  squashfs-root/etc/                # configuration files
ls  squashfs-root/usr/sbin/           # services and daemons
```

---

## 3 — Backdoor Hunting: Hardcoded Credentials

### 3.1 Password Hashes in /etc/shadow or /etc/passwd

```bash
# Check for password hashes directly in /etc/passwd (old-style)
cat squashfs-root/etc/passwd
# Vulnerable: root:$1$xyz..:0:0:root:/root:/bin/sh
# Safe but default: root:x:0:0:root:/root:/bin/sh (shadow auth)

# If shadow exists:
cat squashfs-root/etc/shadow
# Crack with hashcat:
hashcat -m 500 -a 0 hashes.txt rockyou.txt   # MD5-crypt ($1$)
hashcat -m 1800 -a 0 hashes.txt rockyou.txt   # SHA-512-crypt ($6$)
```

### 3.2 Hardcoded Credential Strings

```bash
# Search all files for common credential patterns
grep -r "password" squashfs-root/etc/ --include="*.conf" --include="*.cfg" -l
grep -r "passwd"   squashfs-root/etc/ -l
grep -rn "admin"   squashfs-root/etc/ | grep -i "pass\|auth\|cred"

# Check init scripts for hardcoded credentials
grep -rn "login\|telnet\|ssh" squashfs-root/etc/init.d/

# Web server config
cat squashfs-root/etc/lighttpd.conf  2>/dev/null
cat squashfs-root/etc/nginx.conf     2>/dev/null
cat squashfs-root/etc/httpd.conf     2>/dev/null
```

### 3.3 Private Keys and Certificates

```bash
# Find SSH host keys (private key = complete compromise)
find squashfs-root -name "*.pem" -o -name "*.key" -o -name "id_rsa" \
     -o -name "ssh_host_*_key" 2>/dev/null

# Check if all devices ship the same key (common vendor mistake)
md5sum squashfs-root/etc/ssh/ssh_host_rsa_key
# If all devices from this vendor have the same hash: critical finding

# Find SSL/TLS certificates and keys
find squashfs-root -name "*.crt" -o -name "*.pem" | xargs file 2>/dev/null
openssl rsa -in squashfs-root/path/to/private.key -noout 2>/dev/null && \
    echo "PRIVATE KEY FOUND"
```

### 3.4 Real-World Case: Linksys E-Series Backdoor (CVE-2014-8244)

```
CASE STUDY: Multiple Linksys E-series routers (2014)

Finding from firmware analysis:
  - /usr/sbin/adminpasswd binary contained a hardcoded authentication
    bypass string
  - Any user who sent a specific HTTP request string bypassed authentication
    entirely and received admin-level access

Discovery method:
  1. Extract firmware with binwalk
  2. Run strings against all binaries in /usr/sbin/
  3. Found the backdoor string in the authentication daemon
  4. Confirmed by sending HTTP request with the string

Detection in firmware:
  strings squashfs-root/usr/sbin/adminpasswd | grep -i "admin\|pass\|key"
```

---

## 4 — Web Server Binary Analysis

Most IoT admin panels run on a minimal HTTP server. Finding vulnerabilities
requires reversing the CGI/binary handler.

### 4.1 Identifying the Web Server

```bash
# Find the web server binary
ls squashfs-root/usr/sbin/ squashfs-root/usr/bin/ | grep -E "http|web|www|cgi"

# Identify the binary
file squashfs-root/usr/sbin/httpd
# Expected: ELF 32-bit LSB executable, MIPS, MIPS32 rel2 ...

# Find CGI handlers
find squashfs-root/www -name "*.cgi" -o -name "*.sh"
ls squashfs-root/www/cgi-bin/
```

### 4.2 String Analysis of the Web Binary

```bash
strings squashfs-root/usr/sbin/httpd | grep -E \
    "command|system|popen|exec|sprintf|strcpy|strcat|gets"

# Look for command injection patterns:
strings squashfs-root/usr/sbin/httpd | grep -E \
    "ping|traceroute|nslookup|iptables|ifconfig|nvram"
# If present: likely a command injection vector via web form input

# Look for authentication bypass:
strings squashfs-root/usr/sbin/httpd | grep -iE \
    "admin|password|auth|session|token|debug|test|bypass"
```

### 4.3 Emulating Firmware with QEMU

For dynamic analysis without physical hardware:

```bash
# Install QEMU user mode emulation
sudo apt-get install qemu-user-static

# For a MIPS little-endian binary:
sudo chroot squashfs-root \
    /usr/bin/qemu-mipsel-static \
    /usr/sbin/httpd -p 8080 &

# Or use firmadyne (automated firmware emulation):
# https://github.com/firmadyne/firmadyne
```

---

## 5 — Automated Analysis: FACT and Firmware Analysis Framework

```bash
# FACT (Firmware Analysis and Comparison Tool) — Docker-based
# https://github.com/fkie-cad/FACT_core

# Pull and start FACT
docker-compose up -d

# Upload firmware via web UI at http://localhost:5000
# FACT automatically:
#   - Extracts filesystem
#   - Identifies binaries and their architectures
#   - Runs static analysis plugins (string search, crypto identifier,
#     known vulnerability check, software component analysis)
#   - Compares firmware versions

# Manual grep-based equivalent for key findings:
find squashfs-root -type f -exec file {} \; | grep ELF | \
    awk '{print $1}' | sed 's/://' | while read bin; do
    strings "$bin" | grep -qiE "password|admin|secret" && echo "STRINGS: $bin"
done
```

---

## 6 — Lab Exercise

Use the firmware extracted in Day 701, or download a public firmware image
from any consumer router vendor (e.g., TP-Link, Netgear, D-Link publicly
available on their support sites).

```
FIRMWARE ANALYSIS LAB

Firmware file: _______________________________
Source: ______________________________________

EXTRACTION:
  binwalk output (key sections found):
    1. ___________________________________________________
    2. ___________________________________________________
    3. ___________________________________________________
  Filesystem type: squashfs / jffs2 / other: ____________
  Extraction successful: Y / N

CREDENTIAL HUNTING:
  /etc/passwd: _________________________________________
  /etc/shadow: _________________________________________
  Hardcoded credential found: Y / N  Details: _________
  SSH private key found: Y / N  Same across devices? ___

WEB SERVER BINARY:
  Binary path: ________________________________________
  Architecture: MIPS / ARM / x86 / other: ____________
  Command injection surface identified: Y / N
    Suspicious strings: _________________________________

EMULATION (optional):
  QEMU successful: Y / N
  Web interface accessible: Y / N  Port: ______________

FINDINGS SUMMARY:
  Critical (hardcoded key/credential): ________________
  High (command injection surface): ___________________
  Medium (weak password hash): ________________________
```

---

## Key Takeaways

1. **Every IoT device is a Linux box with a compressed filesystem.** Once
   you extract the firmware, everything you already know about Linux security —
   credential auditing, binary analysis, web vulnerability testing — applies
   directly.
2. **Hardcoded credentials are endemic in IoT firmware.** Vendors ship with
   default root passwords, shared SSH host keys, and hardcoded admin tokens
   that survive factory reset. Extract the firmware before testing the device
   — you will find the credentials before you try to brute-force them.
3. **QEMU extends your attack surface from physical devices to images.**
   You do not need the physical router to test its web server. Chroot into
   the extracted filesystem and emulate the binary. The attack surface is the
   same binary running on your machine.
4. **Firmware comparison (diff between versions) reveals patches.** Two
   consecutive firmware versions from the same vendor, diffed with binwalk or
   FACT, will show exactly which binary changed. That change is the location
   of the patched vulnerability — apply variant analysis from Day 692.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q702.1, Q702.2 …).

---

## Navigation

← Previous: [Day 701 — Hardware Security: UART, JTAG](DAY-0701-Hardware-Security-UART-JTAG.md)
→ Next: [Day 703 — Advanced iOS: Binary Protections and Jailbreak](DAY-0703-Mobile-Advanced-iOS-Jailbreak.md)
