---
title: "Phase 3 — Binary Reverse Engineering: sable_broker in Ghidra"
tags: [ghost-level, reverse-engineering, ghidra, binary-analysis,
  vulnerability-research, module-11-ghost-level]
module: 11-GhostLevel
day: 712
prerequisites:
  - Day 711 — Phase 3: Network Service Enumeration
  - Day 432 — Ghidra: Static RE Fundamentals
  - Day 451 — GDB Dynamic Analysis
related_topics:
  - Day 713 — Phase 3: Binary Exploitation
---

# Day 712 — Phase 3: Binary Reverse Engineering (sable_broker)

> "The strings told you where to look. The Ghidra decompiler will tell you
> what the code does. Your job is to read the decompiler output with the
> same scepticism you'd apply to a colleague's code review — assume it is
> wrong until you can verify it. Then find the one place where it trusts
> you too much."
>
> — Ghost

---

> **ENGAGEMENT CLOCK — CHECK IN**
> Time elapsed: _______ hours | Protocol mapped: Y / N | Crash found: Y / N

---

## Goals

Load `sable_broker` into Ghidra and audit the four operation handlers.
Identify the vulnerability class (heap overflow, stack overflow, or UAF).
Confirm the vulnerability manually. Prepare the PoC for Day 713.

**Target time:** 4 hours in Ghidra + confirmation.

---

## 1 — Ghidra Project Setup

```
GHIDRA SETUP STEPS

1. Open Ghidra → New Project → Non-Shared Project
   Name: "SABLE_Broker_Audit"
   Save location: engagement/ghidra/

2. File → Import File → select binaries/sable_broker
   Format: ELF   Language: x86:LE:32:default:gcc
   Options: Load External Libraries = NO

3. Double-click to open in CodeBrowser
   When prompted: Yes, run auto-analysis

4. Wait for analysis to complete (2–5 minutes for a small binary)

5. Set architecture-specific settings:
   Analysis → One Shot → Decompiler Parameter ID → Apply
   This improves parameter type inference significantly
```

---

## 2 — Function Navigation Strategy

```
GHIDRA NAVIGATION — SABLE BROKER

STEP 1: Find the main dispatch loop
  Window → Symbol Tree → Functions
  Look for: main(), handle_client(), dispatch(), process_request()
  If stripped: sort by size descending — the largest function is often main

STEP 2: Find operation handlers
  In the dispatch/main function, look for:
    switch(op_code) or if/else chain testing 0x01, 0x02, 0x03, 0x04
    Function calls after each case

STEP 3: Audit each handler
  For each handler function:
    → What parameters does it take? (size from network? count? offset?)
    → What memory operations does it perform? (malloc? memcpy? strcpy?)
    → Is the length/size value validated before use?
    → Can an arithmetic operation on user data overflow?
```

---

## 3 — Decompiler Audit Worksheet

### Handler 0x01 — PING

```
HANDLER ANALYSIS: Op 0x01 (PING)

Ghidra function name / address: _______________________________
Decompiled logic (summarise):
  _______________________________________________________________

User-controlled inputs: _______________________________________
Memory operations: ____________________________________________
Vulnerability: Y / N  Notes: _________________________________
```

### Handler 0x02 — GET

```
HANDLER ANALYSIS: Op 0x02 (GET)

Ghidra function name / address: _______________________________
Decompiled key lines (paste from Ghidra):
  _______________________________________________________________
  _______________________________________________________________
  _______________________________________________________________

User-controlled inputs:
  → Length field (from TLV header): ____________________________
  → Key data (N bytes from socket): ___________________________

Allocation: malloc(___________) — is argument user-controlled?
  If malloc(n): where does n come from? _______________________

memcpy/strcpy arguments:
  dst: ____________  src: ____________  size: _______________

Validation present: Y / N
  What is validated: ___________________________________________
  What is NOT validated: _______________________________________

Vulnerability hypothesis:
  [ ] Heap buffer overflow: malloc too small, copy too large
  [ ] Stack buffer overflow: stack allocation with user-supplied size
  [ ] Integer overflow before malloc
  [ ] OOB read via negative/large index
  [ ] Use-after-free: freed pointer reused
  CWE: _______ Evidence: ____________________________________
```

### Handler 0x03 — PUT

```
HANDLER ANALYSIS: Op 0x03 (PUT)

Ghidra function name / address: _______________________________
Summary: ______________________________________________________

Key data structure (how is stored data organised in memory?):
  _______________________________________________________________

Vulnerability hypothesis:
  _______________________________________________________________
```

### Handler 0x04 — ADMIN

```
HANDLER ANALYSIS: Op 0x04 (ADMIN)

Authentication check (how is the admin token verified?):
  Compare function: ____________________________________________
  Token stored at: _____________________________________________
  Token value (hardcoded?): ____________________________________

Bypass possible (timing attack, length check bypass, etc.): ______
Vulnerability after auth: ________________________________________
```

---

## 4 — Cross-Reference the Crash

```bash
# Relate the crash from Day 711 to the code path found in Ghidra
# If crash was triggered by op 0x02 with length 0xFFFF:

# In Ghidra: find the handler for 0x02
# Set breakpoint in Ghidra's emulator, or confirm with GDB

# If binary is 32-bit x86 and stripped:
gdb -q binaries/sable_broker
(gdb) set architecture i386
(gdb) break *0x<handler_address>    # from Ghidra
(gdb) run                           # then send the crashing input in another terminal

# Send the crash trigger via pwntools:
python3 - << 'EOF'
from pwn import *

conn = process('./binaries/sable_broker')  # or remote('10.0.1.20', 9000)

# The crash trigger from Day 711 (adapt to your finding)
payload = struct.pack(">BH", 0x02, 0x7FFF) + b'A' * 64
conn.send(payload)
conn.interactive()
EOF
```

```
CRASH CORRELATION WITH GHIDRA

Crash input:  op=0x__ length=______ data=________________________
Code path in Ghidra:
  → main() → handler_0x__() → <allocation> → <memcpy/copy>

Vulnerable code (Ghidra decompiler, paste 5–10 lines):
  _______________________________________________________________
  _______________________________________________________________
  _______________________________________________________________
  _______________________________________________________________

Root cause (one sentence):
  _______________________________________________________________

CWE: _______
Taint path:
  Source: recv() / read() on the length field
  → passed to: _______________________________________________
  → used in: malloc() / memcpy() at ________________________
  Sink: ____________________________________________________

Exploitability assessment (use Day 688 framework):
  Q1 — Attacker controls content: Y / N
  Q2 — Attacker controls what is corrupted: Y / N / Unknown
  Q3 — Post-corruption outcome: ___________________________
  Q4 — Attack surface: AV:N (network service, no auth)
  Severity: CVSS ~______
```

---

## 5 — Prepare for Exploitation

```
EXPLOITATION PREPARATION

Target: sable_broker, 32-bit x86 ELF, port 9000
Vulnerability: ________________________________________________
Protection summary:
  PIE:          Y / N
  Stack canary: Y / N
  NX:           Y / N
  RELRO:        None / Partial / Full

Exploitation path chosen:
  [ ] Ret2libc (if NX, no PIE, has libc)
  [ ] Shellcode on stack (if no NX)
  [ ] ROP chain (if NX + no ASLR or PIE bypass)
  [ ] Heap exploitation (tcache/fastbin if heap bug)
  [ ] format string to leak and overwrite

libc version on target: __________________________________
(get from: proxychains ssh → ldd /path/to/sable_broker)
libc base leaked: Y / N / Not needed
```

---

## Navigation

← Previous: [Day 711 — Phase 3: Network Service Enumeration](DAY-0711-Phase3-Network-Service-Enum.md)
→ Next: [Day 713 — Phase 3: Binary Exploitation and Shell](DAY-0713-Phase3-Binary-Exploitation.md)
