---
title: "Audit Campaign Day 4 — PoC Development and Crash Confirmation"
tags: [vulnerability-research, code-audit, poc-development, crash-confirmation,
  debugger, gdb, asan, module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 669
prerequisites:
  - Day 668 — Audit Campaign Day 3: Deep Manual Audit
  - Day 665 — VulnResearch Practice Sprint Day 2
related_topics:
  - Day 670 — Audit Campaign Day 5: Finding Report
  - Day 657 — CVE Reproduction Lab
---

# Day 669 — Audit Campaign Day 4: PoC Development and Crash Confirmation

> "A theory that the input at offset twelve causes an integer overflow is
> worth zero until you demonstrate it. You need two things: ASan says
> AddressSanitizer: HEAP-BUFFER-OVERFLOW and a stack trace that lands in
> the function you predicted. When you have both, you have a finding.
> Until then, you have a hypothesis. Treat it accordingly."
>
> — Ghost

---

## Goals

Convert your strongest candidate bug into a working, reproducible PoC. Get
ASan confirmation. Minimise the PoC. Confirm the stack trace matches the
predicted vulnerable function. Document the finding at advisory-quality depth.

**Prerequisites:** Day 668 (at least one candidate bug documented).
**Estimated study time:** 5–6 hours.

---

## 1 — Crafting the Triggering Input

Your candidate bug specifies a field, an offset, and a triggering value.
Now you turn that into the smallest possible file or packet that:

1. Passes all validation gates before the vulnerable code
2. Contains exactly the triggering value at exactly the right location

### Step 1: Find a Valid Baseline

Start from the smallest valid input the program accepts without crashing.

```bash
# Option 1: use an existing test file from the project's test suite
ls tests/ | head -20
BASELINE=$(ls tests/*.{png,wav,xml,bin} 2>/dev/null | head -1)

# Option 2: create a minimal valid file manually
# Read the format spec or look at how the parser reads the file header
# Create the minimal valid header in Python

# Confirm baseline does NOT crash (control):
./build-asan/[target_binary] "$BASELINE"
echo "Exit code: $? (0 = no crash; expected 0)"
```

### Step 2: Craft the Trigger

```python
#!/usr/bin/env python3
"""
Day 669 PoC — Audit campaign trigger file generator.

Template for binary file format bugs. Adapt to your target.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path


def read_field_u32_le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def write_field_u32_le(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", data, offset, value)


def craft_poc(baseline_file: str, field_offset: int, trigger_value: int) -> bytes:
    """
    Load a valid baseline input, replace the vulnerable field with the
    triggering value, and return the modified bytes.

    Args:
        baseline_file:  Path to a valid input file (accepted by the parser).
        field_offset:   Byte offset of the vulnerable field in the file.
        trigger_value:  The value that triggers the bug (e.g., 0xFFFFFFFF).
    """
    data = bytearray(Path(baseline_file).read_bytes())

    original = read_field_u32_le(data, field_offset)
    write_field_u32_le(data, field_offset, trigger_value)

    print(f"[*] Field at offset 0x{field_offset:04x}: "
          f"0x{original:08x} → 0x{trigger_value:08x}")
    return bytes(data)


if __name__ == "__main__":
    # ── FILL IN YOUR VALUES ──────────────────────────────────────────────────
    BASELINE_FILE  = "tests/sample.bin"  # Replace with your actual test file
    FIELD_OFFSET   = 0x0C                # Byte offset of the vulnerable field
    TRIGGER_VALUE  = 0xFFFFFFFF          # Value that causes integer overflow / OOB

    # For network bugs: see craft_network_poc() from Day 665 instead
    # ── END CONFIGURATION ───────────────────────────────────────────────────

    poc = craft_poc(BASELINE_FILE, FIELD_OFFSET, TRIGGER_VALUE)
    output = Path(sys.argv[1] if len(sys.argv) > 1 else "poc_campaign.bin")
    output.write_bytes(poc)
    print(f"[*] PoC written: {output} ({len(poc)} bytes)")
    print(f"[*] Run: ./build-asan/[target_binary] {output}")
```

### Step 3: Run the PoC Against the ASan Build

```bash
# Run the PoC
ASAN_OPTIONS="detect_odr_violation=0" \
  ./build-asan/[target_binary] poc_campaign.bin 2>&1 | tee crash_output.txt

# Key lines to look for in crash_output.txt:
grep -E "ERROR:|SUMMARY:|#[0-9]+ " crash_output.txt | head -20

# Expected output pattern:
# ==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
# READ/WRITE of size N at 0x... thread T0
#     #0 0x... in [VULNERABLE_FUNCTION] /path/to/file.c:LINE
#     #1 0x... in [CALLING_FUNCTION]
# SUMMARY: AddressSanitizer: heap-buffer-overflow ...
```

### PoC Confirmation Log

```
POC CONFIRMATION

Command run: ________________________________________________
Exit code: __________________________________________________

ASan error line:
  ___________________________________________________________

Crash address:
  READ of size ____ at 0x______________
  or WRITE of size ____ at 0x______________

Stack trace frame #0:
  ___________________________________________________________

Does frame #0 match the function I predicted in Day 668? Y / N

If NO — what function did it crash in?
  ___________________________________________________________
  What does this tell me about the taint path? _______________

CONFIRMED CRASH: Y / N
```

---

## 2 — Debugger Confirmation

ASan output gives you the crash type and stack trace. GDB gives you the
exact values at the moment of crash. Use both.

```bash
# Run under GDB with ASan build (disable ASLR for reproducibility)
gdb -q ./build-asan/[target_binary]
# In GDB:
# (gdb) set environment ASAN_OPTIONS=abort_on_error=1
# (gdb) run poc_campaign.bin
# ... crash occurs ...
# (gdb) bt          # full backtrace
# (gdb) frame 0     # select crash frame
# (gdb) info args   # function arguments at crash
# (gdb) x/16x $rdi  # examine memory at pointer argument
# (gdb) p/d $rsi    # print size argument as decimal

# Key GDB commands for crash analysis:
# info registers    — all register values
# x/Nx ADDR         — examine N bytes at ADDR
# p variable_name   — print variable value
# disas             — disassemble current function
# list              — show source at current position
```

### GDB Analysis Worksheet

```
GDB ANALYSIS

Crash address (from $rip or $pc): 0x____________________
Instruction at crash: _________________________________________

Key register values at crash:
  rdi (arg 1): 0x____________________ (meaning: ______________)
  rsi (arg 2): 0x____________________ (meaning: ______________)
  rdx (arg 3): 0x____________________ (meaning: ______________)

Variable values in crash frame:
  __________ = __________________ (why this matters: __________)
  __________ = __________________ (why this matters: __________)
  __________ = __________________ (why this matters: __________)

The attacker-controlled value at crash: ______________________
How far it can overwrite: _____________________________________

For UAF bugs — was free() called before? Y / N
  freed at frame: ______________________________________________
  used at frame: _______________________________________________
```

---

## 3 — Minimise the PoC

A minimal PoC is easier to analyse, easier to share with a vendor, and
proves you understand the bug. Do not ship a 1 MB crash file when
a 32-byte file demonstrates the same crash.

```bash
# AFL-based minimisation (if crash was discovered by AFL):
afl-tmin -i poc_campaign.bin -o poc_minimal.bin \
         -- ./build-asan/[target_binary] @@

# Verify minimised file still crashes:
ASAN_OPTIONS="abort_on_error=1" \
  ./build-asan/[target_binary] poc_minimal.bin 2>&1 | \
  grep -E "ERROR:|#0 "

# Manual binary search minimisation:
python3 << 'EOF'
import subprocess, sys
from pathlib import Path

original = Path("poc_campaign.bin").read_bytes()
binary   = Path("poc_minimal.bin") if Path("poc_minimal.bin").exists() \
           else Path("poc_campaign.bin")

data = bytearray(binary.read_bytes())

def crashes(d: bytes) -> bool:
    Path("/tmp/test_min.bin").write_bytes(d)
    r = subprocess.run(
        ["./build-asan/[target_binary]", "/tmp/test_min.bin"],
        capture_output=True, timeout=5
    )
    return r.returncode != 0

print(f"Start size: {len(data)} bytes")

# Try zeroing out blocks that are not needed for the crash
block_size = 16
for i in range(0, len(data), block_size):
    test = bytearray(data)
    test[i:i + block_size] = b"\x00" * min(block_size, len(data) - i)
    if crashes(bytes(test)):
        data = test  # crash still occurs — keep the zeroed version

print(f"After zero-fill minimisation: {len(data)} bytes (still crashes: {crashes(bytes(data))})")
EOF
```

---

## 4 — Write the Bug Summary

Before tomorrow's final report, write a one-page bug summary. This
is distinct from the full advisory — it is the internal document
that captures what you know for certain.

```
BUG SUMMARY — AUDIT CAMPAIGN FINDING

DATE: ______________________ AUDITOR: _______________________
TARGET: _________________________ COMMIT: ___________________

TITLE: ______________________________________________________

CWE: _________________ CVSS v3.1 (preliminary): _____________

ONE-SENTENCE DESCRIPTION:
  ___________________________________________________________
  ___________________________________________________________

VULNERABLE FUNCTION: _______________________________________
FILE / LINE: ________________________________________________

TAINT CHAIN (brief):
  Source: ____________________________________________________
  → Propagation: ____________________________________________
  → Sink: ____________________________________________________

TRIGGERING VALUE:
  Field: _______________________ Offset: ____________________
  Value: _______________________ Why: ________________________

CRASH CONFIRMED: Y / N
CRASH TYPE (ASan output):
  ___________________________________________________________

WORST-CASE IMPACT:
  [ ] RCE — arbitrary code execution from parsing malicious file
  [ ] DoS — process terminates; service disruption
  [ ] Info leak — adjacent heap/stack memory exposed
  [ ] No security impact (hardening finding only)

POC FILE: poc_campaign.bin or poc_minimal.bin
POC REPRODUCES ON CLEAN MACHINE: Y / N / not yet tested

DISCLOSURE RECOMMENDATION:
  [ ] Full advisory + responsible disclosure
  [ ] Report only (DoS, low severity)
  [ ] False positive — closing
```

---

## Key Takeaways

1. **The PoC must reproduce on a clean machine.** Your PoC is not done
   until someone who did not write it can run it and see the same crash.
   Write down every dependency, library version, and build flag. If the
   PoC requires your specific compiler or library version to reproduce, say
   so explicitly.
2. **ASan error type tells you the bug class.** `HEAP-BUFFER-OVERFLOW` is
   CWE-122/787. `heap-use-after-free` is CWE-416. `SEGV on unknown
   address` with near-null address is usually a null pointer deref, not a
   security vulnerability. Know the difference.
3. **Minimisation is how you prove understanding.** When you can reduce a
   1 MB crash file to 24 bytes and still hit the same crash frame, you have
   proven you know exactly which bytes matter. Vendors will trust that
   analysis. Reviewers will understand it immediately.
4. **If GDB and ASan disagree, believe ASan.** ASan has instrumented the
   entire runtime; GDB only sees what the CPU exposes. An ASan false positive
   is extremely rare. A GDB misread is common. Start with the ASan report.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q669.1, Q669.2 …).

---

## Navigation

← Previous: [Day 668 — Audit Campaign Day 3: Deep Manual Audit](DAY-0668-Audit-Campaign-Deep-Manual-Audit.md)
→ Next: [Day 670 — Audit Campaign Day 5: Finding Report](DAY-0670-Audit-Campaign-Finding-Report.md)
