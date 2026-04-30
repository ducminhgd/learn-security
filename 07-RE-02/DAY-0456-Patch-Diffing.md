---
title: "Patch Diffing — Finding Bugs from Security Patches"
tags: [reverse-engineering, patch-diffing, bindiff, diaphora, CVE, vulnerability-research,
  1-day]
module: 07-RE-02
day: 456
related_topics:
  - CVE Reproduction from Patch Diff (Day 457)
  - Vulnerability Research (Module A-06)
  - Zero-Day Mindset (Module A-08)
---

# Day 456 — Patch Diffing

> "Every security patch is a public confession: the vendor just told you
> exactly where the bug was. They fixed it — but between the patch and
> the deployment, there is a window. That window is your research."
>
> — Ghost

---

## Goals

Understand why patch diffing matters for 1-day (n-day) vulnerability research.
Use BinDiff and Diaphora to compare pre-patch and post-patch binaries.
Identify the changed functions and reason about what was fixed.
Scope the work required to reproduce a CVE from the diff.

**Prerequisites:** Day 440 (algorithm recognition), Day 434 (assembly patterns), Ghidra.
**Time budget:** 4 hours.

---

## Part 1 — What Is Patch Diffing?

A security patch changes one or more functions to fix a vulnerability. By
comparing the patched and unpatched binary:

```
Unpatched binary (vulnerable)   →   Patched binary (fixed)
        ↓ diff ↓
Changed functions = potential vulnerability locations
```

This is called a **1-day** or **n-day** analysis:
- **0-day:** Vulnerability found before any patch exists.
- **1-day:** Patch released; vulnerability found by diffing; exploit written before
  most deployments update.
- **n-day:** Patch released long ago; vulnerability well-documented; exploit widely
  available.

Patch diffing is how elite teams convert "patch released" into "exploit ready"
within hours to days.

---

## Part 2 — The Patch Diffing Workflow

```
Step 1: Obtain both binaries
  - Pre-patch: from older package, archive.org, vendor portal, or package manager cache
  - Post-patch: from the latest vendor release or CVE advisory

Step 2: Run BinDiff or Diaphora on both binaries
  → Produces a similarity score for each function pair
  → Functions with score < 1.0 (changed) are your targets

Step 3: Inspect changed functions in Ghidra
  → What was added? (bounds check, NULL check, length validation?)
  → What was removed? (dead code, debug path?)
  → What was modified? (size calculation, type, comparison?)

Step 4: Understand the fix
  → The fix tells you the vulnerability class (OOB read, UAF, integer overflow…)
  → The location of the fix tells you the attack surface (input parsing, protocol handler…)

Step 5: Write a PoC for the pre-patch binary
  → Reproduce the crash, then escalate to exploitation
```

---

## Part 3 — BinDiff

BinDiff (by Zynamics/Google) compares two binaries at the function level using
a combination of structural and syntactic similarity.

### Setup

```bash
# BinDiff requires IDA Pro (commercial) or its own exporter
# Community alternative: use Diaphora (free, Ghidra or IDA plugin)
# Or: use bindiff CLI with exported BinExport files

# If you have IDA:
# Run BinExport plugin on both binaries → produces .BinExport files
# Open BinDiff → compare two .BinExport files
```

### Reading BinDiff Output

```
Function diff table (sorted by similarity, ascending = most changed first):

Address A  | Name A          | Address B  | Name B          | Similarity | Changes
-----------|-----------------|------------|-----------------|------------|--------
0x00401234 | parse_header    | 0x00401240 | parse_header    | 0.72       | 14
0x00401500 | check_bounds    | 0x00401520 | check_bounds    | 0.91       | 3
0x00401800 | process_packet  | 0x00401800 | process_packet  | 1.00       | 0 (unchanged)

→ parse_header changed significantly: 14 differences. Start here.
→ check_bounds: 3 differences. Look for the added bounds check.
```

---

## Part 4 — Diaphora (Free Alternative)

Diaphora is a free, open-source binary diffing plugin for IDA Pro and Ghidra.

```bash
# Ghidra plugin install:
# Download: https://github.com/joxeankoret/diaphora
# Copy diaphora.py to Ghidra's script directory
# Run via Script Manager

# Export both binaries:
#   open binary A in Ghidra → run diaphora_ghidra.py → produces A.sqlite
#   open binary B in Ghidra → run diaphora_ghidra.py → produces B.sqlite
# Run compare:
python3 diaphora.py A.sqlite B.sqlite -o diff_report.html
```

### Interpreting Diaphora Output

```
Best matches (similarity = 1.0): unchanged functions
Partial matches (0.5–0.99): modified functions ← investigate these
Unmatched (in A, not in B or vice versa): added or removed functions
```

---

## Part 5 — Manual Diff: Reading Changed Functions

When you identify a changed function, compare it side by side in Ghidra.

### What to Look For

**Added bounds check:**
```c
// Unpatched:
memcpy(dst, src, user_len);

// Patched:
if (user_len > sizeof(dst)) return ERR_TOO_LARGE;   // ← added
memcpy(dst, src, user_len);
```

→ Vulnerability: heap/stack buffer overflow. `user_len` not validated.

**Added NULL check:**
```c
// Unpatched:
result = lookup_object(id);
result->field = value;     // UAF or NULL deref if result is NULL/freed

// Patched:
result = lookup_object(id);
if (!result) return NULL;  // ← added
result->field = value;
```

→ Vulnerability: NULL pointer dereference or use-after-free.

**Integer overflow fix:**
```c
// Unpatched:
size_t total = count * element_size;
buf = malloc(total);

// Patched:
if (count > SIZE_MAX / element_size) return NULL;  // ← overflow check added
size_t total = count * element_size;
buf = malloc(total);
```

→ Vulnerability: integer overflow leads to undersized allocation.

---

## Part 6 — Practical Example: CVE Pattern (Simulated)

```
Scenario: A network daemon parses a TLV packet header.
Patch: Added bounds check in parse_tlv_header().

Pre-patch:
  void parse_tlv_header(uint8_t *buf) {
      uint32_t tag    = *(uint32_t*)buf;
      uint32_t length = *(uint32_t*)(buf+4);
      uint8_t *value  = buf + 8;
      memcpy(global_store, value, length);   // ← length not bounded
  }

Post-patch:
  void parse_tlv_header(uint8_t *buf) {
      uint32_t tag    = *(uint32_t*)buf;
      uint32_t length = *(uint32_t*)(buf+4);
      if (length > MAX_TLV_VALUE_SIZE) return;  // ← patch
      uint8_t *value  = buf + 8;
      memcpy(global_store, value, length);
  }
```

**Patch diff tells you:**
1. The vulnerability is in `parse_tlv_header`.
2. The class is an unbounded `memcpy` — heap/global buffer overflow.
3. The trigger is a crafted TLV packet with `length > MAX_TLV_VALUE_SIZE`.
4. A PoC sends a malformed TLV with an oversized `length` field.

---

## Part 7 — Finding the Binaries

For real CVE research:

```bash
# Linux packages — get old version from snapshot repos
apt-get download package=1.2.3  # specific version

# Debian snapshot: https://snapshot.debian.org/
# Ubuntu packages: https://launchpad.net/ubuntu/+source/...

# Windows: check archive.org for old installer versions
# macOS: Homebrew keeps formula history; brew install package@version

# Docker images with specific versions:
docker pull nginx:1.21.0   # older, potentially vulnerable
```

---

## Key Takeaways

1. Every security patch is a roadmap to a vulnerability. The changed functions
   are the bug locations.
2. BinDiff/Diaphora identify changed functions by structural similarity. Lower
   similarity = more changes = more interesting.
3. The added code in the patch tells you the missing control: missing bounds
   check, missing NULL check, missing integer overflow guard.
4. Patch diffing is how 1-day exploits are developed. Between patch release and
   widespread deployment, attackers with patch-diffing skills have a significant
   advantage.
5. Practice patch diffing on well-documented CVEs first. Read the CVE description,
   find the patch, reproduce the diff, and confirm your analysis matches the
   documented vulnerability.

---

## Exercises

1. Find CVE-2021-3156 (sudo heap overflow). Download the patched and unpatched
   sudo source code. Diff the C source first. Then diff the compiled binaries
   with Diaphora. Confirm both diffs point to the same function.
2. Find any recent CVE in a widely used open-source tool where both versions are
   available as binaries. Run Diaphora. List the top 3 changed functions.
3. Read the changed function in the pre-patch binary. Write a one-paragraph
   description of the vulnerability class and trigger condition — before reading
   the CVE description. Compare your analysis to the official write-up.
4. Estimate the time to write a working PoC for the vulnerability you identified
   in exercise 3. What information do you still need?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q456.1, Q456.2 …).

---

## Navigation

← Previous: [Day 455 — Deobfuscation Lab](DAY-0455-Deobfuscation-Lab.md)
→ Next: [Day 457 — CVE Reproduction from Patch Diff](DAY-0457-CVE-Reproduction-from-Patch-Diff.md)
