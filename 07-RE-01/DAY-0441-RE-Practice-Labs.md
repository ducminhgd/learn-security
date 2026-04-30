---
title: "RE Practice Labs — Days 441–450"
tags: [reverse-engineering, practice, crackmes, flare-on, ghidra, gdb, frida, algorithms]
module: 07-RE-01
day: 441
related_topics:
  - Identifying Algorithms in Binaries (Day 440)
  - Packers and Obfuscation (Day 451)
  - RE Mindset and Toolchain (Day 431)
---

# Days 441–450 — RE Practice Labs

> "You have the tools. You have the theory. Now the only thing between
> you and competence is hours of practice on real binaries.
> Each day is a different challenge. Each challenge teaches you something
> the theory cannot. Start. Fail. Learn. Repeat."
>
> — Ghost

---

## Goals

Apply Days 431–440 techniques on a variety of crackmes and RE challenges.
Build muscle memory for the Ghidra workflow, GDB dynamic analysis, and
algorithm recognition.
Produce a written analysis note for each challenge.

**Prerequisites:** All of Days 431–440.
**Time budget:** 6–8 hours per day; 10 days total.

---

## How to Use This Block

Each day has a challenge assignment. Do not skip directly to hints.
Follow this protocol for every challenge:

```
1. Triage (5 min): file, checksec, strings, readelf / pefile
2. Static first (30–60 min): Ghidra — rename, comment, understand algorithm
3. Dynamic if needed (30 min): GDB or Frida to confirm values
4. Recover the flag or correct input
5. Write up (20 min): algorithm, technique used, what you learned
```

If stuck after 60 minutes of genuine effort on a single problem:
→ Check the hint.
→ Do not look at a full walkthrough until you have the flag.

---

## Day 441 — Crackme: Simple Comparison Chain

**Target:** Crackme from crackmes.one — search for Linux x64, difficulty 1–2/6.

**Challenge focus:** Character-by-character comparison with a fixed key.

**Triage questions to answer before opening Ghidra:**
1. Is it stripped?
2. What library functions does it call? (`strcmp`, `memcmp`, or manual loop?)
3. What does the binary print when given wrong input?

**Analysis goal:** Identify the comparison function, extract the expected value
without running the binary.

**Hint (Day 441):**
> Look for the string that appears in `.rodata` near the comparison site.
> Use the XREF window (X key) from the success/failure string to navigate there.

**Write-up template:**
```
Binary: <name>
Algorithm: <describe>
Key extraction method: <static / dynamic>
Result: <flag or password>
Time: <how long it took>
What to improve: <one thing>
```

---

## Day 442 — Crackme: XOR Key

**Target:** Crackme with XOR-encoded expected value. Build your own or use:

```c
// Build it yourself (so you control difficulty):
// Store expected as XOR'd bytes, compare transform(input) vs expected
// Compile stripped: gcc -O1 -s -o xor_crackme xor_crackme.c
```

**Challenge focus:** Recognise the XOR transform, invert it.

**Analysis goal:** Derive the key mathematically without brute-forcing.

**Hint (Day 442):**
> Find the loop that processes your input byte by byte.
> What constant is it XOR-ing with? The expected array XOR that constant = your key.

---

## Day 443 — Crackme: Hash-Based Validation

**Target:** Binary that hashes the input and compares the hash.

```c
// Sample structure (compile and strip):
// 1. Read input
// 2. Compute djb2 hash: hash = 5381; for each char: hash = hash*33 + c
// 3. Compare to hardcoded hash value
```

**Challenge focus:** Identify the hash algorithm, understand why you cannot
reverse it, and determine a different approach (brute-force, rainbow table, or
dictionary attack against the hash).

**Analysis goal:**
- Identify the algorithm as djb2 (or similar simple hash).
- Note the hardcoded hash value.
- Brute-force it for a short word (≤ 6 chars).

**Hint (Day 443):**
> The multiplier `33` (or `0x21`) and initialiser `5381` are djb2 constants.
> Once you identify the algorithm and the target hash, write a Python brute-forcer.

---

## Day 444 — Crackme: Multi-Stage (Static Only)

**Target:** A crackme with three validation stages:
- Stage 1: Length check (must be exactly 12 chars)
- Stage 2: Checksum check (sum of bytes mod 256 == expected)
- Stage 3: XOR compare against stored array

**Challenge focus:** Solve all three stages through static analysis alone.
Do not run the binary until you have a candidate key.

**Analysis goal:**
- Map each stage in Ghidra.
- Derive the constraints.
- Write a Python solver that satisfies all three simultaneously.

**Hint (Day 444):**
> Start with the strongest constraint (Stage 3 XOR gives you the exact bytes).
> Then verify Stage 2 (checksum) is satisfied by those bytes.
> Adjust if not — but usually Stage 3 alone is sufficient.

---

## Day 445 — Algorithm Recognition Sprint

**Target:** Three short binaries, each using a different crypto primitive.
Identify the algorithm in each without reversing the full binary.

Build them yourself using: AES (OpenSSL), RC4 (manual), and CRC32 (manual).

```bash
# AES binary: compile a small file that encrypts stdin with AES-128-ECB
# RC4 binary: compile a manual RC4 implementation
# CRC32 binary: compile a CRC32 checksum calculator
gcc -O1 -s -o aes_bin aes_sample.c -lssl -lcrypto
gcc -O1 -s -o rc4_bin rc4_sample.c
gcc -O1 -s -o crc32_bin crc32_sample.c
```

**For each binary:**
1. Run the triage one-liner.
2. Search for crypto constants in Ghidra.
3. Confirm with findcrypt3 if available.
4. Answer: what algorithm, what key size, what mode?

**Time limit:** 30 minutes per binary.

---

## Day 446 — Flare-On Challenge: Level 1

**Target:** Flare-On Challenge Level 1 (any year — they are archived).
Recommended: Flare-On 11 (2024) or Flare-On 10 (2023), Challenge 1.
Download from: https://flare-on.com/

**Challenge focus:** Apply the full methodology on a real competition binary.

**Protocol:**
1. Full triage.
2. Static analysis first.
3. Dynamic only if needed.
4. Flag format: `flag@flare-on.com` or similar (check the challenge description).

**Note:** Flare-On challenges are designed to be solved statically. The flag is
usually derivable without running the binary.

---

## Day 447 — Windows PE Crackme (Linux Analysis)

**Target:** A Windows PE crackme (.exe) analysed on Linux using Ghidra.

You do not need to run it. Analyse statically.

**Analysis workflow:**
```
file crackme.exe         → confirm PE format
python3 -c "import pefile; pe = pefile.PE('crackme.exe'); ..."
→ read IAT — what functions does it import?
→ check for TLS callbacks
Open in Ghidra: File → Import → select crackme.exe
→ Ghidra supports PE natively
→ Navigate to entry point → find WinMain or main → analyse
```

**Challenge focus:** IAT reading, Windows API call recognition, PE navigation
in Ghidra.

**Windows API to recognise:**
- `GetDlgItemTextA` / `GetWindowTextA` → reads text from a UI input field
- `MessageBoxA` → shows a dialog (success/failure message)
- `lstrcmpA` → string comparison on Windows

---

## Day 448 — Frida Scripting Sprint

**Target:** crackme1 and crackme2 from Days 433 and 435.

**Challenge:** Solve both using **only Frida scripts** — no static analysis.

**crackme1 task:**
Write a Frida script that hooks `strcmp` and prints both arguments, then
recovers the password from the output.

**crackme2 task:**
Write a Frida script that:
1. Bypasses the `ptrace` anti-debug by patching the return value.
2. Hooks the `strcmp` comparison.
3. Prints the TRANSFORMED expected value.
4. Computes and prints the original key.

**Time limit:** 2 hours total for both.

---

## Day 449 — Write-Up and Pattern Reference Day

**No new binary today.** Review your analysis notes from Days 441–448.

**Tasks:**

1. Write a clean analysis note for the three most difficult challenges you faced.
   Follow this structure:
   - Binary name and what it does
   - Algorithm identified and how you identified it
   - Key extraction method (static formula / dynamic observation / brute-force)
   - Time taken and what you would do faster next time

2. Build your personal **RE Pattern Reference Card**:
   ```
   Pattern Reference Card
   ─────────────────────
   AES: S-box starts 63 7C 77 7B; constants in .rodata
   SHA-256: IV = 6a09e667 bb67ae85
   MD5: IV = 67452301 efcdab89
   RC4 KSA: loop 0..255, init S[i]=i, XOR with key
   CRC32: table at .rodata, first entry = 0, second = 77073096
   UPX: sections UPX0/UPX1, "UPX!" magic
   djb2 hash: init 5381, multiplier 33
   ptrace anti-debug: call ptrace(PTRACE_TRACEME); check == -1
   ```

3. Identify your weakest skill from this block. Write down three specific things
   you will do tomorrow to improve it.

---

## Day 450 — RE Block Competency Self-Check

**Self-assessment against the learning objectives of Days 431–440:**

| Skill | Can I do it without notes? |
|---|---|
| Five-minute triage protocol | Yes / No — practice until Yes |
| Navigate Ghidra to main(), rename functions | Yes / No |
| Read a loop, if/else, switch in disassembly | Yes / No |
| Bypass ptrace anti-debug statically | Yes / No |
| Hook strcmp with Frida | Yes / No |
| Read PE IAT and identify suspicious imports | Yes / No |
| Read ELF PLT/GOT structure | Yes / No |
| Identify AES, SHA-256, RC4 by constants | Yes / No |
| Write a YARA rule for an algorithm | Yes / No |
| Recover a key from XOR, additive, or hash-based crackme | Yes / No |

**Gate criteria for moving to Day 451:**

Reverse an unknown crackme (from crackmes.one, not previously seen) within
90 minutes using only static analysis. The crackme must have at least one
obfuscation technique (anti-debug, XOR encoding, or hash comparison).

If you cannot meet this in 90 minutes, spend the day on additional crackmes
from crackmes.one before proceeding.

---

## Key Takeaways (Practice Block)

1. Speed comes from pattern recognition, not from memorising instructions.
   The more crackmes you reverse, the faster the patterns appear.
2. Static analysis first, always. It is faster and safer than dynamic.
3. Dynamic analysis fills gaps: when you cannot derive a runtime value
   statically, hook it with Frida or catch it in GDB.
4. Write up every challenge. The write-up is where the learning solidifies.
   A challenge without a write-up is a challenge half-learned.
5. The pattern reference card is a living document. Add to it every time
   you see a new pattern.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q441-450.1, …).

---

## Navigation

← Previous: [Day 440 — Identifying Algorithms in Binaries](DAY-0440-Identifying-Algorithms-in-Binaries.md)
→ Next: [Day 451 — Packers and Obfuscation](../07-RE-02/DAY-0451-Packers-and-Obfuscation.md)
