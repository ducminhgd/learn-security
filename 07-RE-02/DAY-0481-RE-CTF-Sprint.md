---
title: "RE CTF Sprint — Days 481–489"
tags: [reverse-engineering, CTF, sprint, crackmes, flare-on, speed, triage, strategy]
module: 07-RE-02
day: 481
related_topics:
  - RE Advanced Practice (Days 458–480)
  - RE Competency Gate (Day 490)
  - RE Mindset and Toolchain (Day 431)
---

# Days 481–489 — RE CTF Sprint

> "Speed is a skill. A competition has a clock. A real engagement has a clock.
> The analyst who solves three challenges in the time others solve one is more
> valuable than the analyst who solves every challenge — eventually.
> Sprint. Document. Repeat."
>
> — Ghost

---

## Goals

Build speed and efficiency in the RE workflow without sacrificing correctness.
Practice CTF strategy: triage multiple challenges, prioritise by bang-per-hour.
Compete in at least one real online RE challenge during this block.

**Prerequisites:** All of Days 431–480. You should have solved at least 10
crackmes/Flare-On challenges before starting this sprint.
**Time budget:** 6–8 hours per day; 9 days total.

---

## Sprint Philosophy

A CTF sprint has three goals:
1. **Speed up the triage.** The first 10 minutes determine whether a challenge
   is worth spending 2 hours on or 20 minutes.
2. **Build a toolbox, not a dependency.** Every challenge should sharpen a skill,
   not just produce a flag.
3. **Track bottlenecks.** After each challenge, identify what slowed you down.
   That is your practice target.

---

## Day 481 — Speed Triage Sprint

**Challenge format:** 5 binaries, 30 minutes each = 2.5 hours.

**Find 5 Easy-Medium crackmes from crackmes.one or Flare-On challenge 1–3.**

For each binary, the only allowed output is your triage note:

```
Binary: [name]
File type: [ELF/PE, arch, stripped?]
Protections: [ASLR/PIE/NX/RELRO]
Key strings: [3–5 important strings]
Imports: [top 5 suspicious or relevant imports]
Algorithm: [your guess before opening Ghidra]
Estimated time to solve: [your estimate]
```

After 30 minutes per binary — move on, even if unsolved. Speed matters.

---

## Day 482 — Classic CTF Reversing Techniques

**Challenge focus:** Three challenges that use common CTF RE patterns.

### Pattern 1: License key checksum

The binary computes a checksum of the input and compares it to a constant.

**Speed technique:** Find the comparison instruction in Ghidra (any `cmp` with
an embedded constant). Extract the constant. Work backward to find valid input.

### Pattern 2: Multi-table lookup

The binary uses multiple lookup tables to transform input (e.g., base32,
substitution cipher).

**Speed technique:** Dump the tables from `.rodata`. Reverse the lookup to get
the valid input character set.

### Pattern 3: Recursive validation

The binary validates input recursively or through multiple passes.

**Speed technique:** Hook the exit condition with Frida. Force it to succeed.
Observe what input triggers the "correct" path.

**Time limit per challenge:** 45 minutes.

---

## Day 483 — Obfuscated Binary Sprint

**Two binaries:** One with anti-debug, one with XOR-encoded strings.

**Speed targets:**
- Anti-debug bypass: < 10 minutes from identification to working Frida script.
- XOR string recovery: < 15 minutes from identifying the key to all strings
  decrypted.

**Anti-debug speed protocol:**
```
1. strings binary | grep -i debug  → check for IsDebuggerPresent / ptrace
2. objdump -d | grep ptrace         → confirm
3. Load pre-built Frida bypass script → 30 seconds to bypass
4. Proceed with analysis
```

**XOR string speed protocol:**
```
1. strings binary — find garbled non-printable sequences
2. Open in Ghidra — find the decryption loop
3. Read the key (constant XOR operand)
4. python3: print(''.join(chr(b ^ KEY) for b in bytes([...])))
5. Done.
```

---

## Day 484 — Algorithm Recognition Speed Drill

**Format:** 10 binaries, 15 minutes each = 2.5 hours.

**Each binary uses exactly one algorithm.** Your only job is to identify it.

Algorithms covered: AES, SHA-256, MD5, RC4, CRC32, djb2 hash, Vigenère,
XOR cipher, Zlib, custom S-box.

**Scoring:**
- Correct identification with supporting evidence (constant, code pattern): pass
- Correct guess without evidence: partial credit — explain the evidence next time
- Wrong: analyse why and add the missed constant to your reference card

**Evidence must be stated:**
"AES — S-box constant `63 7C 77 7B` at address `0x00402000`."
Not "It looks like AES."

---

## Day 485 — Flare-On Speed Run

Pick any Flare-On edition's first 3 challenges.

**Time limit:** 90 minutes for all three.

Target pace:
- Challenge 1: 20 minutes
- Challenge 2: 30 minutes
- Challenge 3: 40 minutes

After the time limit, write up whatever you solved. If you did not finish
challenge 3, analyse what took time and whether it was avoidable.

**Key question to answer at the end:**
"What was the bottleneck? Triage, algorithm identification, dynamic analysis,
or write-up?"

---

## Day 486 — Live CTF Participation

**Platform:** Choose one:
- picoCTF (always-on, good RE challenges)
- CryptoHack (crypto-RE focus)
- crackmes.one timed challenges
- CTFtime.org — check for any ongoing CTF with RE category

**Rules for today:**
1. Start with triage on all available RE challenges simultaneously.
2. Sort by estimated solve time (fastest first — maximise flags per hour).
3. Set a timer: 45 minutes per challenge. If not solved, move on.
4. After the session: review any unsolved challenges.

**Track your stats:**
```
Total challenges attempted: X
Total flags captured: Y
Average time per flag: Z minutes
Fastest solve: [challenge, time]
Slowest/unsolved: [challenge, blocker]
```

---

## Day 487 — Packed Binary Speed Drill

**Two packed binaries:** One UPX, one custom packer.

**UPX speed protocol:**
```
1. die ./binary → confirms UPX
2. upx -d → unpack
3. Proceed
Total: < 5 minutes from identification to unpacked binary
```

**Custom packer speed protocol:**
```
1. die ./binary → identifies packer name or "unknown"
2. Entropy check: find high-entropy section
3. GDB: hbreak at start of high-entropy section
4. Run → catch at OEP
5. dump binary memory to file
6. Proceed with unpacked binary
Total: < 30 minutes for a simple custom packer
```

---

## Day 488 — Full RE Challenge: Unknown Binary

**The Ultimate Speed Challenge.**

Download an unknown binary from crackmes.one at difficulty 3–4/6.
Do not read any comments, ratings, or hints about it.

**Clock starts when you touch the binary.**

```
Phase 1 Triage:       target < 10 minutes
Phase 2 Static:       target < 40 minutes
Phase 3 Dynamic:      target < 20 minutes (only if static was insufficient)
Phase 4 Solution:     flag/password identified
Phase 5 Write-up:     15 minutes

Total target: < 90 minutes
```

After the clock stops: write up everything, even if you did not solve it.
"Did not solve" + "here is exactly where I got stuck" is more valuable for
learning than a solved challenge with a vague write-up.

---

## Day 489 — Sprint Retrospective and Reference Card Update

**No new binary today.** Consolidate what you learned.

### Task 1: Sprint Statistics

Fill out your sprint stats table:

```
| Day | Challenges | Flags | Avg time | Bottleneck identified |
|-----|-----------|-------|----------|-----------------------|
| 481 |           |       |          |                       |
| 482 |           |       |          |                       |
...
```

### Task 2: Pattern Reference Card — Final Update

Add every new pattern you encountered during this sprint:

```
New patterns from this sprint:
  [algorithm / technique / anti-debug variant / packer]
  → How identified
  → Bypass / recovery technique
  → Time to identify next time: [target]
```

### Task 3: Gate Readiness Assessment

**Gate requirement (Day 490):**
> Reverse a real-world crackme or packed binary (difficulty 3–4/6) within
> 90 minutes using static + dynamic analysis. Produce a clean write-up.

Rate yourself:

| Criterion | Ready? |
|---|---|
| Can triage in < 10 minutes | Yes / No |
| Can reverse a simple crackme in < 30 minutes | Yes / No |
| Can bypass anti-debug in < 10 minutes | Yes / No |
| Can identify AES/SHA/RC4 in < 5 minutes | Yes / No |
| Can unpack UPX in < 5 minutes | Yes / No |
| Can unpack a simple custom packer in < 30 minutes | Yes / No |
| Can write a clean write-up in < 15 minutes | Yes / No |

If any row is "No" → spend today drilling that specific skill before the gate.

---

## Key Takeaways (CTF Sprint Block)

1. Speed is built by repetition. You are slow because you have not done it
   100 times. Sprint blocks are how you get to 100.
2. CTF strategy: triage all challenges, start with the fastest, move on
   at the time limit. Flags per hour beats "I almost had it."
3. The bottleneck is almost never "I did not know the technique." It is
   almost always "I was slow to recognise the pattern." Fix pattern
   recognition, not technique knowledge.
4. Write-ups are your compound interest. They slow you down today and
   make you faster next month.
5. Your pattern reference card is a living document. A card that grows
   through every sprint is a card that makes every future sprint faster.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q481-489.1, …).

---

## Navigation

← Previous: [Days 458–480 — RE Advanced Practice](DAY-0458-RE-Advanced-Practice.md)
→ Next: [Day 490 — RE Competency Gate](DAY-0490-RE-Competency-Gate.md)
