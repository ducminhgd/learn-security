---
title: "Ghidra Fundamentals"
tags: [reverse-engineering, ghidra, decompiler, disassembly, function-analysis, cross-references]
module: 07-RE-01
day: 432
related_topics:
  - RE Mindset and Toolchain (Day 431)
  - Ghidra Lab Crackme 1 (Day 433)
  - x64 Assembly for RE (Day 434)
---

# Day 432 — Ghidra Fundamentals

> "The decompiler is a crutch. Use it. But never trust it blindly.
> The decompiled C is a guess — a good guess, but a guess.
> When the guess does not make sense, drop to the disassembly.
> The assembly never lies."
>
> — Ghost

---

## Goals

Navigate a binary in Ghidra with confidence.
Use the Code Browser, decompiler, and cross-reference windows effectively.
Rename functions and variables to build a clean analysis workspace.
Understand the limits of decompiled output.

**Prerequisites:** Day 431 (RE Mindset), x64 assembly basics.
**Time budget:** 4 hours.

---

## Part 1 — Ghidra Project Setup

```bash
# Start Ghidra
./ghidraRun

# Create a new project:
# File → New Project → Non-Shared Project → name it "crackmes"
# Import a binary:
# File → Import File → select binary
# Accept defaults: Ghidra auto-detects ELF/PE, architecture, language
# Double-click the imported binary to open Code Browser
# When prompted: Yes — auto-analyse with default options
```

### Key Windows

| Window | Shortcut | Purpose |
|---|---|---|
| Listing (disassembly) | — | Raw assembly, always visible |
| Decompiler | — | Pseudocode approximation of the current function |
| Symbol Tree | — | All functions, labels, imports, exports |
| Functions | — | Function list with names and sizes |
| Cross References | X | Who calls this? Who reads this address? |
| Data Type Manager | — | Structs, enums, typedefs |
| Program Trees | — | Sections / segments |

---

## Part 2 — Navigating the Code Browser

### Finding main()

ELF binaries start at `_start` (the CRT entry point). `main()` is called from
`__libc_start_main`. Ghidra usually labels it `main` automatically.

```
Symbol Tree → Functions → search "main"
  If no "main", look for the function passed as the first argument to
  __libc_start_main in _start's decompiled output.
```

### Essential Keyboard Shortcuts

```
G          — Go to address / function name
L          — Rename symbol at cursor
T          — Set type (retype a variable)
;          — Add comment at cursor
Ctrl+L     — Search for text in all listings
X          — Open cross-references for selected address/symbol
F          — Search for strings / scalars in the binary
Space      — Toggle between disassembly and decompiler graph
```

### Navigation Flow

1. Open `main()` in the decompiler.
2. Read the high-level flow. Identify calls to interesting functions.
3. Double-click a function call → navigates to that function.
4. Press `Alt+Left` (Back) to return.

---

## Part 3 — Renaming for Clarity

Ghidra's auto-analysis produces names like `FUN_00401234` and `DAT_00601010`.
Your job is to rename these as you understand them.

### Rename a Function

```
In the decompiler or Listing, click on the function name.
Press L.
Type a meaningful name (e.g., "check_password", "validate_key").
Press Enter.
```

### Retype a Variable

```
In the decompiler, right-click a variable.
Choose "Retype Variable" or press T.
Enter the correct type (int, char *, unsigned long, etc.)
```

### Add a Comment

```
In the Listing pane, position cursor on an instruction.
Press ; (semicolon).
Type your comment.
```

### A Renaming Protocol

When you encounter an unknown function:

1. Check its imports — what does it call? (`printf`, `strcmp`, `fread`…)
2. Check its cross-references — who calls it?
3. Read the decompiled body.
4. Name it with a verb-noun pattern: `check_license`, `decrypt_payload`,
   `parse_config`.

---

## Part 4 — Cross-References (XREFs)

Cross-references tell you where a function or data address is used.

```
Click on a function name in the decompiler.
Press X.
→ "Called from": every place in the binary that calls this function
→ "Referenced from": every instruction that reads/writes this address
```

**Use case — finding the comparison that validates input:**

```
Strings window: find "Correct!" or "Wrong password"
→ Click the string
→ Press X → see who references this string
→ Navigate to that function
→ Find the check that decides which string to print
→ That check is the vulnerability
```

---

## Part 5 — Decompiler Pitfalls

The decompiler is powerful but imperfect. Know these failure modes:

### Incorrect Variable Types

```c
// Ghidra says:
undefined8 uVar1;
uVar1 = FUN_00401234(param1);

// What it probably means:
char *result;
result = check_password(input);
```

Fix: retype `uVar1` as `char *` — the decompiled code immediately becomes clearer.

### Missing Function Arguments

When Ghidra does not know a function's prototype, it may show wrong argument
counts. Fix by importing the correct type library or manually setting the
function signature:

```
Right-click function name in decompiler → Edit Function Signature
Set return type and parameter types
```

### Indirect Calls / Function Pointers

```c
// Ghidra may show:
(*(code *))(param1, param2);

// This is a function pointer call. To understand it:
// 1. Find where the function pointer is set
// 2. Trace the code path that assigns it
// 3. Use dynamic analysis to see what it points to at runtime
```

### Inlined Code

The compiler may inline small functions. The decompiled output will not show
a function call — the logic appears inline. This is normal.

---

## Part 6 — A Practical Analysis Session

```
Goal: understand what this binary does and where it checks input.

Step 1: File → Import → auto-analyse
Step 2: Symbol Tree → find main()
Step 3: Decompiler → read main()
  → Note all function calls from main
  → Note all string references
Step 4: Find the string "Correct" or similar
  → Strings window → search → XREF it
Step 5: Navigate to the checking function
  → Rename all variables: "input", "expected", "result"
  → Rename the function: "check_password"
Step 6: Understand the algorithm
  → Is it a strcmp? A hash check? A custom algorithm?
Step 7: Extract the correct input or derive the key
```

---

## Key Takeaways

1. Ghidra's decompiler is your reading accelerator, not your truth oracle.
   When the pseudocode is wrong, the disassembly is always right.
2. Rename everything you understand. A renamed analysis session is ten times
   faster than one full of `FUN_00401234`.
3. Cross-references (X key) are how you navigate a binary. Follow strings to
   their referencing function; follow functions to their callers.
4. Retyping variables transforms ugly decompiler output into readable pseudocode.
5. Every binary analysis session should end with cleaner names than when you
   started.

---

## Exercises

1. Import `/bin/ls` into Ghidra. Analyse it. Find the function that handles
   the `-l` flag. Rename three functions based on what they do.
2. Import any crackme binary. Use the Strings window to find output strings.
   XREF them to find the checking function. Name that function `validate_input`.
3. Find a function in any binary that makes an indirect call
   `(*(code *))(...)`. Trace backward to where the function pointer is set.
4. In any binary, find a call to `strcmp`. XREF it to see all comparison sites.
   What strings are being compared at each site?

---

## Questions

> Add your questions here. Each question gets a Global ID (Q432.1, Q432.2 …).

---

## Navigation

← Previous: [Day 431 — RE Mindset and Toolchain](DAY-0431-RE-Mindset-and-Toolchain.md)
→ Next: [Day 433 — Ghidra Lab: Crackme 1](DAY-0433-Ghidra-Lab-Crackme-1.md)
