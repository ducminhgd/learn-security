---
title: "Ghidra Lab — Crackme 1: Find the Password"
tags: [reverse-engineering, ghidra, crackme, lab, strcmp, static-analysis]
module: 07-RE-01
day: 433
related_topics:
  - Ghidra Fundamentals (Day 432)
  - x64 Assembly for RE (Day 434)
  - Ghidra Lab Crackme 2 (Day 435)
---

# Day 433 — Ghidra Lab: Crackme 1

> "A crackme is a puzzle with one answer. Your job is not to guess —
> it is to read. The binary tells you the answer if you know how to
> ask the right questions. Read the code. The password is already
> in there."
>
> — Ghost

---

## Goals

Apply the five-minute triage protocol to a real crackme.
Use Ghidra to locate and understand the password-checking logic.
Recover the correct password without running a brute-force attack.

**Prerequisites:** Day 431 (triage), Day 432 (Ghidra navigation).
**Time budget:** 3–4 hours.

---

## Part 1 — The Lab Binary

Build this crackme yourself so you control the difficulty:

```c
// crackme1.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define SECRET "gh0st_w4s_here"

int check_password(const char *input) {
    char buf[64];
    // Simulate a "hardened" check that is still static
    int i;
    for (i = 0; i < (int)strlen(SECRET); i++) {
        if (input[i] != SECRET[i]) return 0;
    }
    if (input[strlen(SECRET)] != '\0') return 0;
    return 1;
}

int main(int argc, char *argv[]) {
    char input[128];
    printf("Enter the password: ");
    if (fgets(input, sizeof(input), stdin) == NULL) {
        fprintf(stderr, "Input error\n");
        return 1;
    }
    // Strip newline
    size_t len = strlen(input);
    if (len > 0 && input[len-1] == '\n') input[len-1] = '\0';

    if (check_password(input)) {
        printf("Access granted. Welcome, ghost.\n");
    } else {
        printf("Access denied.\n");
    }
    return 0;
}
```

```bash
# Compile — strip symbols to make it a real reversing challenge
gcc -O1 -o crackme1 crackme1.c -s
# Verify symbols are stripped:
nm crackme1 2>&1 | head
# Should say: "no symbols" or very few CRT symbols
```

---

## Part 2 — Triage (5 Minutes)

```bash
file crackme1
# → ELF 64-bit LSB executable, x86-64, stripped

checksec crackme1
# Note which protections are on (NX, RELRO, stack canary, PIE)

strings crackme1
# Look for interesting strings...
# You should see: "Enter the password:", "Access granted...", "Access denied."
# Do you see the secret itself? Why or why not?

strace ./crackme1 <<< "test"
# What syscalls? read(), write(), exit_group()
# No exec calls → not doing system() checks
```

**Triage conclusions:**
- Stripped ELF, 64-bit.
- Reads from stdin, prints one of two strings.
- `strings` may not show the secret in plaintext (why? — keep this in mind for
  more advanced crackmes).

---

## Part 3 — Static Analysis in Ghidra

### Step 1: Import and Analyse

```
File → Import File → crackme1
Auto-analyse with defaults.
```

### Step 2: Find main()

```
Symbol Tree → Functions → look for "main" or "entry"
If stripped, look in the Listing for the call to __libc_start_main.
The first argument is the address of main().
Double-click to navigate there.
```

### Step 3: Read main() in the Decompiler

You should see something like:

```c
// Ghidra decompiler output (approximate)
undefined8 main(int param_1, undefined8 param_2) {
    char local_90[128];
    size_t sVar1;

    printf("Enter the password: ");
    fgets(local_90, 0x80, stdin);
    sVar1 = strlen(local_90);
    if (0 < (long)sVar1 && local_90[sVar1 - 1] == '\n') {
        local_90[sVar1 - 1] = '\0';
    }
    if (FUN_00401156(local_90) == 0) {
        puts("Access denied.");
    } else {
        puts("Access granted. Welcome, ghost.");
    }
    return 0;
}
```

Rename `local_90` → `input_buf` (press T, set type to `char[128]`).
Rename `FUN_00401156` → `check_password` (press L).

### Step 4: Navigate to check_password()

Double-click `check_password` in the decompiler.

You should see the loop:

```c
// Approximate decompiled output
bool check_password(char *param_1) {
    int iVar1;
    size_t sVar2;
    int local_c;

    local_c = 0;
    sVar2 = strlen("gh0st_w4s_here");  // or the constant embedded
    while (local_c < (int)sVar2) {
        if (param_1[local_c] != "gh0st_w4s_here"[local_c]) {
            return false;
        }
        local_c = local_c + 1;
    }
    if (param_1[(int)sVar2] != '\0') {
        return false;
    }
    return true;
}
```

If the string is embedded as a `.rodata` reference, click the string literal in
Ghidra and press X to see what it is. The secret is `gh0st_w4s_here`.

### Step 5: Confirm

```bash
echo "gh0st_w4s_here" | ./crackme1
# → Access granted. Welcome, ghost.
```

---

## Part 4 — What If the String Is Not Visible?

If `strings` did not show the secret, the binary might:

1. **Store it character-by-character** — each char compared individually.
   Look for `cmp byte ptr [...]` instructions in the Listing.
2. **XOR-encode it** — decrypt at runtime. Look for a loop with `XOR`.
3. **Hash the input** — compare a hash. Look for crypto constants.

For this crackme, the string comparison is direct. Advanced crackmes covered in
Day 435 and beyond use obfuscation.

---

## Part 5 — Understanding the Assembly (Decompiler Verification)

In the Listing window, find the loop in `check_password`:

```asm
; The loop body — x64 Intel syntax
movsx   eax, byte ptr [rdx + rax]   ; load input[i] into AL
movsx   ecx, byte ptr [secret + rax] ; load secret[i] into CL
cmp     eax, ecx                     ; compare
jne     .fail                        ; if not equal, jump to return 0
add     eax, 1                       ; i++
```

The `secret + rax` addressing tells you the secret is at a fixed address in
`.rodata`. Press G, enter the address of `secret` — Ghidra shows you the string.

---

## Key Takeaways

1. The five-minute triage protocol provides the roadmap before opening a decompiler.
2. Strings referenced in the binary's `.rodata` section are readable via Ghidra's
   Defined Strings window — even when `strings` output is noisy.
3. Renaming functions and variables as you understand them is not optional.
   It is the primary method of building understanding incrementally.
4. The decompiler output and the disassembly should agree. When they do not,
   the disassembly wins.
5. A crackme solved through static analysis is a crackme understood. A crackme
   solved by running a brute force is a crackme skipped.

---

## Exercises

1. Modify `crackme1.c` to check a different password. Recompile, strip, and
   reverse it again from scratch in under 20 minutes. Time yourself.
2. Change the comparison to use `strcmp()` instead of the manual loop. Recompile
   and re-reverse. How does the decompiler output change?
3. Find a real Easy crackme on crackmes.one. Apply the same method. Submit the
   solution to the site to confirm.
4. After solving, write a 200-word analysis note: what was the algorithm, what
   were the relevant assembly instructions, what would a YARA rule look like
   to detect binaries using this pattern.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q433.1, Q433.2 …).

---

## Navigation

← Previous: [Day 432 — Ghidra Fundamentals](DAY-0432-Ghidra-Fundamentals.md)
→ Next: [Day 434 — x64 Assembly for Reverse Engineers](DAY-0434-x64-Assembly-for-Reverse-Engineers.md)
