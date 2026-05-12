---
title: "OOB Read and Write Lab"
tags: [vulnerability-research, oob, lab, integer-overflow, heap-overflow,
  asan, poc, cwe-125, cwe-787, module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 674
prerequisites:
  - Day 673 — Bug Class: OOB Read and Write
  - Day 393 — Heap Buffer Overflow
  - Day 396 — Heap Lab: Tcache Poisoning
related_topics:
  - Day 675 — Milestone 675 and Mid-Module Retrospective
  - Day 662 — Bug Class: Integer Overflow and Format String
---

# Day 674 — OOB Read and Write Lab

> "A lab has two phases. Phase one: you trigger the bug. You see ASan
> fire, the stack trace hits the function you predicted, and it feels
> like confirmation. That is the researcher's dopamine hit. Phase two:
> you understand why it crashed, not just that it did. You trace the
> exact bytes from the malicious input to the bad memory access. That
> second phase is what separates a crash from a finding."
>
> — Ghost

---

## Goals

Trigger an OOB read and an OOB write in two purpose-built vulnerable
programs. Write minimal PoCs for both. Confirm each under ASan.
Document both findings with root cause analysis.

**Prerequisites:** Day 673.
**Estimated study time:** 5 hours.

---

## Lab Target 1 — OOB Read: `minildb`

A tiny key-value store that reads records from a binary file.
Contains a signedness confusion OOB read.

```c
/* minildb.c — OOB read via signed/unsigned confusion
 *
 * Build:
 *   clang -g -fsanitize=address,undefined \
 *         -fno-omit-frame-pointer \
 *         -o minildb minildb.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define MAX_KEY_LEN   128
#define MAX_VALUE_LEN 512
#define DB_CAPACITY    64

typedef struct {
    char    key[MAX_KEY_LEN];
    char    value[MAX_VALUE_LEN];
} Record;

static Record db[DB_CAPACITY];
static int    db_size = 0;

/*
 * load_db reads records from a binary file.
 *
 * FILE FORMAT:
 *   [4 bytes LE] record count
 *   For each record:
 *     [4 bytes LE SIGNED] key length     ← vulnerability: signed, not unsigned
 *     [key_len bytes]     key data
 *     [4 bytes LE]        value length
 *     [value_len bytes]   value data
 *
 * VULNERABILITY (CWE-125, OOB read):
 *   key_len is read as int32_t (signed). A negative value passes the
 *   "< MAX_KEY_LEN" check because negative < 128. When cast to size_t
 *   for memcpy, it becomes a huge positive number → OOB read.
 */
int load_db(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) return -1;

    uint32_t count;
    fread(&count, 4, 1, fp);
    if (count > DB_CAPACITY) count = DB_CAPACITY;

    for (uint32_t i = 0; i < count; i++) {
        int32_t key_len;                        /* ← signed! */
        fread(&key_len, 4, 1, fp);

        if (key_len < MAX_KEY_LEN) {            /* ← -1 passes this check */
            fread(db[db_size].key, key_len, 1, fp); /* ← cast to size_t → huge */
        }

        uint32_t val_len;
        fread(&val_len, 4, 1, fp);
        if (val_len < MAX_VALUE_LEN) {
            fread(db[db_size].value, val_len, 1, fp);
        }
        db_size++;
    }
    fclose(fp);
    return 0;
}

void dump_db(void) {
    for (int i = 0; i < db_size; i++) {
        printf("[%d] key=%s value=%s\n", i, db[i].key, db[i].value);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) { fprintf(stderr, "Usage: %s <db.bin>\n", argv[0]); return 1; }
    if (load_db(argv[1]) != 0) { fprintf(stderr, "load failed\n"); return 1; }
    dump_db();
    return 0;
}
```

---

## Exercise 1A — Understand the OOB Read (20 minutes)

```
UNDERSTANDING EXERCISE: minildb OOB read

1. What C type is key_len? _________________________________
2. What is the maximum value of this type? _________________
3. What is the value of -1 cast to size_t on a 64-bit system?
   ___________________________________________________________
4. Why does -1 pass the check `if (key_len < MAX_KEY_LEN)`?
   ___________________________________________________________
5. What does fread(db[db_size].key, (size_t)-1, 1, fp) attempt to do?
   ___________________________________________________________
6. In practice (with a limited file), what will ASan report?
   ___________________________________________________________
```

---

## Exercise 1B — Craft the OOB Read PoC (30 minutes)

```python
#!/usr/bin/env python3
"""
Day 674 — minildb OOB read PoC.
Craft a .bin file with key_len = -1 (signed) to trigger signedness
confusion and ASan HEAP-BUFFER-OVERFLOW on fread().
"""
from __future__ import annotations

import struct
from pathlib import Path


def craft_oob_read_poc() -> bytes:
    poc = bytearray()

    # Header: 1 record
    poc += struct.pack("<I", 1)

    # ── FILL THIS IN ─────────────────────────────────────────────────────────
    # Field: key_len  (4 bytes, SIGNED)
    # Set it to -1 so it passes the < 128 check but becomes SIZE_MAX as size_t
    key_len: int = ___  # replace ___ with the correct signed int value for -1
    poc += struct.pack("<i", key_len)     # signed int32

    # No key data bytes (the exploit is in the size, not the data)

    # Field: value_len (4 bytes, UNSIGNED) — set to 0 (skip value)
    poc += struct.pack("<I", 0)
    # ─────────────────────────────────────────────────────────────────────────

    return bytes(poc)


if __name__ == "__main__":
    poc = craft_oob_read_poc()
    Path("poc_oob_read.bin").write_bytes(poc)
    print("[*] Written poc_oob_read.bin")
    print("[*] Run: ./minildb poc_oob_read.bin")
    print("[!] Expect: ASan: heap-buffer-overflow on fread")
```

```bash
# Build and test
clang -g -fsanitize=address,undefined -o minildb minildb.c
python3 poc_oob_read.py
./minildb poc_oob_read.bin 2>&1 | head -25
```

### OOB Read Confirmation Log

```
POC 1 — OOB READ CONFIRMATION

ASan error type: ______________________________________________
Crash function: _______________________________________________
Frame #0 location in source: __________________________________
Size of attempted read: ________________________________________
Address read: 0x_____________________________________________

Root cause (one sentence):
  ___________________________________________________________

Fix (what change stops the crash?):
  ___________________________________________________________
```

---

## Lab Target 2 — OOB Write: `minipacker`

A simple data serialiser with an integer overflow before allocation.

```c
/* minipacker.c — OOB write via integer overflow before malloc
 *
 * Build:
 *   clang -g -fsanitize=address,undefined \
 *         -fno-omit-frame-pointer \
 *         -o minipacker minipacker.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/*
 * pack_items serialises an array of items into a buffer.
 *
 * INPUT FORMAT:
 *   [4 bytes LE] item_count
 *   [4 bytes LE] item_size (bytes per item)
 *   [item_count * item_size bytes] item data
 *
 * VULNERABILITY (CWE-787, integer overflow → OOB write):
 *   total_size = item_count * item_size
 *   If both values are attacker-controlled and no overflow check exists,
 *   the multiplication wraps. The resulting small allocation is then
 *   written with item_count * item_size bytes → OOB write.
 */
uint8_t *pack_items(const uint8_t *input, size_t input_len,
                    size_t *out_size) {
    if (input_len < 8) return NULL;

    uint32_t item_count = *(uint32_t *)input;
    uint32_t item_size  = *(uint32_t *)(input + 4);

    /* VULNERABLE: no overflow check before multiplication */
    uint32_t total_size = item_count * item_size;   /* ← wraps on overflow */

    if (total_size == 0 || total_size > 1024 * 1024) return NULL;

    uint8_t *buf = malloc(total_size);
    if (!buf) return NULL;

    /* Copy item data into the allocated buffer */
    size_t data_len = input_len - 8;
    if (data_len > total_size) data_len = total_size; /* ← this guard uses total_size
                                                          which is the SMALL overflow result */

    /* BUG: actual data in the file may be item_count * item_size bytes,
     * all of which are read with the correct (large) size, but the buffer
     * was only total_size (small, overflowed) bytes → OOB write */
    memcpy(buf, input + 8, data_len);   /* writes data_len bytes into buf[total_size] */

    *out_size = total_size;
    return buf;
}

int main(int argc, char *argv[]) {
    if (argc < 2) { fprintf(stderr, "Usage: %s <pack.bin>\n", argv[0]); return 1; }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) { perror("fopen"); return 1; }

    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp); rewind(fp);

    uint8_t *input = malloc(sz);
    fread(input, 1, sz, fp);
    fclose(fp);

    size_t out_size = 0;
    uint8_t *packed = pack_items(input, sz, &out_size);
    if (!packed) {
        fprintf(stderr, "pack failed\n");
        free(input); return 1;
    }

    printf("[*] Packed %zu bytes\n", out_size);
    /* Use the packed data (simulate processing) */
    for (size_t i = 0; i < out_size; i++) {
        printf("%02x ", packed[i]);
    }
    printf("\n");

    free(packed);
    free(input);
    return 0;
}
```

---

## Exercise 2A — Understand the OOB Write (20 minutes)

```
UNDERSTANDING EXERCISE: minipacker OOB write

1. What types are item_count and item_size? _________________
2. What is the maximum product before overflow?
   ___________________________________________________________
3. If item_count = 0x10000 (65536) and item_size = 0x10000 (65536),
   what is item_count * item_size as uint32_t?
   ___________________________________________________________
4. malloc(total_size) allocates how many bytes with these values?
   ___________________________________________________________
5. How many bytes does memcpy write if data_len follows total_size?
   ___________________________________________________________
6. Is this an OOB write or an OOB read? ____________________
```

---

## Exercise 2B — Craft the OOB Write PoC (40 minutes)

```python
#!/usr/bin/env python3
"""
Day 674 — minipacker OOB write PoC.
Craft a .bin file with item_count and item_size values that cause
uint32_t overflow, resulting in a small allocation and a large memcpy
→ heap-buffer-overflow (write).
"""
from __future__ import annotations

import struct
from pathlib import Path


def craft_oob_write_poc() -> bytes:
    poc = bytearray()

    # ── FILL THIS IN ──────────────────────────────────────────────────────────
    # Choose item_count and item_size such that:
    #   item_count * item_size (uint32_t) = a small value (overflows)
    #   but we provide item_count * item_size (large, pre-overflow) bytes of data
    #
    # Hint: item_count = 0x___ and item_size = 0x___ where their uint32 product
    # wraps to something small (like 0x10 = 16 bytes).
    #
    # Then provide MORE than 16 bytes of actual data.

    item_count: int = ___   # replace with value that causes overflow
    item_size:  int = ___   # replace with value that causes overflow

    poc += struct.pack("<I", item_count)
    poc += struct.pack("<I", item_size)

    # Provide actual data: total_size_correct bytes (pre-overflow, large)
    # These will be memcpy'd into the small (overflowed) buffer
    total_correct = item_count * item_size  # Python: no overflow
    actual_to_send = min(total_correct, 128)  # don't make the file huge
    poc += b"A" * actual_to_send
    # ─────────────────────────────────────────────────────────────────────────

    return bytes(poc)


if __name__ == "__main__":
    poc = craft_oob_write_poc()
    Path("poc_oob_write.bin").write_bytes(poc)
    print("[*] Written poc_oob_write.bin")
    print("[*] Run: ./minipacker poc_oob_write.bin")
    print("[!] Expect: ASan: heap-buffer-overflow (write)")
```

```bash
clang -g -fsanitize=address,undefined -o minipacker minipacker.c
python3 poc_oob_write.py
./minipacker poc_oob_write.bin 2>&1 | head -25
```

### OOB Write Confirmation Log

```
POC 2 — OOB WRITE CONFIRMATION

item_count used: ____________  item_size used: ________________
uint32 product (overflow result): ____________________________
malloc size: __________________________________________________
bytes attempted to write: _____________________________________
bytes past allocation end: ____________________________________

ASan error type: ______________________________________________
  Expected: AddressSanitizer: heap-buffer-overflow on address ...
            WRITE of size N

Crash function: _______________________________________________
Frame #0: _____________________________________________________

Root cause (one sentence):
  ___________________________________________________________

Fix (the specific check needed):
  ___________________________________________________________
```

---

## Exercise 3 — Write Both Bug Reports (45 minutes)

Write abbreviated advisory-format summaries for both findings.

```
FINDING 1 — minildb OOB Read (CWE-125)

Title: Signedness confusion in load_db() allows OOB read via fread()
CWE: CWE-125 / CWE-195 (Use of Signed Integer Where Unsigned Expected)
CVSS: (fill in)

Root cause: key_len is declared int32_t but used as size_t in fread().
  A negative key_len passes the `< MAX_KEY_LEN` check and becomes SIZE_MAX
  when cast to size_t, causing fread() to attempt reading SIZE_MAX bytes.

Trigger: Set the key_len field at file offset 4 to 0xFFFFFFFF (= -1 as int32).

Impact: Program reads memory far past the db[] array boundary,
  potentially leaking heap metadata or adjacent object data.

Fix: Declare key_len as uint32_t (unsigned); or add check `key_len > 0`
  before the unsigned comparison. The specific change:
    int32_t key_len;  →  uint32_t key_len;


FINDING 2 — minipacker OOB Write (CWE-787)

Title: Integer overflow in pack_items() leads to heap OOB write via memcpy()
CWE: CWE-787 / CWE-190
CVSS: (fill in)

Root cause: total_size = item_count * item_size with no overflow check.
  If the product overflows uint32_t, malloc() receives a small value.
  memcpy() then writes data_len bytes (= the correct, large count)
  into the small allocation, overflowing the heap buffer.

Trigger: item_count = 0x10001, item_size = 0x10000 →
  product wraps to 0x10000 = 65536, but 65537 × 65536 bytes are provided.
  malloc(65536) is followed by memcpy(..., 65536) → OOB by 65536 bytes.

Impact: Heap buffer overflow; adjacent heap objects corrupted;
  potential for code execution if controlled data is written.

Fix: Add overflow check before multiplication:
  if (item_count > 0 && item_size > UINT32_MAX / item_count) return NULL;
```

---

## Key Takeaways

1. **Signedness is a type, not a decoration.** Every time you read a
   size field from external input into a signed integer, you have a
   potential vulnerability. The attacker sets the value to -1 or any
   negative number. It passes your positive-range checks and then
   becomes SIZE_MAX when the function that uses it expects an unsigned
   argument. Change the type or add an explicit non-negative check.
2. **Integer overflow before allocation is exploitable, not just a
   DoS.** A too-small allocation followed by a write of the larger,
   correct size is an OOB write into heap. With proper heap grooming,
   this is code execution. Check every multiplication of user-controlled
   values with: `if (b > MAX / a) return error;`.
3. **ASan reports the crash at the wrong site.** ASan fires at the
   `memcpy` or `fread` call, not at the arithmetic error. The arithmetic
   error is upstream, often several lines or functions earlier. When you
   see an OOB crash, trace backward from the size operand to where it
   was computed. That is the root cause.
4. **The fix is almost always at the boundary, not the operation.**
   Adding `if (key_len < 0) return error;` before the `fread` is correct
   but incomplete — it treats a symptom. The correct fix changes the type
   declaration to `uint32_t`, which makes the problem impossible to
   represent. Fix the root cause, not the downstream symptom.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q674.1, Q674.2 …).

---

## Navigation

← Previous: [Day 673 — Bug Class: OOB Read and Write](DAY-0673-Bug-Class-OOB-Read-Write.md)
→ Next: [Day 675 — Milestone 675 and Mid-Module Retrospective](DAY-0675-Milestone-675-Mid-Module-Retrospective.md)
