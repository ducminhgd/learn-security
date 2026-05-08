---
title: "Coverage-Guided Fuzzing — Persistent Mode, Structure-Aware Input"
tags: [vulnerability-research, fuzzing, AFL++, libFuzzer, coverage,
  persistent-mode, custom-mutator, structure-aware, module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 655
prerequisites:
  - Day 654 — Fuzzing Lab
related_topics:
  - Patch Diffing and CVE Reproduction (Day 656)
  - Advanced Fuzzing Sprint (Day 664)
---

# Day 655 — Coverage-Guided Fuzzing: Persistent Mode and Structure-Aware Input

> "Basic fuzzing — corpus, mutate, run — finds the easy bugs. The hard bugs
> live behind input validation. The parser rejects your mutated input before
> it ever reaches the interesting code. To get past the parser, you need to
> generate structurally valid inputs. That is what structure-aware fuzzing does.
> And to make it fast enough to matter, you need persistent mode."
>
> — Ghost

---

## Goals

Understand AFL++ persistent mode and why it matters for speed. Understand
structure-aware fuzzing with custom mutators. Set up a dictionary-based fuzzer
for a text protocol. Understand fuzzing targets that require specific input
structure (e.g. TLS, PDF, SQL).

**Prerequisites:** Day 654.
**Estimated study time:** 4 hours.

---

## Persistent Mode — 10-100× Speedup

```c
/*
 * PERSISTENT MODE HARNESS (AFL++)
 *
 * Normal mode: fork() + exec() for every test case → ~1000 exec/s
 * Persistent mode: run in loop, no fork → ~50,000-100,000 exec/s
 *
 * Requirements: target must not maintain state between test cases
 *               (or you must reset it manually)
 */
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include "target_library.h"

/* AFL++ persistent mode uses this main() pattern */
int main(int argc, char **argv) {
    /* One-time initialisation (outside the loop) */
    target_init();

    /* AFL++ persistent loop macro */
    while (__AFL_LOOP(10000)) {
        /* Read input from stdin (AFL++ sends it) */
        uint8_t buf[65536];
        ssize_t n = read(0, buf, sizeof(buf));
        if (n <= 0) continue;

        /* Call the target function */
        /* Reset any state the target modifies */
        target_parse(buf, (size_t)n);
        target_reset_state();
    }

    target_cleanup();
    return 0;
}

/*
 * Compile with deferred fork server + persistent mode:
 *
 * afl-clang-fast -g -fsanitize=address -D__AFL_HAVE_MANUAL_CONTROL \
 *     persistent_harness.c target_lib.a -o target_persistent
 *
 * Run:
 * afl-fuzz -i corpus/ -o output/ -- ./target_persistent
 *
 * Speedup: typically 10× to 100× over normal mode
 */
```

---

## Stage 1 — Dictionary-Guided Fuzzing

For text-based protocols (HTTP, SQL, JSON), a dictionary tells the fuzzer
which tokens are meaningful. This dramatically speeds up coverage of
parser code paths.

```python
#!/usr/bin/env python3
"""
AFL++ dictionary builder for common text formats.
"""
from __future__ import annotations

from pathlib import Path


def build_http_dictionary() -> str:
    """Build an AFL++ dictionary for HTTP protocol fuzzing."""
    tokens = [
        # HTTP methods
        b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS",
        b"PATCH", b"CONNECT", b"TRACE",
        # HTTP versions
        b"HTTP/1.0", b"HTTP/1.1", b"HTTP/2",
        # Common headers
        b"Content-Type:", b"Content-Length:", b"Authorization:",
        b"Cookie:", b"Host:", b"Transfer-Encoding:", b"X-Forwarded-For:",
        # Content types
        b"application/json", b"application/x-www-form-urlencoded",
        b"multipart/form-data",
        # Special values
        b"chunked", b"gzip", b"deflate", b"keep-alive", b"close",
        # Status codes
        b"200", b"301", b"302", b"400", b"401", b"403", b"404", b"500",
    ]
    lines = []
    for token in tokens:
        escaped = token.decode("ascii", errors="replace")
        lines.append(f'"{escaped}"')
    return "\n".join(lines)


def build_json_dictionary() -> str:
    """Build an AFL++ dictionary for JSON fuzzing."""
    tokens = [
        b"{", b"}", b"[", b"]", b":", b",",
        b'"', b"null", b"true", b"false",
        b"0", b"-1", b"1.0", b"1e10",
        b'"key"', b'"value"', b'"type"', b'"id"',
    ]
    lines = [f'"{t.decode("ascii", errors="replace")}"' for t in tokens]
    return "\n".join(lines)


def build_sql_dictionary() -> str:
    """Build an AFL++ dictionary for SQL parser fuzzing."""
    tokens = [
        b"SELECT", b"INSERT", b"UPDATE", b"DELETE", b"FROM", b"WHERE",
        b"JOIN", b"LEFT JOIN", b"INNER JOIN", b"ON", b"GROUP BY",
        b"ORDER BY", b"HAVING", b"LIMIT", b"OFFSET",
        b"'", b'"', b"--", b"/*", b"*/", b";",
        b"NULL", b"TRUE", b"FALSE", b"AND", b"OR", b"NOT",
        b"UNION", b"ALL", b"DISTINCT", b"AS",
    ]
    lines = [f'"{t.decode("ascii", errors="replace")}"' for t in tokens]
    return "\n".join(lines)


# Write dictionaries to files
if __name__ == "__main__":
    Path("dicts").mkdir(exist_ok=True)
    Path("dicts/http.dict").write_text(build_http_dictionary())
    Path("dicts/json.dict").write_text(build_json_dictionary())
    Path("dicts/sql.dict").write_text(build_sql_dictionary())
    print("[*] Dictionaries written to dicts/")
    print("Usage: afl-fuzz -i corpus/ -o output/ -x dicts/json.dict -- ./target @@")
```

---

## Stage 2 — Structure-Aware Fuzzing with Custom Mutator

```python
#!/usr/bin/env python3
"""
Custom AFL++ mutator for JSON (structure-aware fuzzing).
Implements the AFL++ custom mutator Python API.
"""
from __future__ import annotations

import json
import random
import string


def _random_string(length: int = 8) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def _mutate_json_value(val: object, depth: int = 0) -> object:
    """Recursively mutate a JSON value with type-preserving mutations."""
    if depth > 5:
        return val

    r = random.random()

    if isinstance(val, str):
        mutations = [
            val + _random_string(random.randint(1, 20)),
            val * random.randint(0, 10),
            val.upper(),
            val[::-1],
            "../" * 5 + val,
            val + "\x00" * 10,
            "A" * random.randint(100, 10000),
        ]
        return random.choice(mutations)

    if isinstance(val, int):
        mutations = [0, -1, 2**31 - 1, 2**32, -(2**31), 2**63, val + 1, val - 1]
        return random.choice(mutations)

    if isinstance(val, float):
        import math
        mutations = [0.0, float("inf"), float("-inf"), float("nan"), val * 2, val / 2]
        return random.choice(mutations)

    if isinstance(val, list):
        if r < 0.3 and val:
            return [_mutate_json_value(v, depth + 1) for v in val]
        if r < 0.6:
            return val + [_mutate_json_value(val[0] if val else None, depth + 1)]
        return []

    if isinstance(val, dict):
        if r < 0.4:
            key = _random_string()
            val[key] = _mutate_json_value(None, depth + 1)
        elif r < 0.7 and val:
            random_key = random.choice(list(val.keys()))
            val[random_key] = _mutate_json_value(val[random_key], depth + 1)
        return val

    if val is None:
        return random.choice([None, 0, "", [], {}])

    return val


# AFL++ Custom Mutator API:
def fuzz(buf: bytes, add_buf: bytes, max_size: int) -> bytes:
    """AFL++ calls this with the current test case. Return mutated bytes."""
    try:
        data = json.loads(buf)
        mutated = _mutate_json_value(data)
        result = json.dumps(mutated, ensure_ascii=False)
        return result.encode("utf-8")[:max_size]
    except (json.JSONDecodeError, Exception):
        # If input is not valid JSON, fall back to byte-level mutation
        if buf:
            pos = random.randint(0, len(buf) - 1)
            buf_list = bytearray(buf)
            buf_list[pos] = random.randint(0, 255)
            return bytes(buf_list)
        return buf


# Usage: export AFL_CUSTOM_MUTATOR_LIBRARY=./json_mutator.so
# (Compile as shared library: gcc -shared -fPIC -o json_mutator.so json_mutator.c)
# For Python mutator: export AFL_PYTHON_MODULE=json_mutator
print("[*] JSON structure-aware mutator loaded")
print("    Usage: AFL_PYTHON_MODULE=json_mutator afl-fuzz -i corpus/ -o out/ -- ./target @@")
```

---

## Stage 3 — Coverage Visualisation

```bash
# Generate HTML coverage report to understand what the fuzzer is reaching

# With LLVM coverage (libFuzzer):
# 1. Compile with coverage instrumentation:
clang -g -fprofile-instr-generate -fcoverage-mapping \
    fuzz_target.c target_lib.a -o target_cov

# 2. Run on corpus to get profile data:
LLVM_PROFILE_FILE="default.profraw" ./target_cov corpus/*

# 3. Convert profile data:
llvm-profdata merge -sparse default.profraw -o default.profdata

# 4. Generate HTML report:
llvm-cov show ./target_cov \
    -instr-profile=default.profdata \
    -format=html \
    -output-dir=coverage_report/ \
    -show-line-counts-or-regions

# Open in browser:
open coverage_report/index.html

# KEY: Look for red/orange lines (NOT covered) in parsing functions
# These represent code paths the fuzzer has not reached
# → Improve corpus or add custom mutator to reach these paths
```

---

## Stage 4 — Fuzzing Hard Targets

```python
#!/usr/bin/env python3
"""
Strategies for fuzzing targets that require structured input.
"""
from __future__ import annotations

HARD_TARGET_STRATEGIES = {
    "Encrypted/authenticated protocols": {
        "problem": "Input must pass authentication before reaching parser logic",
        "solution": [
            "Patch out authentication check in instrumented binary",
            "Hook the auth function to always return success",
            "Fuzz the post-auth parser directly with a harness",
        ],
        "example": "TLS: fuzz the record parser after handshake by patching MAC verification",
    },
    "Checksum-protected formats": {
        "problem": "Mutated bytes fail checksum → parser rejects before interesting code",
        "solution": [
            "Patch out checksum verification in instrumented binary",
            "Write custom mutator that recomputes checksum after mutation",
            "libprotobuf-mutator: generates structurally valid protobuf (checksum included)",
        ],
        "example": "ZIP/PNG: CRC-32 check — patch CRC function to always return match",
    },
    "State machines": {
        "problem": "Protocol parser has states — must send messages in correct order",
        "solution": [
            "Write a full protocol client as the harness (sends multiple messages)",
            "Use AFL's network fuzzing mode with a proxy",
            "Fuzz individual state handler functions directly",
        ],
        "example": "SMB: authentication → session setup → file operations — fuzz file ops directly",
    },
    "Magic numbers and headers": {
        "problem": "Parser returns immediately if magic bytes are wrong",
        "solution": [
            "Add magic bytes as a dictionary entry",
            "Seed corpus: start with valid files (magic is correct)",
            "Write a custom mutator that preserves the magic bytes",
        ],
        "example": "PDF: first 4 bytes must be %PDF — AFL dictionary adds this token",
    },
}

for problem_type, info in HARD_TARGET_STRATEGIES.items():
    print(f"\n[*] PROBLEM: {problem_type}")
    print(f"    Issue: {info['problem'][:80]}")
    print("    Solutions:")
    for s in info["solution"][:2]:
        print(f"      → {s}")
    print(f"    Example: {info['example'][:80]}")
```

---

## Key Takeaways

1. **Persistent mode is not optional for serious fuzzing.** The fork() overhead
   caps normal mode at ~1,000 exec/s on most systems. Persistent mode gets to
   50,000–100,000 exec/s on the same hardware. This is the difference between
   finding 50M test cases in a week and finding 4B. Implement persistent mode
   for every fuzzing campaign.
2. **Dictionaries are free coverage gains.** A 100-token dictionary for JSON or
   SQL takes 20 minutes to write and immediately teaches the fuzzer which byte
   sequences trigger parser branches. Every text-based protocol should have a
   dictionary before you start the fuzzer.
3. **Structure-aware fuzzing reaches where dumb mutation cannot.** If your target
   validates input format strictly, dumb mutation wastes 99% of test cases on
   invalid inputs that are rejected at the parser's first line. A custom mutator
   that generates structurally valid inputs inverts this ratio.
4. **Coverage visualisation shows you what is left to find.** After 24 hours of
   fuzzing, the LLVM coverage report shows you exactly which lines of code have
   never executed. Those lines contain the bugs the fuzzer has not reached yet.
   Use this to guide corpus improvements and custom mutator development.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q655.1, Q655.2 …).

---

## Navigation

← Previous: [Day 654 — Fuzzing Lab](DAY-0654-Fuzzing-Lab.md)
→ Next: [Day 656 — Patch Diffing and CVE Reproduction](DAY-0656-Patch-Diffing-CVE-Reproduction.md)
