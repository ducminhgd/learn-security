---
title: "Source Code Auditing — Finding Vulnerabilities in C, C++, and Go"
tags: [vulnerability-research, source-code-audit, C, C++, Go, memory-safety,
  grep-patterns, code-review, CWE, module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 651
prerequisites:
  - Day 608 — Binary Exploitation Fundamentals
  - Day 650 — Malware Analysis Competency Check (Module 10 complete)
related_topics:
  - Code Audit Lab (Day 652)
  - Fuzzing Fundamentals (Day 653)
---

# Day 651 — Source Code Auditing: Finding Vulnerabilities in C, C++, and Go

> "Fuzzing finds bugs randomly. Code auditing finds bugs deliberately. The two
> are complementary — fuzz first to get the low-hanging fruit, then audit the
> code that the fuzzer never reaches. But auditing comes first in your head,
> because you need to understand the code to write a fuzzer that matters."
>
> — Ghost

---

## Goals

Learn systematic source code auditing methodology for C/C++ and Go. Build
grep-based pattern recognition for common bug classes. Understand which
code constructs are inherently high-risk. Apply the methodology to a small
open-source codebase.

**Prerequisites:** Day 608, Day 650 (Module 10 complete).
**Estimated study time:** 4 hours.

---

## Auditing Mindset

```
THE AUDITOR'S MENTAL MODEL
══════════════════════════════════════════════════════════════════════════

NOT: "Does this code look wrong?"
YES: "Where does user input flow? Does it reach a dangerous sink unsanitised?"

Source → (taint analysis) → Sink

Sources (where attacker-controlled data enters):
  read(), recv(), fgets(), getenv(), argv[], HTTP body, file content

Sinks (where dangerous operations happen):
  memcpy(), strcpy(), sprintf(), system(), popen(), eval(), SQL query

The audit question is always: "Can attacker-controlled input reach this sink
without being properly validated?"

THREE AUDITING APPROACHES:
  1. Bottom-up: start at sinks → trace backward to sources
  2. Top-down: start at entry points → trace data forward to sinks
  3. Grep-first: search for known dangerous patterns → read surrounding context

Ghost's recommended approach for new codebases:
  Grep first (30 min) → find the highest-risk sinks
  Then trace backward from each sink (2-3 hours per interesting sink)
  Document the call chain: source → transform → sink
```

---

## Stage 1 — Dangerous C/C++ Patterns

```python
#!/usr/bin/env python3
"""
C/C++ vulnerability grep pattern catalogue.
"""
from __future__ import annotations

C_VULNERABILITY_PATTERNS = {
    "Buffer overflow (stack)": {
        "cwe": "CWE-121",
        "grep_patterns": [
            r"strcpy\s*(",
            r"strcat\s*(",
            r"sprintf\s*(",
            r"gets\s*(",
            r"scanf\s*\(\s*\"%s",
        ],
        "vulnerable_example": 'strcpy(dst, user_input);  // dst may be too small',
        "safe_alternative":   'strncpy(dst, user_input, sizeof(dst) - 1); dst[sizeof(dst)-1] = 0;',
        "finding_note": "Count bytes in dst vs maximum possible length of src",
    },
    "Buffer overflow (heap)": {
        "cwe": "CWE-122",
        "grep_patterns": [
            r"malloc\s*\(.*strlen",
            r"memcpy\s*\(",
            r"memmove\s*\(",
        ],
        "vulnerable_example": 'char *buf = malloc(len); memcpy(buf, data, user_len);  // user_len > len',
        "safe_alternative":   'if (user_len > len) return ERROR; memcpy(buf, data, user_len);',
        "finding_note": "Verify length argument is bounded before allocation and copy",
    },
    "Integer overflow": {
        "cwe": "CWE-190",
        "grep_patterns": [
            r"malloc\s*\(\s*\w+\s*\*",        # malloc(a * b) — may overflow
            r"calloc\s*\(\s*\w+\s*,\s*\w+",  # calloc(a, b) — safer but worth checking
            r"(\w+)\s*\+\s*(\w+)\s*>\s*\w+",  # Subtraction before comparison
        ],
        "vulnerable_example": 'size_t total = n * sizeof(T); void *p = malloc(total);  // n * sizeof overflows',
        "safe_alternative":   'if (n > SIZE_MAX / sizeof(T)) return NULL; size_t total = n * sizeof(T);',
        "finding_note": "Any arithmetic that feeds a memory allocation is a target",
    },
    "Format string injection": {
        "cwe": "CWE-134",
        "grep_patterns": [
            r"printf\s*\(\s*\w",    # printf(user_str) — missing format
            r"fprintf\s*\(\s*\w+\s*,\s*\w",
            r"syslog\s*\(\s*\w+\s*,\s*\w",
            r"snprintf\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w",
        ],
        "vulnerable_example": 'printf(user_input);  // attacker uses %n to write memory',
        "safe_alternative":   'printf("%s", user_input);',
        "finding_note": "First non-stream argument to printf family must be a literal",
    },
    "Use-After-Free": {
        "cwe": "CWE-416",
        "grep_patterns": [
            r"free\s*\(",
            r"delete\s+",   # C++
        ],
        "vulnerable_example": 'free(ptr); ... use(ptr);  // dangling pointer access',
        "safe_alternative":   'free(ptr); ptr = NULL;  // + check for NULL before use',
        "finding_note": "Trace every free() — is the pointer used again after? Is it NULLed?",
    },
    "Command injection": {
        "cwe": "CWE-78",
        "grep_patterns": [
            r"system\s*\(",
            r"popen\s*\(",
            r"execv\s*\(",
            r"execl\s*\(",
            r"ShellExecute",
        ],
        "vulnerable_example": 'char cmd[256]; sprintf(cmd, "ls %s", user_path); system(cmd);',
        "safe_alternative":   'execv("/bin/ls", args);  // separate command from data',
        "finding_note": "Any user data in a shell command = command injection",
    },
    "SQL injection (C with embedded SQL)": {
        "cwe": "CWE-89",
        "grep_patterns": [
            r"sqlite3_exec\s*\(",
            r"mysql_query\s*\(",
            r"sprintf.*SELECT",
        ],
        "vulnerable_example": 'sprintf(query, "SELECT * FROM users WHERE name=\'%s\'", user_name);',
        "safe_alternative":   'sqlite3_prepare_v2(db, "SELECT ... WHERE name=?", ...); sqlite3_bind_text(...)',
        "finding_note": "Any SQL built with string concatenation is injectable",
    },
}

for pattern_name, info in C_VULNERABILITY_PATTERNS.items():
    print(f"\n[*] {pattern_name} ({info['cwe']})")
    print(f"    Grep: {info['grep_patterns'][0]}")
    print(f"    Example: {info['vulnerable_example'][:80]}")
    print(f"    Fix:     {info['safe_alternative'][:80]}")
    print(f"    Note:    {info['finding_note'][:80]}")
```

---

## Stage 2 — Go Vulnerability Patterns

```python
#!/usr/bin/env python3
"""
Go-specific vulnerability patterns.
"""
from __future__ import annotations

GO_VULNERABILITY_PATTERNS = {
    "Goroutine leak": {
        "cwe": "CWE-400",
        "grep_patterns": [r"go func\(", r"go \w+\("],
        "description": (
            "Goroutines that block forever (channel never sends, context never cancels) "
            "accumulate memory. Not a security issue directly, but can cause DoS."
        ),
        "detection": "Look for `go func()` without a corresponding context.Done() case",
    },
    "Race condition (shared state without mutex)": {
        "cwe": "CWE-362",
        "grep_patterns": [r"var \w+ =", r"^\w+ :="],
        "description": "Shared variables accessed from multiple goroutines without sync",
        "detection": "go test -race ./... — Go's built-in race detector",
    },
    "Unsafe pointer use": {
        "cwe": "CWE-119",
        "grep_patterns": [r"unsafe\.Pointer", r"unsafe\.Sizeof", r"uintptr\("],
        "description": "unsafe.Pointer bypasses Go's type and memory safety guarantees",
        "detection": "Any unsafe.Pointer usage deserves manual review",
    },
    "Unchecked error return": {
        "cwe": "CWE-252",
        "grep_patterns": [r"^\s*\w+\s*\(.*\)$", r"= \w+\("],  # call with no err check
        "description": (
            "Go functions return (value, error). Ignoring error = ignoring failure. "
            "Security-relevant: ignoring crypto errors, file write errors, auth errors."
        ),
        "detection": "errcheck linter; grep for function calls on their own line",
    },
    "Path traversal": {
        "cwe": "CWE-22",
        "grep_patterns": [r"filepath\.Join", r"os\.Open", r"os\.ReadFile"],
        "description": "User-controlled path components allow directory traversal",
        "vulnerable_example": 'os.Open(basepath + "/" + userInput)  // userInput = "../../etc/passwd"',
        "safe_alternative":   'filepath.Join(basepath, userInput) — then verify starts with basepath',
    },
    "Regex denial of service (ReDoS)": {
        "cwe": "CWE-1333",
        "grep_patterns": [r"regexp\.MustCompile\(", r"regexp\.Compile\("],
        "description": "Exponential backtracking regex applied to user input causes CPU DoS",
        "detection": "Audit regexes for nested quantifiers like (a+)+ or (a|a)*",
    },
    "SQL injection (database/sql)": {
        "cwe": "CWE-89",
        "grep_patterns": [r"db\.Query\s*\(", r"db\.Exec\s*\(", r'fmt\.Sprintf.*SELECT'],
        "vulnerable_example": 'db.Query("SELECT * FROM users WHERE id=" + userID)',
        "safe_alternative":   'db.Query("SELECT * FROM users WHERE id=?", userID)',
    },
}

print("[*] GO VULNERABILITY PATTERNS")
for name, info in GO_VULNERABILITY_PATTERNS.items():
    print(f"\n  {name} ({info['cwe']})")
    if "grep_patterns" in info:
        print(f"  Grep: {info['grep_patterns'][0]}")
    if "description" in info:
        print(f"  Desc: {info['description'][:80]}...")
```

---

## Stage 3 — Grep-First Audit Workflow

```bash
#!/usr/bin/env bash
# Grep-first audit script for C/C++ codebases
# Run from the root of the target repository

TARGET="."

echo "=== HIGH-RISK FUNCTION CALLS ==="
grep -rn --include="*.c" --include="*.cpp" --include="*.h" \
    -E "(strcpy|strcat|sprintf|gets|system|popen|printf\s*\(\s*[^\"'])" \
    "$TARGET" | grep -v "//.*strcpy\|//.*sprintf" | head -50

echo ""
echo "=== MALLOC WITH MULTIPLICATION (integer overflow check) ==="
grep -rn --include="*.c" --include="*.cpp" \
    -E "malloc\s*\([^)]*\*" \
    "$TARGET" | head -30

echo ""
echo "=== FORMAT STRING SINKS ==="
grep -rn --include="*.c" --include="*.cpp" \
    -E "(printf|fprintf|syslog|snprintf)\s*\(\s*[^\"']" \
    "$TARGET" | head -30

echo ""
echo "=== FREE WITHOUT NULL ASSIGNMENT ==="
grep -rn --include="*.c" --include="*.cpp" \
    -E "free\s*\(" \
    "$TARGET" | head -30

echo ""
echo "=== SHELL EXECUTION ==="
grep -rn --include="*.c" --include="*.cpp" \
    -E "(system|popen|exec[vl][ep]?)\s*\(" \
    "$TARGET" | head -20

echo ""
echo "=== GO: UNSAFE PACKAGE ==="
grep -rn --include="*.go" \
    -E "(unsafe\.(Pointer|Sizeof|Alignof)|uintptr\()" \
    "$TARGET" | head -20

echo ""
echo "=== GO: SQL WITHOUT PARAMETERISATION ==="
grep -rn --include="*.go" \
    -E "Sprintf.*(SELECT|INSERT|UPDATE|DELETE)" \
    "$TARGET" | head -20
```

---

## Stage 4 — Documenting a Finding

Every finding must be documented in a structured format before you move on.

```
FINDING TEMPLATE
══════════════════════════════════════════════════════════════

Title: <CWE-NNN> <Short Description> in <function/file>

File: src/parser.c
Line: 142

Severity: Critical / High / Medium / Low / Informational

Description:
  The function parse_header() at line 142 copies user-supplied data into a
  fixed-size stack buffer using strcpy() without bounds checking. An attacker
  who provides input longer than 255 bytes will overwrite the return address.

Vulnerable code:
  char header[256];
  strcpy(header, user_data);  // user_data may exceed 256 bytes

Exploitation:
  Overwrite return address with attacker-controlled value → arbitrary code
  execution. Mitigated by ASLR and stack canary but may be bypassed via
  information disclosure or brute force.

Fix:
  Use strlcpy() (BSD) or snprintf():
  snprintf(header, sizeof(header), "%s", user_data);
  header[sizeof(header) - 1] = '\0';

CWE: CWE-121 (Stack-Based Buffer Overflow)
CVSS v3: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
```

---

## Key Takeaways

1. **Start with dangerous sinks, not the whole codebase.** `strcpy`, `system`,
   `popen`, `sprintf` — these are your starting points. A 100,000-line codebase
   has maybe 50 dangerous sink calls. Read those 50 call sites, trace backward to
   the source, and you have done 80% of a meaningful audit in a fraction of the time.
2. **Grep is not the audit — it is the audit map.** The grep output tells you where
   to read carefully. The actual vulnerability is found by reading the surrounding
   code: Where does the buffer come from? Can its size be controlled? Is there
   validation before the call?
3. **Go is safer but not safe.** Go eliminates most buffer overflows and
   use-after-free bugs. But it introduces its own bug classes: goroutine leaks,
   race conditions, unchecked errors, and path traversal. Adjust your grep patterns
   for the language.
4. **Document every finding before moving on.** Auditors who keep mental notes
   lose findings. Auditors who write structured finding reports produce advisories.
   Use the template for every issue, even the low-severity ones — you do not know
   yet which ones will chain into something critical.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q651.1, Q651.2 …).

---

## Navigation

← Previous: [Day 650 — Malware Analysis Competency Check](../10-MalwareAnalysis-01/DAY-0650-Malware-Analysis-Competency-Check.md)
→ Next: [Day 652 — Code Audit Lab](DAY-0652-Code-Audit-Lab.md)
