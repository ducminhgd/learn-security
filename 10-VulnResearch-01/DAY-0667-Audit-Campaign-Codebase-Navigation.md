---
title: "Audit Campaign Day 2 — Codebase Navigation and Function Prioritisation"
tags: [vulnerability-research, code-audit, codebase-navigation, taint-analysis,
  function-prioritisation, module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 667
prerequisites:
  - Day 666 — Open-Source Audit Campaign: Scoping and Setup
  - Day 651 — Source Code Auditing
related_topics:
  - Day 668 — Audit Campaign Day 3: Deep Manual Audit
  - Day 660 — Static Analysis: Semgrep and CodeQL
---

# Day 667 — Audit Campaign Day 2: Codebase Navigation and Function Prioritisation

> "You do not read a codebase the way you read a novel — front to back.
> You read it the way a detective reads a crime scene. You start at the
> entry point. You follow the data. You stop when the data reaches
> a dangerous operation. Everything between entry and danger is your
> attack chain."
>
> — Ghost

---

## Goals

Build a navigable mental model of the audit target. Identify every function
that processes external input. Produce a prioritised audit function list.
Begin the fuzzing campaign in the background.

**Prerequisites:** Day 666 (your target is selected and built).
**Estimated study time:** 4–5 hours.

---

## 1 — Entry Point to Danger: The Taint Map

### The Three Questions

Every function in a codebase falls into one of three categories for an
auditor:

1. **Source** — where external data enters (file read, socket recv, argv)
2. **Sink** — where dangerous operations occur (memcpy, malloc, exec, printf
   with format arg)
3. **Propagation** — everything in between; functions that pass, transform,
   or partially validate the data

Your job is to map the path from every Source to every Sink.

### Finding Sources

```bash
# Source patterns — external data entry points
SOURCE_PATTERNS=(
  "fread\|fgets\|fgetc\|getline\|read("    # file I/O
  "recv(\|recvfrom(\|recvmsg("             # socket I/O
  "argc\|argv\["                           # command line
  "getenv("                               # environment variables
  "sscanf\|fscanf\|scanf("                # format-string reads
  "mmap("                                 # memory-mapped files
)

for pattern in "${SOURCE_PATTERNS[@]}"; do
  echo "=== $pattern ==="
  grep -rn "$pattern" --include="*.c" --include="*.cpp" . | \
    grep -v "^Binary\|\.git" | head -20
done
```

### Finding Sinks

```bash
# Sink patterns — dangerous operations
SINK_PATTERNS=(
  "memcpy\|memmove\|memset\|bcopy"        # memory operations
  "strcpy\|strcat\|sprintf\|vsprintf"     # unsafe string ops
  "malloc\|calloc\|realloc\|alloca"       # allocations (look for size)
  "system(\|popen(\|exec[lv]"             # command execution
  "printf\|fprintf\|vprintf" 	           # format strings
  "free("                                 # deallocation (for UAF)
)

for pattern in "${SINK_PATTERNS[@]}"; do
  echo "=== $pattern ==="
  grep -rn "$pattern" --include="*.c" --include="*.cpp" . | \
    grep -v "^Binary\|\.git" | head -20
done
```

### Identifying High-Value Functions

High-value functions are those where attacker-controlled data reaches a
dangerous operation with incomplete validation between them.

```bash
# Functions that both read from input and perform dangerous ops in the same file
python3 << 'EOF'
import subprocess, collections

sources = ["fread", "fgets", "recv(", "read(", "getenv"]
sinks   = ["memcpy", "malloc", "free(", "sprintf", "strcpy", "system("]

result = subprocess.run(
    ["grep", "-rn", "--include=*.c", "--include=*.cpp",
     r"\|".join(sources + sinks), "."],
    capture_output=True, text=True
)

# Count occurrences of both sources AND sinks per file
per_file = collections.defaultdict(lambda: {"sources": 0, "sinks": 0})
for line in result.stdout.splitlines():
    fname = line.split(":")[0]
    for s in sources:
        if s in line:
            per_file[fname]["sources"] += 1
    for s in sinks:
        if s in line:
            per_file[fname]["sinks"] += 1

# Files with both sources and sinks are highest priority
hot = [(f, v["sources"], v["sinks"])
       for f, v in per_file.items()
       if v["sources"] > 0 and v["sinks"] > 0]
hot.sort(key=lambda x: x[1] + x[2], reverse=True)

print("FILE                                  SOURCES  SINKS")
print("─" * 60)
for fname, src, snk in hot[:20]:
    print(f"{fname:<40} {src:4}     {snk:4}")
EOF
```

### Taint Map Worksheet

```
TAINT MAP

Confirmed external input sources (function name, file, line):
  Source 1: ________________________ (______, line ______)
  Source 2: ________________________ (______, line ______)
  Source 3: ________________________ (______, line ______)

Data flow for Source 1 (trace the data manually 3–5 functions deep):
  → ________________ (______, line ______) — what happens here?
  → ________________ (______, line ______) — what happens here?
  → ________________ (______, line ______) — SINK — dangerous op: _______

Data flow for Source 2:
  → ________________ (______, line ______) — what happens here?
  → ________________ (______, line ______) — SINK — dangerous op: _______

Highest-priority file based on source/sink density:
  File: ________________________ Sources: ______ Sinks: ______

Top 5 functions to audit today (in priority order):
  1. ________________ in _________________ (why: _______________)
  2. ________________ in _________________ (why: _______________)
  3. ________________ in _________________ (why: _______________)
  4. ________________ in _________________ (why: _______________)
  5. ________________ in _________________ (why: _______________)
```

---

## 2 — Navigating the Code: Practical Techniques

### Use ctags for Jump-to-Definition

```bash
# Generate ctags index
ctags -R --languages=C,C++ --c-kinds=+p --extras=+q .

# In vim, jump to definition: Ctrl+]  |  Jump back: Ctrl+T
# In VS Code: install ctags extension or use LSP (clangd)

# From the command line: find all callers of a function
function callers() {
    local fname="$1"
    grep -rn "\b${fname}\s*(" --include="*.c" --include="*.cpp" .
}

callers "parse_header"    # who calls parse_header?
callers "read_chunk"      # who calls read_chunk?
```

### Cross-Reference with cscope

```bash
# Build cscope database
cscope -Rbq

# Interactive: cscope -d
# Find callers of a function (non-interactive):
cscope -dL -3 parse_header    # -3 = find callers
cscope -dL -1 parse_header    # -1 = find definition
```

### Code Reading Protocol for Each Function

When you sit down to audit a function, run this mental checklist:

```
FUNCTION AUDIT PROTOCOL

Function: _________________________________
File / Line: ______________________________

STEP 1: What does this function do?
  (1 sentence): _______________________________________________

STEP 2: What are the inputs?
  Parameter types and sizes:
    param 1: ______________ type: ________ trusted? Y / N
    param 2: ______________ type: ________ trusted? Y / N
    param 3: ______________ type: ________ trusted? Y / N

  Does any input come from external/attacker-controlled data?
    Y / N — which one: ______________________________________

STEP 3: What validations are performed on inputs?
  [ ] Size check before memcpy/malloc
  [ ] Null check before pointer dereference
  [ ] Range check on index before array access
  [ ] Integer overflow check before multiplication
  [ ] None apparent

STEP 4: Are there dangerous operations?
  Dangerous operation: _______________________________________
  Is the operand validated before this operation? Y / N / PARTIAL
  If partial: what is the gap? __________________________________

STEP 5: What is the worst case?
  If an attacker controls param X, what is the worst outcome?
    ___________________________________________________________

VERDICT:
  [ ] Clean — validated correctly, no issue
  [ ] Suspicious — needs deeper review, incomplete validation seen
  [ ] Candidate — likely bug; will write PoC
  [ ] Confirmed — demonstrated trigger condition, writing PoC now
```

---

## 3 — Audit Function List

After your orientation, produce a written list of every function you will
audit. Do not start reading randomly. Work the list top to bottom.

```
AUDIT FUNCTION LIST

Priority | File                  | Function              | Reason
─────────┼───────────────────────┼───────────────────────┼─────────────────────
  HIGH   | _________________     | _____________________ | __________________
  HIGH   | _________________     | _____________________ | __________________
  HIGH   | _________________     | _____________________ | __________________
  MED    | _________________     | _____________________ | __________________
  MED    | _________________     | _____________________ | __________________
  MED    | _________________     | _____________________ | __________________
  LOW    | _________________     | _____________________ | __________________
  LOW    | _________________     | _____________________ | __________________

TOTAL: ______ functions to audit
Realistic coverage in 5 days: ______ functions
```

---

## 4 — Launch the Fuzzing Campaign

While you read code manually, run AFL++ in the background. Crashes found by
the fuzzer during manual review are golden: you get both the automated crash
and the code path understanding.

```bash
# Prepare a seed corpus from the project's test files
mkdir corpus_seeds
find . -name "*.png" -o -name "*.jpg" -o -name "*.wav" -o -name "*.xml" \
     -o -name "*.bin" | head -50 | xargs -I{} cp {} corpus_seeds/

# If no test files: create a minimal valid input
# For a binary format, reverse-engineer the minimum valid header manually
# (3 minutes of reading the format spec or test harness is enough)

# Launch AFL++ in the background
AFL_SKIP_CPUFREQ=1 afl-fuzz \
  -i corpus_seeds/ \
  -o afl_output/ \
  -m none \
  -- ./build-asan/[target_binary] @@ &

AFL_PID=$!
echo "AFL++ running as PID $AFL_PID"
echo "Check progress: afl-whatsup afl_output/"
echo "Stop when done: kill $AFL_PID"

# Leave it running during your manual code review session
# Check status periodically:
sleep 300 && afl-whatsup afl_output/ &
```

### Fuzzing Campaign Log

```
FUZZING CAMPAIGN

Binary: _______________________________
Corpus: _____________ files, total ________ bytes
AFL++ started at: ______________________

After 30 minutes:
  Execs/sec: ____________
  Paths found: ____________
  Crashes: ____________

After 2 hours:
  Execs/sec: ____________
  Paths found: ____________
  Crashes: ____________
  (triage crashes: afl-triage afl_output/crashes/ ...)
```

---

## 5 — First Manual Reads: High-Priority Functions

Start with the top 3 functions from your audit list. For each one, apply
the Function Audit Protocol above. Your goal by end of day:

- At minimum 3 functions fully audited with the protocol worksheet filled
- At least 1 "Suspicious" or "Candidate" verdict
- Fuzzing campaign running in background

### Common Patterns Worth Slowing Down For

```c
// Pattern 1: Integer arithmetic before size-controlled operation
// ─────────────────────────────────────────────────────────────
// A length field is read from the file, arithmetic is performed on it,
// and the result is used as a size for malloc or memcpy.
// Risk: integer overflow in the arithmetic produces a small result,
// leading to undersized allocation or OOB write.

size_t chunk_size = read_u32(data);        // from attacker input
size_t total = chunk_size * sizeof(item);  // ← multiplication may overflow
void *buf = malloc(total);                 // ← allocates a tiny buffer
memcpy(buf, data + offset, total);         // ← OOB write if overflow occurred

// WHAT TO LOOK FOR: any arithmetic (*, +, <<) on user-controlled values
// before a malloc/alloca/memcpy without overflow checks.


// Pattern 2: Off-by-one in boundary check
// ────────────────────────────────────────
// The check uses < instead of <=, or the off-by-one is in the size itself.

if (offset < BUFFER_SIZE) {       // allows offset == BUFFER_SIZE - 1
    buf[offset] = value;          // writes within bounds
}

// vs the dangerous variant:
if (offset <= BUFFER_SIZE) {      // BUG: allows offset == BUFFER_SIZE
    buf[offset] = value;          // OOB write by one byte
}


// Pattern 3: Length from header not re-validated against available data
// ──────────────────────────────────────────────────────────────────────
// The file contains a "claimed_length" field.
// The code trusts this field without checking that claimed_length bytes
// are actually available in the buffer.

uint32_t claimed_length = be32(hdr->length);  // from file header
memcpy(dst, src, claimed_length);             // BUG: if claimed_length > (src_end - src)
```

---

## Key Takeaways

1. **Entry point to sink is the attack chain.** Every audit starts at the
   same place: where does attacker-controlled data enter the program? Every
   audit ends at the same place: what dangerous operation does it reach?
   Everything in between is the chain you are mapping.
2. **Read the data path, not the feature path.** Junior auditors read code
   to understand what it does. Senior auditors read code to understand what
   happens when the data is wrong. Those are different reads of the same
   function.
3. **Fuzzing and manual review are complementary.** The fuzzer finds paths
   you would never manually trace. Manual review finds bugs the fuzzer would
   never generate the right input to trigger. Run both simultaneously. Let
   the fuzzer crash while you read.
4. **The audit function list is your accountability system.** Without it,
   you will spend five days reading interesting code and not finding bugs.
   With it, you will spend five days auditing high-risk functions and find
   at least one. Write the list; work the list.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q667.1, Q667.2 …).

---

## Navigation

← Previous: [Day 666 — Open-Source Audit Campaign Start](DAY-0666-Open-Source-Audit-Campaign-Start.md)
→ Next: [Day 668 — Audit Campaign Day 3: Deep Manual Audit and Fuzzer Triage](DAY-0668-Audit-Campaign-Deep-Manual-Audit.md)
