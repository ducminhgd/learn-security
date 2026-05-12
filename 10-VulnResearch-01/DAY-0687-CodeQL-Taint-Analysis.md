---
title: "CodeQL Taint Analysis — Writing Queries for Vulnerability Discovery"
tags: [codeql, taint-analysis, static-analysis, vulnerability-research, sast,
  module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 687
prerequisites:
  - Day 660 — Static Analysis: Semgrep and CodeQL
  - Day 667 — Audit Campaign: Codebase Navigation
related_topics:
  - Day 692 — Variant Analysis
  - Day 700 — Module 10 Competency Check
---

# Day 687 — CodeQL Taint Analysis: Writing Queries for Vulnerability Discovery

> "Semgrep finds patterns. CodeQL finds data flow. Those are not the same
> thing. A Semgrep rule that matches `strcpy(dst, src)` will fire on safe
> calls where `src` is a literal. A CodeQL taint query follows the value
> from its source all the way to the sink — through assignments, function
> calls, casts, struct fields. That is what makes it a weapon for serious
> source audit work."
>
> — Ghost

---

## Goals

Write CodeQL taint-tracking queries from scratch for C/C++. Track untrusted
user data from network/file sources to dangerous sinks (`memcpy`, `malloc`,
`strcpy`, `printf`). Run queries against a real open-source project. Use
results to prioritise the manual audit list.

**Prerequisites:** Days 660, 667.
**Estimated study time:** 4 hours.

---

## 1 — CodeQL Architecture Refresher

CodeQL works in two phases:

```
Phase 1: Database creation
  codeql database create <db> --language=cpp --command="make"

Phase 2: Query execution
  codeql query run <query.ql> --database=<db> --output=<results.bqrs>
  codeql bqrs decode --format=csv <results.bqrs>
```

The database is a snapshot of the codebase's AST, CFG, and data-flow graph.
Queries are written in QL — a declarative logic language. The key advantage
over grep: CodeQL understands code structure, not just text.

---

## 2 — The Three Query Types

| Type | What it finds | Use case |
|---|---|---|
| **Local data flow** | Flow within a single function | Fast; misses inter-procedural flow |
| **Global taint tracking** | Flow across function calls | Finds bugs Semgrep misses |
| **Path queries** | Full source-to-sink path with explanation | Report generation |

---

## 3 — Building a Taint Query: Step by Step

### 3.1 Define Sources (where untrusted data enters)

```ql
/**
 * @name Sources of untrusted data in C
 * @kind problem
 * @id cpp/untrusted-sources
 */
import cpp
import semmle.code.cpp.dataflow.TaintTracking

/* Sources: network read, file read, argv, getenv */
class UntrustedSource extends DataFlow::Node {
  UntrustedSource() {
    exists(FunctionCall fc |
      fc.getTarget().hasName(["read", "recv", "fread", "fgets",
                              "getenv", "gets"]) and
      this.asExpr() = fc
    )
    or
    /* argv[N] */
    exists(VariableAccess va |
      va.getTarget().hasName("argv") and
      this.asExpr() = va
    )
  }
}
```

### 3.2 Define Sinks (where dangerous operations happen)

```ql
/* Sinks: memory operations that can overflow */
class MemorySink extends DataFlow::Node {
  MemorySink() {
    exists(FunctionCall fc |
      fc.getTarget().hasName(["memcpy", "memmove", "strcpy",
                              "strcat", "sprintf", "malloc",
                              "alloca", "realloc"]) and
      (
        /* memcpy/memmove: size argument (arg 2) is the sink */
        (fc.getTarget().hasName(["memcpy", "memmove"]) and
         this.asExpr() = fc.getArgument(2))
        or
        /* strcpy/strcat: src argument (arg 1) is the sink */
        (fc.getTarget().hasName(["strcpy", "strcat"]) and
         this.asExpr() = fc.getArgument(1))
        or
        /* malloc/alloca/realloc: size argument is the sink */
        (fc.getTarget().hasName(["malloc", "alloca", "realloc"]) and
         this.asExpr() = fc.getArgument(0))
        or
        /* sprintf: format string (arg 1) is the sink */
        (fc.getTarget().hasName("sprintf") and
         this.asExpr() = fc.getArgument(1))
      )
    )
  }
}
```

### 3.3 Wire Together as a Taint-Tracking Configuration

```ql
/**
 * @name Untrusted data flows to memory operation
 * @description User-controlled data reaches a size or destination
 *              parameter of a memory operation without sanitisation.
 * @kind path-problem
 * @problem.severity warning
 * @id cpp/taint-to-memory-op
 */
import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

class TaintConfig extends TaintTracking::Configuration {
  TaintConfig() { this = "UntrustedToMemoryOp" }

  override predicate isSource(DataFlow::Node node) {
    node instanceof UntrustedSource
  }

  override predicate isSink(DataFlow::Node node) {
    node instanceof MemorySink
  }

  /* Optional: exclude sanitisers (bounds checks, clamping) */
  override predicate isSanitizer(DataFlow::Node node) {
    /* If a value has been compared with a size constant, consider it sanitised.
       This is a simplification — refine based on the target codebase. */
    exists(RelationalOperation ro |
      ro.getAnOperand() = node.asExpr()
    )
  }
}

from TaintConfig config, DataFlow::PathNode src, DataFlow::PathNode sink
where config.hasFlowPath(src, sink)
select sink.getNode(), src, sink,
  "Untrusted data from $@ flows to memory operation",
  src.getNode(), "this source"
```

### 3.4 Running the Query

```bash
# 1. Create a CodeQL database for your target project
codeql database create myproject_db \
    --language=cpp \
    --command="make -j4" \
    --source-root=/path/to/project

# 2. Run the taint query
codeql query run taint_to_memory.ql \
    --database=myproject_db \
    --output=results.bqrs

# 3. Decode results to CSV
codeql bqrs decode --format=csv results.bqrs > results.csv

# 4. Or use sarif for IDE integration
codeql query run taint_to_memory.ql \
    --database=myproject_db \
    --format=sarif-latest \
    --output=results.sarif
```

---

## 4 — Intermediate Technique: Tracking Through Struct Fields

CodeQL's default taint tracking handles local variables. For data that flows
through struct fields, you need to extend the taint tracking configuration:

```ql
class TaintConfigStructAware extends TaintTracking::Configuration {
  TaintConfigStructAware() { this = "StructAwareTaint" }

  override predicate isSource(DataFlow::Node node) {
    node instanceof UntrustedSource
  }

  override predicate isSink(DataFlow::Node node) {
    node instanceof MemorySink
  }

  /* Propagate taint through struct field writes and reads */
  override predicate isAdditionalTaintStep(
    DataFlow::Node src, DataFlow::Node dst
  ) {
    /* struct field assignment: if tainted value is assigned to a field,
       reading that field is also tainted */
    exists(FieldAccess fa, AssignExpr ae |
      ae.getLValue() = fa and
      ae.getRValue() = src.asExpr() and
      dst.asExpr() = fa
    )
    or
    /* Arithmetic on tainted value propagates taint */
    exists(ArithmeticOperation op |
      op.getAnOperand() = src.asExpr() and
      dst.asExpr() = op
    )
  }
}
```

---

## 5 — Practical Query: Integer Overflow Before Malloc

This pattern is responsible for a large fraction of heap buffer overflows. It
specifically targets: `n = user_value; buf = malloc(n * 4)` where `n * 4`
overflows.

```ql
/**
 * @name Integer overflow before malloc
 * @kind path-problem
 * @id cpp/int-overflow-before-malloc
 */
import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

class MultiplyConfig extends TaintTracking::Configuration {
  MultiplyConfig() { this = "IntOverflowMalloc" }

  override predicate isSource(DataFlow::Node node) {
    /* source: user-controlled value from read/recv/fread */
    exists(FunctionCall fc |
      fc.getTarget().hasName(["read", "recv", "fread", "fgets"]) and
      node.asExpr() = fc.getArgument(1)   /* buffer argument = filled by call */
    )
    or
    exists(VariableAccess va |
      va.getTarget().hasName("argv") and
      node.asExpr() = va
    )
  }

  override predicate isSink(DataFlow::Node node) {
    /* sink: argument to malloc that involves multiplication */
    exists(FunctionCall fc, MulExpr mult |
      fc.getTarget().hasName(["malloc", "calloc", "realloc"]) and
      fc.getArgument(0) = mult and
      (mult.getLeftOperand() = node.asExpr() or
       mult.getRightOperand() = node.asExpr())
    )
  }
}

from MultiplyConfig cfg, DataFlow::PathNode src, DataFlow::PathNode sink
where cfg.hasFlowPath(src, sink)
select sink.getNode(), src, sink,
  "User-controlled value $@ used in multiplication before malloc — potential integer overflow",
  src.getNode(), "source"
```

---

## 6 — Lab Exercise

**Target:** Choose an open-source C project with network or file input parsing
(suggestions: `libtiff`, `libxml2`, `nasm`, `musl libc`).

```
CODEQL TAINT ANALYSIS LAB

Target project: _______________________________
Build system: make / cmake / autotools
Database creation command: ____________________
Database size: _______ MB

QUERY 1 — General taint to memory op:
  Results: _______ findings
  False positive rate (estimated): _______%
  Top 3 real candidates:
    1. ___________________________________________________
    2. ___________________________________________________
    3. ___________________________________________________

QUERY 2 — Integer overflow before malloc:
  Results: _______ findings
  Real candidates: ______
  Most interesting: ____________________________________

CROSS-CHECK WITH SEMGREP:
  Semgrep findings: _______
  CodeQL findings not found by Semgrep: _______
  Semgrep findings not found by CodeQL: _______
  Insight: ____________________________________________

MANUAL FOLLOW-UP (top candidate):
  File: _________________________ Line: _______
  Taint path:
    Source: _____________________________________________
    → ___________________________________________________
    → ___________________________________________________
    Sink: _______________________________________________
  Exploitable? Y / N / Unknown
  Notes: ______________________________________________
```

---

## Key Takeaways

1. **CodeQL taint tracking is inter-procedural.** A tainted value that flows
   through three function calls and into a struct field is still found. Semgrep
   sees none of that — it only matches at the line level.
2. **The `isSanitizer` predicate is where false positives die.** Every bounds
   check, clamping operation, or validation function you model as a sanitiser
   removes a false positive from the output. Invest time in this predicate for
   long-running audit campaigns.
3. **CodeQL and fuzzing are complementary, not competing.** CodeQL finds the
   path. The fuzzer confirms whether it is reachable and exploitable. Combine
   them: use CodeQL to generate target inputs for the fuzzer.
4. **Building the database is the hard part.** If `make` fails, the database
   is incomplete. Use `codeql database trace-command` to diagnose build
   failures. On projects that use non-standard build systems, this is where
   most CodeQL setup time is spent.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q687.1, Q687.2 …).

---

## Navigation

← Previous: [Day 686 — AFL++ Advanced: Persistent Mode and Custom Mutators](DAY-0686-AFL-Advanced-Persistent-Mode.md)
→ Next: [Day 688 — Heap Exploitation from the Vulnerability Researcher's Perspective](DAY-0688-Heap-Exploitation-Researcher-Perspective.md)
