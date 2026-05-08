---
title: "Static Analysis with Semgrep and CodeQL — Automated Vulnerability Discovery"
tags: [vulnerability-research, static-analysis, Semgrep, CodeQL, SAST,
  dataflow-analysis, taint-tracking, module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 660
prerequisites:
  - Day 651 — Source Code Auditing
  - Day 659 — Writing a Security Advisory
related_topics:
  - Advanced Fuzzing Sprint (Day 661)
  - Bug Class Deep Dive — Integer Overflow (Day 662)
---

# Day 660 — Static Analysis with Semgrep and CodeQL

> "Manual code review finds the bugs you know to look for. Automated static
> analysis finds the bugs you forgot to look for — the same pattern repeated
> forty-seven times across eight files you didn't bother to open. You are not
> replacing the auditor with a tool. You are using the tool to make the auditor
> more efficient: let the machine find the candidates, let the human confirm the
> real findings."
>
> — Ghost

---

## Goals

Understand the difference between pattern-matching SAST (Semgrep) and
dataflow/taint-tracking SAST (CodeQL). Write Semgrep rules to detect
vulnerability classes. Run CodeQL on a C/Python/JavaScript project. Interpret
and triage static analysis output. Integrate SAST into an audit workflow.

**Prerequisites:** Days 651, 659.
**Estimated study time:** 4 hours.

---

## Why Two Different Tools

```
SAST TOOL COMPARISON
═══════════════════════════════════════════════════════════════════════

SEMGREP — Pattern-Matching SAST
  Model: AST-level pattern matching (not just text grep)
  Speed: Fast (seconds to minutes on large codebases)
  Strength: Finding known bad patterns — unsafe functions, missing checks
  Weakness: Cannot track data flow across function calls (false positives)
  Best for:
    • Detecting dangerous API calls (strcpy, system(), eval())
    • Enforcing coding standards (no hardcoded secrets)
    • Quick triage of large unfamiliar codebases
    • CI/CD integration for "did the dev introduce a new unsafe pattern?"

CODEQL — Dataflow / Taint Tracking SAST
  Model: Database of code facts + Datalog query language
  Speed: Slow (minutes to hours; builds a semantic model first)
  Strength: Tracks tainted data from attacker-controlled source to sink
  Weakness: Requires language support; setup is heavier
  Best for:
    • Finding injection vulnerabilities (SQLi, command injection)
    • Tracking user input through complex call chains
    • Confirming whether a Semgrep candidate is actually reachable
    • Auditing unknown codebases for entire vulnerability classes

WORKFLOW:
  Semgrep first → flag suspicious patterns → CodeQL confirms taint path
```

---

## Stage 1 — Semgrep Rule Writing

```yaml
# semgrep_rules/dangerous_c.yaml
# Detect dangerous C standard library calls that commonly lead to CVEs.

rules:
  - id: strcpy-unsafe
    patterns:
      - pattern: strcpy($DST, $SRC)
    message: |
      strcpy() copies without bounds checking. Use strncpy() + null termination,
      or strlcpy() if available. CWE-121 (Stack Buffer Overflow).
    languages: [c, cpp]
    severity: ERROR
    metadata:
      cwe: CWE-121
      owasp: A03:2021 - Injection

  - id: sprintf-unsafe
    patterns:
      - pattern: sprintf($BUF, $FMT, ...)
    message: |
      sprintf() can overflow BUF if the formatted string exceeds its size.
      Use snprintf($BUF, sizeof($BUF), $FMT, ...) instead. CWE-121.
    languages: [c, cpp]
    severity: ERROR
    metadata:
      cwe: CWE-121

  - id: printf-format-string
    patterns:
      - pattern: printf($USER_INPUT)
    message: |
      Passing user-controlled input directly as printf format string.
      CWE-134 (Format String). Use printf("%s", $USER_INPUT) instead.
    languages: [c, cpp]
    severity: ERROR
    metadata:
      cwe: CWE-134

  - id: gets-unsafe
    patterns:
      - pattern: gets($BUF)
    message: |
      gets() is removed from C11 — it cannot limit input length. Replace
      with fgets($BUF, sizeof($BUF), stdin). CWE-121.
    languages: [c, cpp]
    severity: ERROR

  - id: integer-cast-to-smaller-type
    patterns:
      - pattern: (uint8_t)$EXPR
      - pattern: (char)$EXPR
    message: |
      Casting to a smaller integer type — potential truncation if $EXPR
      holds a value > 255. Verify bounds before cast. CWE-190.
    languages: [c, cpp]
    severity: WARNING
    metadata:
      cwe: CWE-190
```

```yaml
# semgrep_rules/python_security.yaml
# Detect common Python security anti-patterns.

rules:
  - id: python-command-injection
    patterns:
      - pattern: os.system($INPUT)
      - pattern: subprocess.call($INPUT, shell=True)
      - pattern: subprocess.Popen($INPUT, shell=True)
    message: |
      Passing user input to shell=True creates command injection risk. CWE-78.
      Use subprocess.run([cmd, arg1, arg2], shell=False) with a list instead.
    languages: [python]
    severity: ERROR
    metadata:
      cwe: CWE-78

  - id: python-eval-injection
    pattern: eval($INPUT)
    message: |
      eval() with any non-literal input allows code execution. CWE-95.
      If deserializing data, use ast.literal_eval() for safe literals, or
      a purpose-built parser.
    languages: [python]
    severity: ERROR
    metadata:
      cwe: CWE-95

  - id: python-sql-fstring
    patterns:
      - pattern: cursor.execute(f"... {$VAR} ...")
      - pattern: cursor.execute("..." + $VAR + "...")
      - pattern: cursor.execute("..." % $VAR)
    message: |
      SQL query constructed with string formatting — SQL injection risk. CWE-89.
      Use parameterised queries: cursor.execute("SELECT ... WHERE x = %s", (val,))
    languages: [python]
    severity: ERROR
    metadata:
      cwe: CWE-89

  - id: python-pickle-load
    patterns:
      - pattern: pickle.loads($DATA)
      - pattern: pickle.load($FILE)
    message: |
      pickle.loads() on untrusted data allows arbitrary code execution. CWE-502.
      Use JSON or a safe serialisation format for untrusted data.
    languages: [python]
    severity: ERROR
    metadata:
      cwe: CWE-502

  - id: python-weak-hash
    patterns:
      - pattern: hashlib.md5($DATA)
      - pattern: hashlib.sha1($DATA)
    message: |
      MD5 and SHA-1 are cryptographically broken for security uses (collision
      attacks). Use hashlib.sha256() or hashlib.sha3_256(). CWE-327.
    languages: [python]
    severity: WARNING
    metadata:
      cwe: CWE-327
```

```bash
# Running Semgrep on a target codebase:

# Install:
pip install semgrep

# Run built-in rulesets (fast, broad coverage):
semgrep --config=auto /path/to/target/

# Run specific rule file:
semgrep --config=semgrep_rules/dangerous_c.yaml /path/to/target/

# Run with JSON output for scripting:
semgrep --config=auto --json /path/to/target/ | jq '.results[] | .check_id, .path'

# Run official security rulesets:
semgrep --config=p/owasp-top-ten /path/to/target/
semgrep --config=p/c /path/to/target/
semgrep --config=p/python /path/to/target/

# Filter to only high-severity findings:
semgrep --config=auto --severity=ERROR /path/to/target/
```

---

## Stage 2 — CodeQL for Taint Tracking

CodeQL builds a semantic model of the code and lets you query it. The key
concept: **taint tracking** — marking user input as "tainted" and following it
to dangerous sinks.

```python
#!/usr/bin/env python3
"""
CodeQL workflow guide — database creation and querying.
"""
from __future__ import annotations

CODEQL_WORKFLOW = {
    "step_1_install": {
        "description": "Install CodeQL CLI",
        "commands": [
            "# Download from: github.com/github/codeql-action/releases",
            "# Extract and add to PATH:",
            "export PATH=$PATH:/opt/codeql",
            "codeql --version",
        ],
    },
    "step_2_create_database": {
        "description": "Build a CodeQL database from the target project",
        "c_cpp": [
            "codeql database create /tmp/codeql-db \\",
            "    --language=cpp \\",
            "    --command='make -C /path/to/target clean all'",
        ],
        "python": [
            "# Python: no compile step needed",
            "codeql database create /tmp/codeql-db \\",
            "    --language=python \\",
            "    --source-root=/path/to/target",
        ],
        "javascript": [
            "codeql database create /tmp/codeql-db \\",
            "    --language=javascript \\",
            "    --source-root=/path/to/target",
        ],
    },
    "step_3_run_queries": {
        "description": "Run built-in security queries",
        "commands": [
            "# Run all built-in security queries:",
            "codeql database analyze /tmp/codeql-db \\",
            "    codeql/cpp-queries:codeql-suites/cpp-security-extended.qls \\",
            "    --format=sarif-latest \\",
            "    --output=results.sarif",
            "",
            "# Convert SARIF to readable format:",
            "cat results.sarif | python3 -c \\"",
            "  'import json,sys; [print(r[\"message\"][\"text\"], r[\"locations\"][0])",
            "   for r in json.load(sys.stdin)[\"runs\"][0][\"results\"]]'",
        ],
    },
    "step_4_custom_queries": {
        "description": "Write and run custom CodeQL queries",
        "commands": [
            "# Save query to file: my_query.ql",
            "codeql query run my_query.ql --database=/tmp/codeql-db",
            "# Output: BQRS file — convert to CSV:",
            "codeql bqrs decode --format=csv output.bqrs",
        ],
    },
}

for step, info in CODEQL_WORKFLOW.items():
    print(f"\n[{step.upper()}] {info['description']}")
    for key, cmds in info.items():
        if isinstance(cmds, list) and key != "description":
            print(f"  ({key}):")
            for cmd in cmds[:4]:
                print(f"    {cmd}")
```

```ql
/**
 * @name Command injection via user input
 * @description User-controlled data flows to a shell execution function.
 * @kind path-problem
 * @problem.severity error
 * @id python/command-injection
 * @tags security
 *       external/cwe/cwe-078
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs

/**
 * Sources: HTTP request parameters, form data, environment variables.
 */
class UserInputSource extends DataFlow::Node {
  UserInputSource() {
    // Flask request.args, request.form, request.json
    exists(DataFlow::AttrRead read |
      read.getAttributeName() in ["args", "form", "json", "values", "data"] and
      read.getObject().getALocalSource() = API::moduleImport("flask").getMember("request").getAValueReachableFromSource() and
      this = read
    )
    or
    // os.environ.get()
    exists(DataFlow::CallCfgNode call |
      call.getFunction().(DataFlow::AttrRead).getAttributeName() = "get" and
      call.getFunction().(DataFlow::AttrRead).getObject().getALocalSource() =
        API::moduleImport("os").getMember("environ").getAValueReachableFromSource() and
      this = call
    )
  }
}

/**
 * Sinks: os.system(), subprocess with shell=True, eval().
 */
class ShellExecutionSink extends DataFlow::Node {
  ShellExecutionSink() {
    // os.system(cmd)
    exists(DataFlow::CallCfgNode call |
      call.getFunction().(DataFlow::AttrRead).getAttributeName() = "system" and
      this = call.getArg(0)
    )
    or
    // subprocess.call/run/Popen with shell=True and the command is the sink
    exists(DataFlow::CallCfgNode call |
      call.getFunction().(DataFlow::AttrRead).getAttributeName() in
        ["call", "run", "Popen", "check_output", "check_call"] and
      exists(DataFlow::Node kwarg | kwarg = call.getArgByName("shell") |
        kwarg.asExpr().(BooleanLiteral).booleanValue() = true
      ) and
      this = call.getArg(0)
    )
  }
}

/**
 * Taint tracking configuration: flow from user input to shell execution.
 */
class CommandInjectionConfig extends TaintTracking::Configuration {
  CommandInjectionConfig() { this = "CommandInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof UserInputSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof ShellExecutionSink
  }
}

from CommandInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
    "User-controlled value from $@ flows to shell command execution.",
    source.getNode(), "this user input"
```

---

## Stage 3 — Triaging Static Analysis Output

```python
#!/usr/bin/env python3
"""
Static analysis triage guide — separating real findings from noise.
"""
from __future__ import annotations

TRIAGE_FRAMEWORK = {
    "false_positive_indicators": [
        "Finding is in test code (test/, tests/, *_test.c) — low risk",
        "Input is validated by a function that precedes the sink",
        "The 'dangerous' function is wrapped safely (e.g. safe_strcpy with bound checks)",
        "Data is hardcoded at compile time, not attacker-controlled",
        "Finding is in dead code (guarded by #ifdef UNUSED or never called)",
    ],
    "true_positive_indicators": [
        "Source is confirmed external input (HTTP, file, network socket, argv)",
        "No validation or sanitization between source and sink",
        "The code path is reachable without authentication",
        "The sink is a memory operation (memcpy, strcpy) or process launch",
        "Multiple tools agree (Semgrep flags it; CodeQL shows a taint path)",
    ],
    "triage_steps": [
        "1. Read the finding: what function, what file, what line?",
        "2. Read 20 lines above and below the finding in the source",
        "3. Is the input attacker-controlled? (trace it backward)",
        "4. Is there a validation check before the sink? (look above the call)",
        "5. Is the code path actually reachable? (check call graph)",
        "6. Write a PoC: can you trigger the sink with crafted input?",
        "7. If PoC crashes or shows unexpected behaviour: REAL FINDING",
    ],
    "priority_scoring": {
        "Critical": "Remote, unauthenticated, reliable exploit confirmed by PoC",
        "High":     "Remote or auth bypass, taint path confirmed, no PoC yet",
        "Medium":   "Taint path confirmed but requires specific conditions",
        "Low":      "Pattern match only; no confirmed taint path from external input",
        "Info":     "Best practice violation; no security impact in current context",
    },
}

print("[*] STATIC ANALYSIS TRIAGE GUIDE")
print("\nFalse positive indicators:")
for item in TRIAGE_FRAMEWORK["false_positive_indicators"]:
    print(f"  ✗ {item}")

print("\nTrue positive indicators:")
for item in TRIAGE_FRAMEWORK["true_positive_indicators"]:
    print(f"  ✓ {item}")

print("\nTriage steps:")
for step in TRIAGE_FRAMEWORK["triage_steps"]:
    print(f"  {step}")
```

---

## Stage 4 — CI/CD Integration

```yaml
# .github/workflows/sast.yml
# Run Semgrep on every pull request.

name: SAST — Semgrep

on:
  pull_request: {}
  push:
    branches: [main, master]

jobs:
  semgrep:
    name: Semgrep Scan
    runs-on: ubuntu-latest
    container:
      image: semgrep/semgrep

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run Semgrep (OWASP + custom rules)
        run: |
          semgrep \
            --config=p/owasp-top-ten \
            --config=semgrep_rules/ \
            --json \
            --output=semgrep_results.json \
            --error \
            .

      - name: Upload SARIF results to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: semgrep_results.json

      - name: Fail if high-severity findings
        run: |
          HIGH=$(cat semgrep_results.json | python3 -c \
            "import json,sys; results=json.load(sys.stdin)['results']; \
             high=[r for r in results if r.get('extra',{}).get('severity')=='ERROR']; \
             print(len(high))")
          echo "High severity findings: $HIGH"
          [ "$HIGH" -eq "0" ] || exit 1
```

---

## Key Takeaways

1. **Semgrep finds patterns; CodeQL finds flows.** Semgrep will flag every call
   to `strcpy()` in the codebase — fast, but you will spend hours discarding
   calls where the input is bounded. CodeQL tracks whether attacker data actually
   reaches `strcpy()` — slower, but every finding is a candidate taint path. Use
   both: Semgrep to quickly identify risky patterns, CodeQL to confirm which ones
   are reachable.
2. **Static analysis output is a list of candidates, not findings.** Every SAST
   tool produces false positives. The audit workflow is: tool flags → human
   confirms taint path → human writes PoC → PoC confirms exploitability. Skipping
   any step produces either false positives in your report or missed real bugs.
3. **Write custom rules for your target's specific patterns.** Built-in rulesets
   catch common patterns but miss application-specific anti-patterns. If the
   target has a custom wrapper around `malloc()` that is misused throughout the
   codebase, write a Semgrep rule for that specific pattern. Domain-specific rules
   find domain-specific bugs.
4. **CI/CD integration converts SAST from a one-time tool into a continuous
   control.** A Semgrep run in CI on every pull request catches new vulnerable
   patterns before they merge. This is cheaper than a quarterly audit that
   catches the same bugs six months later. The audit finds the existing debt; CI
   prevents new debt from accumulating.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q660.1, Q660.2 …).

---

## Navigation

← Previous: [Day 659 — Writing a Security Advisory](DAY-0659-Writing-Security-Advisory.md)
→ Next: [Day 661 — Advanced Fuzzing: Grammar-Based and Protocol Fuzzing](DAY-0661-Advanced-Fuzzing-Grammar-Protocol.md)
