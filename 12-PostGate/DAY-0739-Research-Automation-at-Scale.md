---
title: "Day 739 — Vulnerability Research Automation at Scale"
tags: [research-automation, vuln-research, pipeline, nuclei, osv-scanner,
  codeql, ci-security, batch-fuzzing, module-12-post-gate]
module: 12-PostGate
day: 739
prerequisites:
  - Day 738 — Threat Intelligence Programme
  - Day 691 — libFuzzer Harness Engineering
  - Day 687 — CodeQL Taint Analysis
related_topics:
  - Day 740 — Milestone 740: Post-Gate Retrospective
---

# Day 739 — Vulnerability Research Automation at Scale

> "The difference between a researcher who finds one bug a month and a
> researcher who finds ten is usually not talent — it is automation.
> The good researcher built a pipeline that runs while they sleep. The great
> researcher built a pipeline that flags interesting findings and lets them
> focus their human judgment on the 5% that matters."
>
> — Ghost

---

## Goals

1. Design a complete automated vulnerability research pipeline for C/C++ open
   source software.
2. Build a batch CodeQL analysis workflow that runs across multiple repositories.
3. Integrate fuzzing campaigns (AFL++ persistent mode) into a CI-like
   orchestration system.
4. Understand OSV (Open Source Vulnerabilities) database as a research signal.
5. Build a triage workflow that filters automated findings to human-reviewable
   candidates.

---

## Prerequisites

- Days 687 (CodeQL), 691 (libFuzzer), 686 (AFL++ persistent mode).
- Python 3.10+, Docker, GitHub CLI.

---

## 1 — The Automated Research Pipeline

```
AUTOMATED VULNERABILITY RESEARCH PIPELINE

Input: a set of target repositories (URLs)

STAGE 1 — INTAKE:
  Clone repo + extract metadata (stars, language, last commit, open issues)
  Check OSV database: is this repo the source of any known CVEs?
  Priority scoring: file count, C/C++ ratio, input-parsing functions detected

STAGE 2 — STATIC ANALYSIS:
  Build CodeQL database
  Run taint-analysis queries (custom + community packs)
  Run Semgrep with vuln-specific rulesets
  Deduplicate alerts: same file+line from multiple tools = higher signal

STAGE 3 — BUILD AND INSTRUMENT:
  Attempt ASan + coverage build
  Generate seed corpus from existing test files + structured mutations
  Start AFL++ campaign (persistent mode if harness exists)

STAGE 4 — TRIAGE:
  Crash deduplication: group by stack trace hash
  ASan report parsing: classify by bug type (heap OOB, stack OOB, UAF)
  Filter: remove crashes from known-bad patterns (null dereference from NULL input)

STAGE 5 — HUMAN REVIEW QUEUE:
  Top 10 candidates by: crash reproducibility × CVSS estimator × novelty score
  Analyst reviews: confirm taint path, assess exploitability
  → Confirmed: PoC, advisory, disclosure
  → Suspicious: deeper manual audit
  → False positive: add to suppression list
```

---

## 2 — Batch CodeQL Analysis

```python
#!/usr/bin/env python3
# batch_codeql.py — Run CodeQL across a list of C/C++ repositories

import subprocess, os, json
from pathlib import Path

TARGETS = [
    "https://github.com/libpng/libpng",
    "https://github.com/madler/zlib",
    "https://github.com/libjpeg-turbo/libjpeg-turbo",
]

CODEQL_CLI = "/opt/codeql/codeql"
QUERY_PACK  = "codeql/cpp-queries:Security"    # official security queries
OUTPUT_DIR  = Path("/tmp/codeql-results")
OUTPUT_DIR.mkdir(exist_ok=True)

CUSTOM_QUERIES = Path("./queries/")            # our custom queries (Day 687)

def run(cmd, **kwargs):
    result = subprocess.run(cmd, shell=True, capture_output=True,
                            text=True, **kwargs)
    return result

def analyse_repo(url):
    name = url.split("/")[-1]
    work_dir = OUTPUT_DIR / name
    work_dir.mkdir(exist_ok=True)

    print(f"\n[*] Analysing: {name}")

    # Clone
    run(f"git clone --depth=1 {url} {work_dir}/src")

    # Build CodeQL database
    db_path = work_dir / "codeql-db"
    r = run(
        f"{CODEQL_CLI} database create {db_path} "
        f"--language=cpp "
        f"--source-root={work_dir}/src "
        f"--command='cmake -B build -S . && make -C build -j4' "
        f"--overwrite",
        cwd=str(work_dir / "src")
    )
    if r.returncode != 0:
        print(f"  [-] Build failed: {r.stderr[:200]}")
        return None

    # Run security queries
    results_file = work_dir / "results.sarif"
    run(
        f"{CODEQL_CLI} database analyze {db_path} "
        f"{QUERY_PACK} "
        f"--format=sarif-latest "
        f"--output={results_file}"
    )

    # Run custom queries
    if CUSTOM_QUERIES.exists():
        custom_results = work_dir / "custom_results.sarif"
        run(
            f"{CODEQL_CLI} database analyze {db_path} "
            f"{CUSTOM_QUERIES} "
            f"--format=sarif-latest "
            f"--output={custom_results}"
        )

    # Parse results
    findings = parse_sarif(results_file)
    print(f"  [+] Found {len(findings)} static analysis alerts")
    return findings

def parse_sarif(sarif_path):
    """Extract findings from SARIF format."""
    if not sarif_path.exists():
        return []
    with open(sarif_path) as f:
        sarif = json.load(f)
    findings = []
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            location = (result.get("locations") or [{}])[0]
            uri = location.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
            line = location.get("physicalLocation", {}).get("region", {}).get("startLine", 0)
            findings.append({
                "rule": result.get("ruleId"),
                "level": result.get("level"),
                "message": result.get("message", {}).get("text", ""),
                "file": uri,
                "line": line,
            })
    return findings

def score_finding(finding):
    """Priority score for manual review."""
    score = 0
    high_value_rules = {
        "cpp/path-injection": 9,
        "cpp/unsafe-use-of-this": 7,
        "cpp/incorrect-string-type-conversion": 6,
        "cpp/integer-overflow-tainted": 10,
        "cpp/tainted-format-string": 9,
        "cpp/memory-may-not-be-freed": 5,
    }
    score += high_value_rules.get(finding.get("rule"), 3)
    if finding.get("level") == "error":
        score += 2
    return score

if __name__ == "__main__":
    all_findings = []
    for url in TARGETS:
        findings = analyse_repo(url)
        if findings:
            for f in findings:
                f["repo"] = url.split("/")[-1]
                f["score"] = score_finding(f)
            all_findings.extend(findings)

    # Sort by priority score
    all_findings.sort(key=lambda x: x["score"], reverse=True)

    print("\n=== TOP 20 REVIEW CANDIDATES ===")
    for f in all_findings[:20]:
        print(f"[{f['score']}] {f['repo']} — {f['rule']}")
        print(f"     {f['file']}:{f['line']}")
        print(f"     {f['message'][:100]}")
        print()
```

---

## 3 — Parallel AFL++ Campaign Orchestrator

```bash
#!/usr/bin/env bash
# fuzz_campaign.sh — Launch parallel AFL++ campaigns for multiple targets

TARGETS=(
    "libpng:libpng_read_fuzzer"
    "zlib:zlib_uncompress_fuzzer"
    "libjpeg:tjunittest"
)

TIMEOUT_HOURS=24
OUTPUT_BASE="/tmp/afl-campaigns"
PARALLEL_INSTANCES=4   # per target (1 primary + 3 secondary)

mkdir -p "$OUTPUT_BASE"

for entry in "${TARGETS[@]}"; do
    IFS=':' read -r target harness <<< "$entry"
    OUT="$OUTPUT_BASE/$target"
    mkdir -p "$OUT"

    echo "[*] Starting campaign for: $target"

    # Primary fuzzer (master)
    AFL_SKIP_CPUFREQ=1 AFL_TMPDIR=/tmp \
    afl-fuzz \
        -i "corpora/$target/" \
        -o "$OUT" \
        -M "master" \
        -t 5000 \
        -- "./builds/$target/$harness" @@ \
    > "$OUT/master.log" 2>&1 &

    # Secondary fuzzers (slaves) — different mutation strategies
    for i in $(seq 1 $((PARALLEL_INSTANCES - 1))); do
        AFL_SKIP_CPUFREQ=1 AFL_TMPDIR=/tmp \
        afl-fuzz \
            -i "corpora/$target/" \
            -o "$OUT" \
            -S "slave_$i" \
            -t 5000 \
            -- "./builds/$target/$harness" @@ \
        > "$OUT/slave_$i.log" 2>&1 &
    done

    echo "  [+] Campaign started: PID group $(pgrep -f $harness)"
done

# Monitor all campaigns
watch -n 30 'afl-whatsup /tmp/afl-campaigns/*/; \
             find /tmp/afl-campaigns -name "crashes" -exec ls -la {} \;'
```

---

## 4 — Using the OSV Database as a Research Signal

The Open Source Vulnerabilities (OSV) database is a machine-readable database
of known vulnerabilities in open source packages.

```python
#!/usr/bin/env python3
# osv_signal.py — Use OSV to find recently patched packages worth auditing

import requests

OSV_API = "https://api.osv.dev/v1"

def query_package_vulns(package, ecosystem="PyPI"):
    """Get all CVEs for a package."""
    r = requests.post(f"{OSV_API}/query", json={
        "package": {"name": package, "ecosystem": ecosystem}
    })
    return r.json().get("vulns", [])

def find_variant_targets(cve_id):
    """
    Given a CVE ID, find:
    1. Which package it affected
    2. Which related packages might have the same pattern
    """
    r = requests.get(f"{OSV_API}/vulns/{cve_id}")
    vuln = r.json()

    print(f"\n=== {cve_id}: {vuln.get('summary', '')}")
    print(f"  Severity: {vuln.get('database_specific', {}).get('severity')}")

    affected = vuln.get("affected", [])
    for pkg_info in affected:
        pkg = pkg_info.get("package", {})
        print(f"  Package: {pkg.get('name')} ({pkg.get('ecosystem')})")

        # The fixed version is interesting — what changed?
        versions = pkg_info.get("ranges", [])
        for v_range in versions:
            for event in v_range.get("events", []):
                if "fixed" in event:
                    print(f"  Fixed in: {event['fixed']}")

    # Variant research: what similar packages exist?
    refs = vuln.get("references", [])
    patch_urls = [r["url"] for r in refs if r.get("type") == "FIX"]
    print(f"  Patch URLs: {patch_urls}")
    print("  → Apply variant analysis: search similar packages for same pattern")

# Research workflow:
# 1. Find recently fixed CVEs in packages you use:
recent_vulns = requests.post(f"{OSV_API}/query", json={
    "package": {"name": "pillow", "ecosystem": "PyPI"}
}).json().get("vulns", [])

for v in recent_vulns[:5]:
    print(f"  {v['id']}: {v.get('summary', '')[:80]}")

# 2. Use variant analysis on the patch:
find_variant_targets("OSV-2023-1234")   # replace with a real CVE ID
```

---

## 5 — Triage Automation: Crash Classifier

```python
#!/usr/bin/env python3
# crash_classifier.py — Parse AFL++ crashes and classify by ASan output

import os, re
from pathlib import Path
from collections import defaultdict

CRASH_DIR = Path("/tmp/afl-campaigns")
BINARY = "./builds/target/harness"

def run_asan(crash_file):
    """Run the binary with ASan output on a crash input."""
    import subprocess
    env = {**os.environ, "ASAN_OPTIONS": "log_path=/tmp/asan_log"}
    r = subprocess.run([BINARY, str(crash_file)], env=env,
                       capture_output=True, timeout=10)
    log_file = Path("/tmp/asan_log")
    log = ""
    for f in Path("/tmp").glob("asan_log.*"):
        log = f.read_text()
        f.unlink()
        break
    return log

def classify_crash(asan_output):
    """Extract bug type and call stack fingerprint."""
    bug_type = "UNKNOWN"
    for bug in ["heap-buffer-overflow", "stack-buffer-overflow", "use-after-free",
                "heap-use-after-free", "SEGV", "double-free", "null-dereference",
                "global-buffer-overflow", "integer-overflow"]:
        if bug in asan_output:
            bug_type = bug
            break

    # Extract top 3 stack frames for deduplication
    frames = re.findall(r'#\d+ .+? in (\w+)', asan_output)
    fingerprint = tuple(frames[:3])

    return bug_type, fingerprint

def deduplicate_and_rank(crash_dir):
    seen = defaultdict(list)
    for crash_file in Path(crash_dir).rglob("crashes/id:*"):
        try:
            asan_out = run_asan(crash_file)
            if not asan_out:
                continue
            bug_type, fingerprint = classify_crash(asan_out)
            seen[fingerprint].append({
                "file": str(crash_file),
                "type": bug_type,
                "asan": asan_out[:500]
            })
        except Exception as e:
            pass

    # Sort by bug type severity
    priority = {
        "heap-buffer-overflow": 9, "use-after-free": 9,
        "heap-use-after-free": 9, "double-free": 8,
        "stack-buffer-overflow": 7, "global-buffer-overflow": 7,
        "integer-overflow": 5, "null-dereference": 2, "SEGV": 2, "UNKNOWN": 1
    }
    ranked = sorted(seen.items(),
                    key=lambda x: priority.get(x[1][0]["type"], 1), reverse=True)

    print(f"Total unique crash signatures: {len(seen)}")
    print("\n=== TOP CANDIDATES ===")
    for fingerprint, crashes in ranked[:10]:
        first = crashes[0]
        print(f"[{priority.get(first['type'], 1)}/9] {first['type']}")
        print(f"  Deduplicated count: {len(crashes)}")
        print(f"  Stack: {' → '.join(fingerprint)}")
        print(f"  Sample: {first['file']}")
        print()

if __name__ == "__main__":
    deduplicate_and_rank(CRASH_DIR)
```

---

## Key Takeaways

1. **Automation is a force multiplier, not a replacement for human judgment.**
   The pipeline finds candidates at machine scale. The researcher still
   confirms exploitability, assesses impact, and writes the advisory. Automation
   does the broad sweep; human expertise does the deep validation.
2. **Batch CodeQL analysis across related repositories is a high-return
   strategy.** If a parsing library has a bug class, libraries that import it
   or implement the same pattern may have the same bug. Running one query
   across 20 related repos costs the same compute time as running it once.
3. **Crash deduplication is as important as crash generation.** An AFL++
   campaign that produces 10,000 crashes may contain 50 unique bug signatures.
   Without deduplication, analysts spend 95% of their time re-examining the
   same bug. The classifier script above reduces a day's work to an hour.
4. **OSV is an underused research signal.** For every package with a recent
   CVE, there is a specific code pattern that was fixed. That pattern may exist
   in dozens of similar libraries. Systematic variant analysis via the OSV API
   is a structured approach to finding original CVEs from known fixes.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q739.1, Q739.2 …).

---

## Navigation

← Previous: [Day 738 — Threat Intelligence Programme](DAY-0738-Threat-Intelligence-Programme.md)
→ Next: [Day 740 — Milestone 740: Post-Gate Retrospective](DAY-0740-Milestone-740-PostGate-Retrospective.md)
