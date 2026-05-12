---
title: "Network Protocol Fuzzing — Boofuzz and Stateful Protocol Testing"
tags: [vulnerability-research, fuzzing, network-fuzzing, boofuzz, protocol,
  stateful-fuzzing, module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 676
prerequisites:
  - Day 653 — Fuzzing Fundamentals (AFL++, libFuzzer)
  - Day 661 — Advanced Fuzzing: Grammar and Protocol
related_topics:
  - Day 677 — Network Fuzzing Lab (Boofuzz)
  - Day 654 — Fuzzing Lab
---

# Day 676 — Network Protocol Fuzzing: Boofuzz and Stateful Testing

> "File format fuzzing is easy. You hand AFL a binary and let it mutate.
> Network protocol fuzzing is harder because the protocol has state. You
> must authenticate before you can send commands. You must complete
> a handshake before you can crash the parser. The fuzzer needs to
> understand conversation, not just mutation. That is what today is about."
>
> — Ghost

---

## Goals

Understand why network protocol fuzzing is harder than file fuzzing.
Learn the Boofuzz framework: sessions, requests, primitives, callbacks.
Design a stateful fuzzing campaign for a real network service.

**Prerequisites:** Days 653, 661.
**Estimated study time:** 4 hours.

---

## Why Network Protocol Fuzzing Differs

### The State Problem

```
FILE FORMAT FUZZING:
  Input → Binary → Parsed → Crash?
  No state. Each test is independent. AFL mutates and hands the fuzzer
  a file; the target reads it and either crashes or doesn't.

NETWORK PROTOCOL FUZZING:
  Connect → Authenticate → Send Command → Wait for Response → Send Next Command → Crash?
  The target has state. If you skip authentication, the server rejects
  your malformed command packets before they reach the parser.
  The fuzzer must "get to" the vulnerable state before injecting mutations.
```

### The Three Challenges

```
CHALLENGE 1: PROTOCOL KNOWLEDGE
  The fuzzer must send syntactically valid data up to the mutation point.
  A login packet must have the right structure. A binary header must have
  the right magic bytes. Knowing the protocol is prerequisite.

CHALLENGE 2: SESSION MANAGEMENT
  The server may drop the connection after a crash. The fuzzer must:
    - Detect that the target has crashed (response timeout or reset)
    - Restart the target
    - Re-establish the session state
    - Continue from where it left off

CHALLENGE 3: COVERAGE MEASUREMENT
  Traditional coverage feedback (AFL's shared memory bitmap) does not
  work over a network socket. You need either:
    - A code coverage agent on the target side (DRCOV, SanitizerCoverage)
    - Network-side coverage proxy
    - Or accept coverage-blind mutation (dumb fuzzing)
```

---

## Boofuzz: The Python Network Fuzzer

### Architecture

```
BOOFUZZ CONCEPTS

Session: The top-level object. Manages the target connection, message
         ordering, crash detection, and restart logic.

Request: A single protocol message (login packet, command, query).
         Contains primitives that will be mutated.

Primitives: Individual fields within a request:
  s_string("hello")        — mutates a string field
  s_int(1337, endian="<")  — mutates an integer field
  s_bytes(b"\x00\x01")     — mutates raw bytes
  s_static(b"\xff\xfe")    — fixed field (not mutated — for magic bytes, etc.)
  s_size("block", length=2) — auto-calculates length of a named block

Connection Sequence:
  The session sends requests in defined order.
  Pre-send callbacks inject authentication before fuzz messages.
  Post-send callbacks verify the server is still alive.
```

### Installation and Basic Structure

```bash
pip install boofuzz
```

```python
#!/usr/bin/env python3
"""
Boofuzz session template.
Demonstrates the core session/request/primitive structure.
"""
from __future__ import annotations

import time
from boofuzz import (
    Session, Target, TCPSocketConnection,
    Request, Block, String, Static, Bytes, Size, IntegerBlock,
    s_initialize, s_string, s_static, s_int, s_bytes, s_block_start, s_block_end,
)


def craft_fuzz_session(host: str = "127.0.0.1", port: int = 9999) -> Session:
    """
    Build a Boofuzz session targeting a custom binary protocol.

    PROTOCOL ASSUMED:
      Login request:
        [4 bytes magic: 0xDEADBEEF]
        [1 byte type: 0x01 = LOGIN]
        [2 bytes username_len]
        [username_len bytes username]
        [1 byte password_len]
        [password_len bytes password]

      Command request (after auth):
        [4 bytes magic: 0xDEADBEEF]
        [1 byte type: 0x02 = CMD]
        [2 bytes cmd_len]
        [cmd_len bytes command data]
    """
    session = Session(
        target=Target(
            connection=TCPSocketConnection(host, port, timeout=5)
        ),
        sleep_time=0.1,           # pause between test cases
        crash_threshold_request=5,  # restart after 5 consecutive no-responses
        web_port=26000,            # web UI for monitoring progress
    )

    # ── LOGIN REQUEST (not fuzzed — authentication step) ──────────────────
    s_initialize("login")
    s_static(b"\xde\xad\xbe\xef")   # magic — fixed
    s_static(b"\x01")               # type = LOGIN — fixed
    # Username
    s_block_start("username_block")
    s_string("admin", name="username", fuzzable=False)   # auth — not fuzzed
    s_block_end("username_block")
    s_size("username_block", length=2, endian="<", name="username_len", fuzzable=False)
    # Password
    s_static(b"\x05")               # password_len = 5
    s_static(b"admin")              # password

    # ── COMMAND REQUEST (fuzzed — this is where we inject mutations) ──────
    s_initialize("command")
    s_static(b"\xde\xad\xbe\xef")   # magic — fixed
    s_static(b"\x02")               # type = CMD — fixed
    # Command data — THIS IS FUZZED
    s_block_start("cmd_block")
    s_string(
        "ls",
        name="command_data",
        fuzzable=True,              # Boofuzz mutates this field
        max_len=4096,               # bound the mutation size
    )
    s_block_end("cmd_block")
    s_size("cmd_block", length=2, endian="<", name="cmd_len")

    # Define message order: send login, then fuzz command
    session.connect(s_get("login"))
    session.connect(s_get("login"), s_get("command"))

    return session


def pre_send_callback(target, fuzz_data_logger, session, *args, **kwargs):
    """Called before each fuzz request. Used to reset state if needed."""
    pass


def post_send_callback(target, fuzz_data_logger, session, sock):
    """Called after each fuzz request. Verify server is alive."""
    try:
        # Read up to 256 bytes response; if timeout, server may have crashed
        data = sock.recv(256)
        if not data:
            fuzz_data_logger.log_fail("Empty response — possible crash")
    except Exception as exc:
        fuzz_data_logger.log_fail(f"No response: {exc}")


if __name__ == "__main__":
    session = craft_fuzz_session()
    # Register callbacks
    # session.add_pre_send_callback(pre_send_callback)
    # session.add_post_send_callback(post_send_callback)

    print("[*] Starting Boofuzz session...")
    print("[*] Web UI at http://localhost:26000")
    session.fuzz()
```

---

## Stateful Protocol Fuzzing Design

### Mapping the State Machine

Before writing a fuzzer, draw the protocol state machine.

```
PROTOCOL STATE MACHINE EXAMPLE (FTP-like protocol)

State 1: CONNECTED
  → Send: USER <username>\r\n
  → Expect: 331 Password required

State 2: USERNAME_SENT
  → Send: PASS <password>\r\n
  → Expect: 230 Logged in

State 3: AUTHENTICATED (attack surface begins here)
  → Send: LIST\r\n              — fuzzing target: directory listing
  → Send: RETR <filename>\r\n  — fuzzing target: file retrieval
  → Send: STOR <filename>\r\n  — fuzzing target: file upload
  → Send: CWD <path>\r\n       — fuzzing target: path traversal

State 4: DATA_CHANNEL
  → Data transfer in progress

FUZZING STRATEGY:
  Correctly navigate States 1 → 2 using fixed (non-fuzzed) messages
  Then inject mutations in State 3 messages
  Each mutation is a separate test case; the session resets to State 1 between
  test cases where needed
```

### State Management in Boofuzz

```python
# Connecting states: define which messages follow which
session.connect(s_get("USER"))         # start: USER message
session.connect(s_get("USER"), s_get("PASS"))         # after USER: PASS
session.connect(s_get("PASS"), s_get("LIST"))         # after PASS: LIST (fuzzed)
session.connect(s_get("PASS"), s_get("RETR"))         # after PASS: RETR (fuzzed)

# This creates a graph:
#   USER → PASS → LIST
#               → RETR
#
# Boofuzz walks all paths, fuzzing each leaf request
```

---

## Crash Detection and Target Restart

### Monitor Types

```python
from boofuzz import ProcessMonitor, NetworkMonitor

# ProcessMonitor: monitors a local process via procmon agent (boofuzz-procmon)
# Use when the target runs locally
process_monitor = ProcessMonitor("127.0.0.1", 26002)
process_monitor.options(
    crash_filename="crashes/procmon_crashes.db",
    restart_time=3,
    proc_name="target_daemon",
)

# NetworkMonitor: passively captures network traffic
# Use for logging, not crash detection
network_monitor = NetworkMonitor("127.0.0.1", 26001)

# Docker restart callback (for containerised targets):
import subprocess

def docker_restart_callback():
    subprocess.run(["docker", "restart", "fuzzing-target"], check=True)
    time.sleep(2)   # wait for service to be ready

# Attach to session:
# session = Session(target=Target(connection=..., monitors=[process_monitor]))
```

---

## Writing a Grammar-Based Mutation Strategy

For protocols with structured fields, grammar-based mutation is more
efficient than pure random mutation.

```python
# Custom primitive: mutate a length field with interesting values
INTERESTING_LENGTHS = [
    0, 1, 2, 127, 128, 255, 256, 32767, 32768, 65535, 65536,
    0xFFFF, 0xFFFFFFFF, 0x80000000,
]

# In Boofuzz, use IntegerBlock with a custom mutation list:
from boofuzz import IntegerBlock

s_initialize("custom_request")
s_static(b"\x01\x02\x03\x04")           # magic
# Length field with interesting values:
IntegerBlock(
    name="payload_len",
    length=4,
    endian="<",
    default_value=10,
    fuzz_values=INTERESTING_LENGTHS,     # inject each of these as test cases
)
# Payload:
s_string("A" * 10, name="payload")
```

---

## Coverage-Guided Network Fuzzing

Without AFL's shared memory feedback, network fuzzers operate coverage-blind.
Two techniques add coverage feedback:

```bash
# Technique 1: SanitizerCoverage (fastest for local targets)
# Build the target with:
clang -g -fsanitize=address -fsanitize-coverage=trace-pc-guard \
      -o target target.c

# Run a coverage proxy that relays coverage data to the fuzzer
# See: https://github.com/google/boofuzz-coverage (or write your own)

# Technique 2: DRCOV (works on closed-source binaries)
# Use DynamoRIO to collect coverage during fuzzing:
drrun -t drcov -logdir coverage_logs -- ./target <input>
# Post-process with lighthouse plugin for IDA/Ghidra

# Technique 3: Corpus distillation from network captures
# Record traffic during manual testing → extract unique request patterns
# Use these as the initial corpus for smart mutation
```

---

## Case Study: CVE-2020-25220 (ProFTPD OOB Write)

```
TARGET: ProFTPD 1.3.7a and earlier
PROTOCOL: FTP (port 21)
CLASS: OOB write in mod_cap module
CVSS: 9.8 (Critical)

HOW IT WOULD HAVE BEEN FOUND WITH NETWORK FUZZING:

State machine:
  CONNECTED → NOOP (pre-auth) → [target: any unauthenticated command]

Fuzz strategy:
  session.connect(s_get("NOOP"))   # pre-auth
  session.connect(s_get("NOOP"), s_get("SITE_CMD"))  # fuzz SITE command

  SITE command primitive:
    s_initialize("SITE_CMD")
    s_static("SITE ")            # FTP SITE verb
    s_string("CPFR /etc/passwd", name="site_arg", fuzzable=True)
    s_static("\r\n")

  The CPFR (Copy From) command accepted a path argument.
  Fuzzing the path with path traversal sequences + length overflow triggers
  the OOB write in the path processing code.

DETECTION:
  Process monitor: target process segfaults or ASan fires
  Crash file: captured SITE CPFR payload in boofuzz crash log

LESSON: The pre-auth attack surface of network daemons (commands available
  before login) is often under-tested. A network fuzzer that targets
  unauthenticated commands finds these bugs quickly.
```

---

## Key Takeaways

1. **State is the primary challenge in network fuzzing.** The fuzzer must
   reach the correct protocol state before injecting mutations. Map the
   state machine first; code the fuzzer second. A fuzzer that sends
   malformed command packets before authenticating tests nothing.
2. **Boofuzz's power is in primitive composition.** The `s_size` primitive
   auto-calculates field lengths; interesting integers cover the historical
   vulnerability triggers; string mutations exercise parsing. Understanding
   each primitive is what makes the harness effective.
3. **Pre-auth attack surface is the highest-value target.** Commands
   that are processed before authentication require no credentials to reach.
   Any bug found there is unauthenticated RCE. Always map the pre-auth
   surface before the post-auth surface.
4. **Network fuzzing without crash detection misses most bugs.** If you
   cannot tell the target has crashed, you cannot record the input that
   caused it. Set up the process monitor before starting the campaign.
   A fuzzer that runs for 24 hours without crash detection is a server
   load test, not a security audit.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q676.1, Q676.2 …).

---

## Navigation

← Previous: [Day 675 — Milestone 675 and Mid-Module Retrospective](DAY-0675-Milestone-675-Mid-Module-Retrospective.md)
→ Next: [Day 677 — Network Fuzzing Lab (Boofuzz)](DAY-0677-Network-Fuzzing-Lab-Boofuzz.md)
