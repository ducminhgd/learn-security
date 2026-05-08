---
title: "Advanced Fuzzing — Grammar-Based and Protocol Fuzzing"
tags: [vulnerability-research, fuzzing, grammar-based, protocol-fuzzing,
  Boofuzz, network-fuzzing, grammar-mutator, module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 661
prerequisites:
  - Day 655 — Coverage-Guided Fuzzing
related_topics:
  - Bug Class Deep Dive — Integer Overflow (Day 662)
  - Vulnerability Research Sprint Day 1 (Day 664)
---

# Day 661 — Advanced Fuzzing: Grammar-Based and Protocol Fuzzing

> "Coverage-guided fuzzing is the best tool we have for unstructured or
> lightly-structured input. But what happens when the target rejects 99.9%
> of your inputs in the first ten bytes? You need to teach the fuzzer the
> grammar of the protocol. Once it speaks the language, it can spend its
> mutations on meaning instead of syntax. That is where the interesting
> bugs live."
>
> — Ghost

---

## Goals

Understand grammar-based fuzzing and when it outperforms coverage-guided
mutation. Write a Boofuzz session to fuzz a network protocol. Use
Grammar-Mutator with AFL++ for structured input generation. Fuzz a binary
protocol parser with a custom harness that handles framing.

**Prerequisites:** Day 655.
**Estimated study time:** 4 hours.

---

## When Grammar-Based Fuzzing Wins

```
FUZZING APPROACH DECISION TREE
═══════════════════════════════════════════════════════════════════════

Is the input format strictly validated before reaching interesting code?
  NO → Use AFL++/libFuzzer with a dictionary and structure-aware mutator (Day 655)
  YES → Continue

Does the target listen on a network socket?
  YES → Use Boofuzz (network protocol fuzzer)
  NO → Continue

Do you have a grammar or BNF spec for the format?
  YES → Use Grammar-Mutator with AFL++ OR use Grammarinator
  NO → Extract grammar from valid samples + code reading

Is the format a well-known one (HTTP, TLS, XML, SQL)?
  YES → Use existing Boofuzz/Peach pit or Grammar-Mutator grammar
  NO → Write a minimal grammar from the parser source

GRAMMAR-BASED ADVANTAGE:
  Coverage-guided fuzzer on JSON parser after 24h: ~40-60% coverage
  Grammar-based fuzzer on same parser after 1h:   ~70-85% coverage
  (Grammar generates syntactically valid inputs — reaches deeper code paths)
```

---

## Stage 1 — Grammar-Based Fuzzing with Grammar-Mutator

AFL++ supports a custom grammar-based mutator via `GRAMMAR_FILE`. Grammar-Mutator
generates structurally valid inputs according to a grammar specification.

```python
#!/usr/bin/env python3
"""
Grammar specification examples for Grammar-Mutator (AFL++ custom mutator).
Grammar files use a ANTLR4-like BNF notation.
"""
from __future__ import annotations

from pathlib import Path


# Grammar-Mutator uses a simple BNF-like format:
# <rule> ::= alternative1 | alternative2
# Terminals are quoted strings or hex escapes
# See: github.com/AFLplusplus/Grammar-Mutator

HTTP_GRAMMAR = """\
<start> ::= <request>
<request> ::= <method> " " <path> " " <version> "\\r\\n" <headers> "\\r\\n" <body>
<method> ::= "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH"
<path> ::= "/" | "/" <path_component>
<path_component> ::= <word> | <word> "/" <path_component>
<version> ::= "HTTP/1.0" | "HTTP/1.1"
<headers> ::= <header> | <header> "\\r\\n" <headers>
<header> ::= "Content-Type: " <content_type> | "Content-Length: " <integer>
           | "Host: " <hostname> | "User-Agent: " <word>
<content_type> ::= "application/json" | "text/plain" | "application/x-www-form-urlencoded"
<hostname> ::= <word> | <word> "." <hostname>
<body> ::= "" | <json_value>
<json_value> ::= <json_object> | <json_array> | <json_string> | <json_number>
               | "null" | "true" | "false"
<json_object> ::= "{}" | "{" <json_members> "}"
<json_members> ::= <json_pair> | <json_pair> "," <json_members>
<json_pair> ::= <json_string> ":" <json_value>
<json_array> ::= "[]" | "[" <json_elements> "]"
<json_elements> ::= <json_value> | <json_value> "," <json_elements>
<json_string> ::= "\\"" <word> "\\""
<json_number> ::= <integer> | "-" <integer>
<integer> ::= "0" | "1" | "42" | "256" | "65535" | "2147483647" | "-1"
<word> ::= "a" | "test" | "user" | "admin" | "value" | "key" | "data"
<integer> ::= "0" | "1" | "100" | "4294967295" | "-1" | "2147483648"
"""

SQL_GRAMMAR = """\
<start> ::= <query>
<query> ::= <select> | <insert> | <update> | <delete>
<select> ::= "SELECT " <columns> " FROM " <table> <where_clause> <limit_clause>
<insert> ::= "INSERT INTO " <table> " (" <columns> ") VALUES (" <values> ")"
<update> ::= "UPDATE " <table> " SET " <assignment> <where_clause>
<delete> ::= "DELETE FROM " <table> <where_clause>
<columns> ::= "*" | <column> | <column> ", " <columns>
<column> ::= "id" | "name" | "email" | "status" | "created_at"
<table> ::= "users" | "orders" | "products" | "sessions"
<where_clause> ::= "" | " WHERE " <condition>
<condition> ::= <column> " = " <value> | <column> " > " <number>
             | <column> " LIKE " <string> | "1=1" | "1=0"
<assignment> ::= <column> " = " <value>
<values> ::= <value> | <value> ", " <values>
<value> ::= <string> | <number> | "NULL" | "true" | "false"
<string> ::= "'" <word> "'" | "''" | "' OR '1'='1" | "'; DROP TABLE users--"
<number> ::= "0" | "1" | "42" | "-1" | "9999999"
<limit_clause> ::= "" | " LIMIT " <number>
<word> ::= "test" | "admin" | "user" | "example"
"""

Path("grammars").mkdir(exist_ok=True)
Path("grammars/http.g").write_text(HTTP_GRAMMAR)
Path("grammars/sql.g").write_text(SQL_GRAMMAR)
print("[*] Grammars written to grammars/")
print()
print("[*] Grammar-Mutator setup:")
print("  1. Clone: git clone https://github.com/AFLplusplus/Grammar-Mutator")
print("  2. Build: cd Grammar-Mutator && make GRAMMAR_FILE=../grammars/http.g")
print("  3. Fuzz:  AFL_CUSTOM_MUTATOR_LIBRARY=./grammar_mutator.so \\")
print("            AFL_CUSTOM_MUTATOR_ONLY=1 \\")
print("            afl-fuzz -i corpus/ -o output/ -- ./target @@")
```

---

## Stage 2 — Network Protocol Fuzzing with Boofuzz

Boofuzz is the modern successor to Sulley. It speaks network protocols and
systematically mutates every field.

```python
#!/usr/bin/env python3
"""
Boofuzz session: fuzzing a custom TCP protocol.
Protocol format:
  [4 bytes: length LE] [1 byte: command] [N bytes: payload]
Commands: 0x01=LOGIN, 0x02=UPLOAD, 0x03=QUERY, 0xFF=DISCONNECT
"""
from __future__ import annotations

from boofuzz import (
    Block,
    Bytes,
    Request,
    Session,
    Static,
    String,
    Target,
    TCPSocketConnection,
    Word,
    DWord,
)
from boofuzz import primitives


def build_login_request() -> None:
    """Define the LOGIN packet structure for fuzzing."""
    Request("login", children=(
        # Length field: 4-byte LE uint32 (boofuzz will mutate this)
        DWord(name="length", default_value=0x0000000A, endian="<"),
        # Command: LOGIN = 0x01
        Static(name="command", default_value=b"\x01"),
        # Username: boofuzz will try long strings, special chars, etc.
        String(name="username", default_value="admin", max_len=64),
        # Separator
        Static(name="sep", default_value=b"\x00"),
        # Password
        String(name="password", default_value="password123", max_len=64),
    ))


def build_upload_request() -> None:
    """Define the UPLOAD packet structure for fuzzing."""
    Request("upload", children=(
        DWord(name="length", default_value=0x00000105, endian="<"),
        Static(name="command", default_value=b"\x02"),
        # Filename: path traversal candidates in mutation list
        String(name="filename", default_value="test.txt", max_len=255),
        Static(name="sep", default_value=b"\x00"),
        # File size field (4 bytes): mismatch causes buffer overflows
        DWord(name="filesize", default_value=256, endian="<"),
        # File data
        Bytes(name="filedata", default_value=b"A" * 256, max_len=65536),
    ))


def build_query_request() -> None:
    """Define the QUERY packet structure — SQL injection candidates."""
    Request("query", children=(
        DWord(name="length", default_value=0x00000020, endian="<"),
        Static(name="command", default_value=b"\x03"),
        # Query string: boofuzz includes SQL injection strings in String mutations
        String(name="query_str", default_value="SELECT * FROM users", max_len=512),
    ))


def run_fuzzer() -> None:
    """Create and run the Boofuzz fuzzing session."""
    session = Session(
        target=Target(
            connection=TCPSocketConnection("127.0.0.1", 9999),
        ),
        sleep_time=0.01,
        crash_threshold_request=3,
        crash_threshold_element=3,
        # Save all crashes to this directory:
        # (boofuzz saves request that caused the crash)
        keep_web_open=False,
    )

    build_login_request()
    build_upload_request()
    build_query_request()

    # Add requests to session (they fuzz independently)
    session.connect(session.root, Request("login"))
    session.connect(session.root, Request("upload"))
    session.connect(session.root, Request("query"))

    # Start fuzzing
    session.fuzz()


if __name__ == "__main__":
    print("[*] Starting Boofuzz session against 127.0.0.1:9999")
    print("[*] Ensure target is running: ./target_server 9999")
    print("[*] Monitor: http://localhost:26000 (Boofuzz web UI)")
    run_fuzzer()
```

```bash
# Boofuzz setup:
pip install boofuzz

# Run the vulnerable target (example from a CTF or lab):
./vulnerable_server 9999 &

# Run boofuzz (capture crashes):
python3 boofuzz_session.py 2>&1 | tee boofuzz_output.log

# Boofuzz logs everything — check for crashes:
# Crash info is saved to boofuzz-results/ directory
ls boofuzz-results/*.db   # SQLite database with all session data

# Replay a specific crashing input:
python3 -c "
import sqlite3, sys
conn = sqlite3.connect('boofuzz-results/run-XXXXXXXX-XXXXXX.db')
c = conn.cursor()
c.execute('SELECT id, name, send_lines FROM steps WHERE name LIKE \"%crash%\"')
for row in c.fetchall():
    print(row[0], row[1])
    print('Payload:', row[2][:100])
"
```

---

## Stage 3 — Binary Protocol Harness for AFL++

When the target is a library (not a server), write a harness that understands
the protocol framing to avoid wasting mutations on invalid length fields.

```c
/*
 * binary_proto_harness.c
 *
 * AFL++ persistent-mode harness for a binary protocol parser.
 *
 * Protocol: [4B length LE] [1B command] [N-1 bytes payload]
 * The harness extracts the fields and calls the parser directly,
 * bypassing the network layer. This eliminates:
 *   - Wasted mutations on the length field (we compute it)
 *   - Network overhead
 *   - State machine problems (we call the parser directly)
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "target_proto.h"  /* Target library header */

/* Minimum input: 5 bytes (4 length + 1 command) */
#define MIN_INPUT_SIZE 5
#define MAX_PAYLOAD    65536

int main(int argc, char **argv) {
    /* Initialise target once (outside persistent loop) */
    proto_init();

    while (__AFL_LOOP(10000)) {
        /* Read fuzzer input from stdin */
        uint8_t buf[MAX_PAYLOAD + 5];
        ssize_t n = read(0, buf, sizeof(buf));

        if (n < MIN_INPUT_SIZE) continue;

        /* Extract command byte */
        uint8_t command = buf[4];

        /* Extract payload */
        uint8_t *payload = buf + 5;
        size_t   payload_len = (size_t)(n - 5);

        /*
         * Call the target parser directly.
         * We ignore the length field from the input — the fuzzer should
         * mutate the payload, not the framing.
         */
        switch (command) {
            case 0x01:  /* LOGIN */
                proto_handle_login(payload, payload_len);
                break;
            case 0x02:  /* UPLOAD */
                proto_handle_upload(payload, payload_len);
                break;
            case 0x03:  /* QUERY */
                proto_handle_query(payload, payload_len);
                break;
            default:
                /* Let the fuzzer explore unknown commands too */
                proto_handle_unknown(command, payload, payload_len);
                break;
        }

        /* Reset parser state between iterations */
        proto_reset();
    }

    proto_cleanup();
    return 0;
}

/*
 * Compile:
 * afl-clang-fast -g -fsanitize=address,undefined \
 *     binary_proto_harness.c target_lib.a \
 *     -I target/include \
 *     -o harness_afl
 *
 * Seed corpus: create one valid packet for each command:
 * python3 -c "import struct; \
 *     open('corpus/login.bin','wb').write(b'\x0a\x00\x00\x00\x01admin\x00pass\x00')"
 *
 * Run:
 * afl-fuzz -i corpus/ -o output/ -m 1024 -- ./harness_afl
 */
```

---

## Stage 4 — TLS and Encrypted Protocol Fuzzing

```python
#!/usr/bin/env python3
"""
Strategy for fuzzing behind TLS/authentication.
The key insight: you do NOT fuzz TLS itself (leave that to BoringSSL's
fuzzer). You fuzz the application-layer parser that runs after TLS terminates.
"""
from __future__ import annotations

TLS_FUZZING_STRATEGIES = {
    "strategy_1_patch_out_tls": {
        "description": "Remove TLS layer from the binary — fuzz plain text",
        "method": [
            "Find SSL_read() / SSL_write() calls in the binary",
            "Replace SSL_read with a stub that reads from stdin",
            "Replace SSL_write with a stub that writes to stdout",
            "Recompile or patch the binary",
        ],
        "advantage": "Maximum fuzzing speed (no TLS overhead)",
        "disadvantage": "Requires source access or deep binary knowledge",
    },
    "strategy_2_mitm_proxy": {
        "description": "Insert a transparent proxy that receives plain text",
        "method": [
            "Use socat or stunnel as an SSL terminator:",
            "socat OPENSSL-LISTEN:8443,cert=server.pem,verify=0 TCP:127.0.0.1:8080",
            "Point boofuzz at port 8080 (plain text)",
            "socat forwards plain text to TLS target on 8443",
        ],
        "advantage": "No binary modification needed",
        "disadvantage": "Adds latency; may affect fuzzing speed",
    },
    "strategy_3_fuzz_post_auth": {
        "description": "Write a harness that authenticates, then fuzzes the session",
        "method": [
            "Complete authentication using a real client",
            "Extract session token / session key",
            "Write boofuzz session that sends auth first, then fuzzes subsequent messages",
        ],
        "boofuzz_example": """
session.connect(session.root, s_get('auth_request'))
session.connect(s_get('auth_request'), s_get('fuzz_payload'))
# auth_request is static; fuzz_payload is the mutation target
""",
    },
}

for name, strategy in TLS_FUZZING_STRATEGIES.items():
    print(f"\n[{name.upper()}]: {strategy['description']}")
    for step in strategy.get("method", [])[:3]:
        print(f"  → {step}")
    if "advantage" in strategy:
        print(f"  ✓ {strategy['advantage']}")
    if "disadvantage" in strategy:
        print(f"  ✗ {strategy['disadvantage']}")
```

---

## Key Takeaways

1. **Grammar-based fuzzing reaches code that mutation-based fuzzing never
   touches.** A JSON parser that validates structure strictly will reject 99% of
   random mutations in the first 10 bytes. A grammar-based fuzzer that generates
   syntactically valid JSON invests 100% of its mutations in semantic variation —
   extreme values, nested structures, edge-case numbers — and reaches code paths
   that random mutation never finds.
2. **Boofuzz owns the protocol; your target owns the parser.** Network protocol
   fuzzers send valid-enough framing to get past the first layer. The bugs they
   find are in the payload handlers — the code that processes individual messages
   after the framing is accepted. Structure your Boofuzz session to stress every
   message type, especially ones with variable-length fields.
3. **Separate the framing from the payload in your harness.** If your harness
   passes the full raw bytes (including length field) to the parser, the fuzzer
   will waste mutations on the length field — most will be rejected as malformed.
   Extract the command and payload yourself in the harness, compute the length,
   and pass the payload directly to the relevant handler function.
4. **TLS is not an obstacle — it is a layer you bypass.** Every TLS-protected
   service terminates TLS and then hands plain text to an application parser.
   Fuzz the application parser directly: either patch out TLS, use a transparent
   proxy, or write a harness that handles the TLS handshake once and then fuzzes
   the application-layer messages. Do not fuzz TLS itself unless you are
   researching the TLS library.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q661.1, Q661.2 …).

---

## Navigation

← Previous: [Day 660 — Static Analysis with Semgrep and CodeQL](DAY-0660-Static-Analysis-Semgrep-CodeQL.md)
→ Next: [Day 662 — Bug Class Deep Dive: Integer Overflow and Format String](DAY-0662-Bug-Class-Integer-Overflow-Format-String.md)
