---
title: "Network Fuzzing Lab — Boofuzz Against a Vulnerable Daemon"
tags: [vulnerability-research, fuzzing, network-fuzzing, boofuzz, lab,
  daemon, tcp, module-10-vulnresearch-01]
module: 10-VulnResearch-01
day: 677
prerequisites:
  - Day 676 — Network Protocol Fuzzing: Boofuzz and Stateful Testing
related_topics:
  - Day 678 — Dependency Confusion and Supply Chain Security
  - Day 653 — Fuzzing Fundamentals
---

# Day 677 — Network Fuzzing Lab: Boofuzz Against a Vulnerable Daemon

> "Fuzzing a network service is different from fuzzing a binary because
> you cannot just measure whether it exited. You have to keep talking
> to it, notice when it stops answering, and figure out what you said
> that killed it. Today you set up the full pipeline: daemon, fuzzer,
> crash detection, log review."
>
> — Ghost

---

## Goals

Stand up a purpose-built vulnerable TCP daemon. Write a Boofuzz harness
that fuzzes it in two states (pre-auth and post-auth). Detect a crash,
triage it, and write the minimal reproducer.

**Prerequisites:** Day 676.
**Estimated study time:** 5 hours.

---

## Lab Setup

### Vulnerable Daemon: `vuln_daemon.c`

Save and build the following vulnerable network daemon.

```c
/* vuln_daemon.c — deliberately vulnerable TCP daemon for fuzzing practice.
 *
 * PROTOCOL:
 *   CLIENT → SERVER: "AUTH <user> <pass>\n"  → SERVER: "OK\n" or "FAIL\n"
 *   CLIENT → SERVER: "GET <key>\n"            → SERVER: "<value>\n"
 *   CLIENT → SERVER: "SET <key> <value>\n"    → SERVER: "OK\n"
 *   CLIENT → SERVER: "EXEC <cmd_len> <cmd>\n" → SERVER: output
 *   CLIENT → SERVER: "QUIT\n"                 → SERVER: closes connection
 *
 * VULNERABILITIES:
 *   1. handle_exec(): reads cmd_len as int, no overflow check before alloca()
 *      → stack overflow via EXEC with large cmd_len (CWE-121)
 *   2. handle_set(): fixed 256-byte value buffer, no bounds check on value
 *      → heap overflow when value exceeds 255 chars (CWE-122)
 *
 * Build:
 *   clang -g -fsanitize=address,undefined \
 *         -fno-omit-frame-pointer -fno-stack-protector \
 *         -o vuln_daemon vuln_daemon.c
 *   Listen: ./vuln_daemon 9876
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <alloca.h>

#define PORT_DEFAULT 9876
#define MAX_LINE     1024
#define KV_CAPACITY  128

typedef struct { char key[64]; char value[256]; } KVPair;
static KVPair kv_store[KV_CAPACITY];
static int kv_size = 0;

static void send_str(int fd, const char *s) {
    write(fd, s, strlen(s));
}

/* BUG 1: cmd_len from client controls alloca() size — stack overflow */
static void handle_exec(int fd, const char *args, int authenticated) {
    if (!authenticated) { send_str(fd, "DENY\n"); return; }

    int cmd_len = 0;
    char cmd_buf_static[16] = {0};
    sscanf(args, "%d %15s", &cmd_len, cmd_buf_static);

    /* VULNERABILITY: no check that cmd_len is reasonable */
    char *cmd = alloca(cmd_len + 1);      /* ← stack buffer sized by attacker */
    memset(cmd, 0, cmd_len + 1);
    memcpy(cmd, cmd_buf_static, strlen(cmd_buf_static));

    /* "Execute" by echoing back */
    dprintf(fd, "EXEC:%s\n", cmd);
}

/* BUG 2: value buffer is 256 bytes; no bounds check on incoming value */
static void handle_set(int fd, const char *args, int authenticated) {
    if (!authenticated) { send_str(fd, "DENY\n"); return; }

    char key[64] = {0};
    char value[256] = {0};              /* ← fixed size */
    /* VULNERABILITY: sscanf with %s reads unbounded string into 256-byte buf */
    sscanf(args, "%63s %255s", key, value);    /* correct size limits */

    /* BUG is actually in the KV store copy — no check on value len */
    for (int i = 0; i < kv_size; i++) {
        if (strcmp(kv_store[i].key, key) == 0) {
            /* Direct copy with no bounds check on existing entry */
            strcpy(kv_store[i].value, value);  /* ← OOB write if value > 255 */
            send_str(fd, "OK\n");
            return;
        }
    }
    if (kv_size < KV_CAPACITY) {
        strncpy(kv_store[kv_size].key, key, 63);
        strcpy(kv_store[kv_size].value, value);  /* ← OOB write */
        kv_size++;
    }
    send_str(fd, "OK\n");
}

static void handle_connection(int client_fd) {
    char line[MAX_LINE];
    int  authenticated = 0;

    while (1) {
        ssize_t n = read(client_fd, line, sizeof(line) - 1);
        if (n <= 0) break;
        line[n] = '\0';

        /* Strip trailing newline */
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        if (strncmp(line, "AUTH ", 5) == 0) {
            /* Simple auth: accept any "AUTH admin admin" */
            if (strstr(line + 5, "admin admin")) {
                authenticated = 1;
                send_str(client_fd, "OK\n");
            } else {
                send_str(client_fd, "FAIL\n");
            }
        } else if (strncmp(line, "GET ", 4) == 0) {
            const char *key = line + 4;
            for (int i = 0; i < kv_size; i++) {
                if (strcmp(kv_store[i].key, key) == 0) {
                    dprintf(client_fd, "%s\n", kv_store[i].value);
                    goto next;
                }
            }
            send_str(client_fd, "NOTFOUND\n");
        } else if (strncmp(line, "SET ", 4) == 0) {
            handle_set(client_fd, line + 4, authenticated);
        } else if (strncmp(line, "EXEC ", 5) == 0) {
            handle_exec(client_fd, line + 5, authenticated);
        } else if (strcmp(line, "QUIT") == 0) {
            break;
        } else {
            send_str(client_fd, "UNKNOWN\n");
        }
        next:;
    }
    close(client_fd);
}

int main(int argc, char *argv[]) {
    int port = argc > 1 ? atoi(argv[1]) : PORT_DEFAULT;

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(port),
        .sin_addr.s_addr = INADDR_ANY,
    };
    bind(srv, (struct sockaddr *)&addr, sizeof(addr));
    listen(srv, 5);

    fprintf(stderr, "[*] vuln_daemon listening on :%d\n", port);

    while (1) {
        int client = accept(srv, NULL, NULL);
        if (client < 0) continue;
        handle_connection(client);
    }
    return 0;
}
```

```bash
# Build
clang -g -fsanitize=address,undefined \
      -fno-omit-frame-pointer -fno-stack-protector \
      -o vuln_daemon vuln_daemon.c

# Start the daemon (in background or a second terminal)
./vuln_daemon 9876 &
DAEMON_PID=$!

# Quick sanity test
python3 -c "
import socket
s = socket.create_connection(('127.0.0.1', 9876))
s.sendall(b'AUTH admin admin\n')
print('Auth:', s.recv(64))
s.sendall(b'SET foo bar\n')
print('Set:', s.recv(64))
s.sendall(b'GET foo\n')
print('Get:', s.recv(64))
s.sendall(b'QUIT\n')
s.close()
"
```

---

## Exercise 1 — Manual Vulnerability Review (30 minutes)

Before fuzzing, identify both vulnerabilities in the code.

```
MANUAL REVIEW RESULTS

BUG 1 — handle_exec()
  Type: ___________________________________________
  CWE: ____________________________________________
  Triggering condition: ___________________________
  Line number: ____________________________________

BUG 2 — handle_set() / handle_connection SET handler
  Type: ___________________________________________
  CWE: ____________________________________________
  Triggering condition: ___________________________
  Line number: ____________________________________
```

---

## Exercise 2 — Write the Boofuzz Harness (90 minutes)

```python
#!/usr/bin/env python3
"""
Day 677 — Boofuzz harness for vuln_daemon.

TARGET: vuln_daemon on 127.0.0.1:9876
PROTOCOL: newline-delimited text
FUZZ TARGETS: EXEC <cmd_len> and SET <key> <value>
"""
from __future__ import annotations

import time
import subprocess
from boofuzz import (
    Session, Target, TCPSocketConnection,
    s_initialize, s_string, s_static, s_int, s_size,
    s_block_start, s_block_end, s_get,
    FuzzLogger, FuzzLoggerText,
)
from boofuzz.monitors import BaseMonitor


class DaemonMonitor(BaseMonitor):
    """
    Restart monitor for vuln_daemon.
    Detects crash via connection failure; restarts the daemon subprocess.
    """

    def __init__(self, binary: str, port: int = 9876) -> None:
        self.binary = binary
        self.port   = port
        self._proc: subprocess.Popen | None = None

    def start_target(self) -> bool:
        if self._proc and self._proc.poll() is None:
            return True   # still running
        self._proc = subprocess.Popen(
            [self.binary, str(self.port)],
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.5)   # wait for bind
        return True

    def stop_target(self) -> bool:
        if self._proc:
            self._proc.terminate()
            self._proc.wait(timeout=3)
        return True

    def alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def post_send(self, target, fuzz_data_logger, session, sock, *args, **kwargs):
        if not self.alive():
            fuzz_data_logger.log_fail("Daemon crashed — recording crash")
            self.start_target()


def build_session() -> Session:
    monitor = DaemonMonitor("./vuln_daemon", port=9876)
    monitor.start_target()

    session = Session(
        target=Target(
            connection=TCPSocketConnection("127.0.0.1", 9876, timeout=3),
            monitors=[monitor],
        ),
        sleep_time=0.05,
        crash_threshold_request=3,
        web_port=26000,
    )

    # ── AUTH (pre-auth, not fuzzed — just get to authenticated state) ──────
    s_initialize("auth")
    s_static(b"AUTH admin admin\n")

    # ── EXEC COMMAND (fuzz the cmd_len field) ─────────────────────────────
    # Protocol: "EXEC <cmd_len> <cmd>\n"
    # BUG: cmd_len controls alloca() size — integer overflow / stack overflow
    s_initialize("exec_fuzz")
    s_static(b"EXEC ")
    s_int(                              # ← fuzz the length field
        10,
        endian="<",
        signed=True,
        format="ascii",
        name="cmd_len",
        fuzz_values=[
            -1, -2147483648, 0, 1, 127, 128, 255, 256,
            65535, 65536, 2147483647,   # INT_MAX
        ],
    )
    s_static(b" ls\n")

    # ── SET COMMAND (fuzz the value field) ────────────────────────────────
    # Protocol: "SET <key> <value>\n"
    # BUG: value is copied into 256-byte buffer without bounds check
    s_initialize("set_fuzz")
    s_static(b"SET testkey ")
    s_string(
        "A" * 10,
        name="set_value",
        fuzz_values=["A" * n for n in [256, 257, 300, 512, 1024, 4096]],
    )
    s_static(b"\n")

    # ── BUILD SESSION GRAPH ───────────────────────────────────────────────
    # Path 1: AUTH → EXEC (fuzz EXEC after auth)
    session.connect(s_get("auth"))
    session.connect(s_get("auth"), s_get("exec_fuzz"))

    # Path 2: AUTH → SET (fuzz SET after auth)
    session.connect(s_get("auth"), s_get("set_fuzz"))

    return session


if __name__ == "__main__":
    print("[*] Starting Boofuzz session — web UI at http://localhost:26000")
    session = build_session()
    session.fuzz()
```

```bash
# In terminal 1: run the fuzzer
python3 vuln_fuzz.py

# In terminal 2: watch the daemon
watch -n 1 'ps aux | grep vuln_daemon'

# In terminal 3: watch for crashes
tail -f boofuzz-results/*.db 2>/dev/null | strings | grep -i "fail\|crash"
```

---

## Exercise 3 — Triage and Manual Reproduction (60 minutes)

After the fuzzer finds a crash, extract the crashing input and reproduce
it manually.

```python
#!/usr/bin/env python3
"""
Manually reproduce the crash found by Boofuzz.
Fill in the crashing values from the boofuzz log.
"""
import socket, time

def reproduce_exec_crash(host="127.0.0.1", port=9876):
    """Reproduce the EXEC crash with cmd_len overflow."""
    s = socket.create_connection((host, port), timeout=3)

    # Authenticate first
    s.sendall(b"AUTH admin admin\n")
    print("Auth:", s.recv(64).strip())
    time.sleep(0.1)

    # ── FILL IN THE CRASHING CMD_LEN VALUE FROM BOOFUZZ LOG ──────────────
    cmd_len = ___   # replace with the crashing value from the fuzzer log
    # ─────────────────────────────────────────────────────────────────────

    payload = f"EXEC {cmd_len} ls\n".encode()
    print(f"Sending: {payload!r}")
    s.sendall(payload)

    try:
        response = s.recv(256)
        print("Response:", response)
    except (ConnectionResetError, TimeoutError):
        print("[!] Connection reset or timeout — daemon crashed!")
    s.close()

if __name__ == "__main__":
    reproduce_exec_crash()
```

```bash
# Start daemon with ASan to confirm crash type
./vuln_daemon 9876 2>&1 &
python3 reproduce_crash.py
# Check ASan output in the vuln_daemon terminal
```

### Crash Triage Log

```
CRASH TRIAGE

Bug 1 (EXEC): cmd_len = _______________________________
  ASan error type: _______________________________________
  Crash function: ________________________________________
  Stack trace frame #0: __________________________________
  Confirmed crash: Y / N

Bug 2 (SET): value length = _____________________________
  ASan error type: _______________________________________
  Crash function: ________________________________________
  Stack trace frame #0: __________________________________
  Confirmed crash: Y / N

Total unique crashes found by fuzzer: ____________________
Total test cases executed: _______________________________
Time to first crash: _____________________________________
```

---

## Key Takeaways

1. **Protocol knowledge before fuzzer code.** The 30 minutes reading
   `vuln_daemon.c` before writing the harness is not optional — it is
   the work. A fuzzer that does not understand the protocol sends random
   bytes that are rejected at the input layer and never reach the
   vulnerable parser.
2. **Authentication is a gate, not an obstacle.** Pre-auth fuzz targets
   are higher value because they require no credentials. Post-auth targets
   require the fuzzer to maintain a valid session. Both are worth fuzzing;
   map them separately in your session graph.
3. **The crash detection pipeline matters as much as the mutations.**
   A fuzzer without restart logic stops at the first crash. A fuzzer
   with a good restart monitor continues through the full mutation space
   and finds multiple bugs. Set up the monitor before starting the campaign.
4. **Network protocol bugs are often the same classes.** The two bugs in
   `vuln_daemon` — integer overflow before stack allocation and OOB write
   in a fixed buffer — appear in real network daemons constantly. The
   difference between a lab exercise and a real CVE is the target.
   The technique is identical.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q677.1, Q677.2 …).

---

## Navigation

← Previous: [Day 676 — Network Protocol Fuzzing Deep Dive](DAY-0676-Network-Protocol-Fuzzing.md)
→ Next: [Day 678 — Dependency Confusion and Supply Chain Security](DAY-0678-Dependency-Confusion-Supply-Chain.md)
