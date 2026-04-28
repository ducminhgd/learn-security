---
title: "Infrastructure Practice Day 11 — Detection Engineering Sprint"
tags: [practice, detection, Sigma, SIEM, blue-team, Suricata, auditd,
       event-logs, write-rules, purple-team, ATT&CK]
module: 04-BroadSurface-04
day: 256
related_topics:
  - Infrastructure Detection and Hardening (Day 244)
  - Infrastructure Practice Day 10 (Day 255)
  - Infrastructure Practice Day 12 (Day 257)
  - Blue Cell modules (Days B-01 to B-10)
---

# Day 256 — Infrastructure Practice Day 11: Detection Engineering Sprint

> "The best detection engineers are former attackers who got tired of being
> undetected. They know what their own attack looks like from the network
> and the log perspective because they ran it themselves. Today you switch
> chairs. Write the rules that would have caught you."
>
> — Ghost

---

## Goals

By the end of today's session you will have:

1. Written 5 Sigma rules covering the attacks from Days 231–244.
2. Tested each rule against sample log data from your lab sessions.
3. Identified and documented the false positives each rule would generate.
4. Written one auditd rule set for Linux host-based detection.

**Time budget:** 5–6 hours.

---

## Rule Writing Sprint

For each attack, write a Sigma rule — then test it against the logs you
generated during Days 245–254. If you do not have logs, generate them now
by running the attack and capturing the relevant log source.

---

### Rule 1 — ARP Spoofing (Zeek ARP log)

```yaml
title: ARP Cache Poisoning — Rapid Gratuitous ARP Replies
status: experimental
logsource:
  product: zeek
  service: arp
detection:
  # Fill in the detection condition:
  selection:
    ___
  condition: ___
  timeframe: 2m
falsepositives:
  - ___
level: high
tags:
  - attack.t1557.002
```

---

### Rule 2 — LLMNR Response from Unexpected Source

```yaml
title: Unexpected LLMNR Response — Possible Poisoning
status: experimental
logsource:
  product: zeek
  service: dns
detection:
  ___
falsepositives:
  - ___
level: high
tags:
  - attack.t1557.001
```

---

### Rule 3 — SUID Binary Executed with euid=0 by Non-Root User (Linux auditd)

```yaml
title: SUID Binary Escalation
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  # Relevant auditd fields: auid (real user), euid (effective user), exe
  selection:
    type: SYSCALL
    syscall: execve
    euid: 0
  filter_root:
    auid: 0  # root doing expected things
  condition: selection and not filter_root
falsepositives:
  - ___
level: high
tags:
  - attack.t1548.001
```

---

### Rule 4 — Windows SeImpersonate Privilege Use (Security Event Log)

```yaml
title: SeImpersonatePrivilege Used by Non-Service Account
status: experimental
logsource:
  product: windows
  service: security
detection:
  ___
falsepositives:
  - ___
level: high
tags:
  - attack.t1134.001
```

---

### Rule 5 — C2 Beaconing via Regular HTTPS (Zeek conn log)

```yaml
title: Periodic HTTPS Beaconing
status: experimental
logsource:
  product: zeek
  service: conn
detection:
  ___
  timeframe: 1h
falsepositives:
  - ___
level: medium
tags:
  - attack.t1071.001
```

---

## auditd Rule Set (Linux Host)

Write a complete `/etc/audit/rules.d/infrastructure.rules` file:

```bash
# Delete all existing rules
-D

# Record SUID binary executions
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -k suid_escalation

# Record sudo usage
-w /usr/bin/sudo -p x -k sudo_usage

# Record cron script modifications
-w /etc/crontab -p wa -k cron_modification
-w /etc/cron.d -p wa -k cron_modification

# Record /etc/passwd and /etc/shadow writes
-w /etc/passwd -p wa -k passwd_modification
-w /etc/shadow -p wa -k shadow_modification

# Record SSH authorized_keys modifications
-a always,exit -F arch=b64 -S open,openat -F dir=/root/.ssh -F perm=w -k ssh_key_plant
```

---

## Testing Your Rules

```bash
# Test Rule 3 (SUID): run a SUID binary as labuser
sudo -u labuser find . -exec id \;
# Check auditd log:
ausearch -k suid_escalation | aureport -i | tail -10

# Test Rule 5 (beaconing): start a Sliver beacon, wait 5 minutes
# Pull Zeek conn.log and run your rule logic as a jq query:
cat conn.log | jq 'select(.proto == "tcp" and .resp_p == 443) | [.ts, ."id.orig_h", ."id.resp_h"]'
```

```
[ ] Rule 1: tested, false positive rate: ___
[ ] Rule 2: tested, false positive rate: ___
[ ] Rule 3: tested, false positive rate: ___
[ ] Rule 4: tested, false positive rate: ___
[ ] Rule 5: tested, false positive rate: ___
```

---

## Reflection

```
Which rule was hardest to write? ___
Which rule had the most false positives? ___
What would you need to add to reduce false positives without missing real attacks? ___
Which attack from this module has NO good detection? ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q256.1, Q256.2 …).

---

## Navigation

← Previous: [Day 255 — Infrastructure Practice Day 10](DAY-0255-Infrastructure-Practice-Day-10.md)
→ Next: [Day 257 — Infrastructure Practice Day 12](DAY-0257-Infrastructure-Practice-Day-12.md)
