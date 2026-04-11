---
title: "Foundation Competency Gate"
tags: [foundation, gate, competency-check, oral-exam, live-demo,
       module-complete, F-01, F-02, F-03, F-04, F-05]
module: 01-Foundation-05
day: 50
related_topics:
  - Foundation CTF Day (Day 049)
  - Red Cell Module — Reconnaissance (R-01, Day 051)
---

# Day 050 — Foundation Competency Gate

## GATE: Foundation Complete

This is not a lesson. This is a checkpoint.

You do not move to the Offensive Track until you pass this gate.
The gate is pass/fail. There is no partial credit.

---

## Prerequisites

- All of 01-Foundation-01 through 01-Foundation-05 (Days 001–049)
- CTF Day (Day 049) — write-ups submitted for at least 4 of 6 challenges

---

## How the Gate Works

Three components. All three must pass.

| Component | Format | Pass criteria |
|---|---|---|
| **Oral Exam** | 20 questions, answered verbally | 17/20 correct |
| **Live Demo** | 3 lab tasks, performed live | All 3 completed |
| **Written Finding** | One pentest finding in report format | Meets the standard |

---

## Component 1 — Oral Exam

### Instructions

Answer each question in under 2 minutes. No notes. No tools.
The examiner will ask follow-up questions on any answer that is incomplete.

### The Questions

**Network and Transport**

1. A web application sends session cookies over HTTP. The `Secure` flag is not
   set. Describe the complete attack chain from a network position to account
   takeover.

2. Explain TLS 1.3 forward secrecy. Why does ECDHE provide it and why does
   static RSA key exchange not?

3. What is ARP spoofing? How does it enable MITM? What defensive control
   prevents it at the network layer?

4. A DNS response has a very short TTL (1 second). What does this suggest to
   an attacker?

**Linux**

5. You find this in `sudo -l`:
   ```
   (root) NOPASSWD: /usr/bin/find
   ```
   Walk me through the exploit.

6. What is the difference between SUID and Linux capabilities? Give one
   capability that is as dangerous as SUID root.

7. An attacker has written a reverse shell to `/tmp/shell.sh`. They have made
   it executable. But they cannot get it to run as root via cron. What is
   likely preventing execution and how would they work around it?

8. Name four sources of forensic evidence that survive a `rm -rf` on a Linux
   system.

**Web Architecture and Cryptography**

9. Explain the Same-Origin Policy. What does it allow? What does it block?
   Give one exception to each.

10. A developer sets `Access-Control-Allow-Origin` to the value of the
    `Origin` header in every response. What vulnerability is this and how
    do you exploit it?

11. What is a CBC padding oracle? What can an attacker recover with it and
    how many requests does it take per byte?

12. You find `jwt.decode(token, jwt.get_unverified_header(token)['alg'])` in
    source code. What is wrong with this and what are the two possible attacks?

13. An API uses `HMAC-MD5(secret, message)` for authentication. What attack
    applies and what does the attacker gain?

**Authentication and Authorisation**

14. A password reset form returns "Email not found" for non-existent users
    and "Reset email sent" for existing users. What vulnerability is this?
    What else besides the error message can enumerate usernames?

15. Describe the MFA step-skip bypass. What exactly is the server not checking,
    and where in the session data is the flaw?

16. A website has RBAC. The user has role `editor`. The delete endpoint checks
    `if user.role == 'editor': allow_delete(post_id)`. What vulnerability is
    present and what is the impact?

17. The `state` parameter is absent from an OAuth authorization request.
    Walk through the complete CSRF attack.

18. An XML SAML assertion has two `<Assertion>` elements with the same `ID`.
    The first has a valid signature. The second (unsigned) has `role=admin`.
    The SP processes the second one. What attack is this?

19. A password reset token is generated as:
    `base64(user_id + ':' + hex(int(time.time())))`.
    Describe the attack, estimate the cracking time at 1000 requests/second.

20. You are reviewing logs and see: 500 login failures across 200 accounts
    from 300 different IPs in 5 minutes. What is happening? What two logs
    would confirm it? What immediate defensive action do you take?

---

## Component 2 — Live Demo

You will perform each task on a live lab environment. Screen-sharing required.
Time limit: 45 minutes total for all three tasks.

### Task 1 — Session Forgery (15 minutes)

**Setup:** A Flask app is running at `http://localhost:5000`.
The secret key is `dev_secret`.

**Task:** Forge a session cookie with `role=admin` and access `/admin`.

```bash
# Hint: the tool you need is flask-unsign
# Demonstrate: decode the current cookie, modify it, sign it, use it.
```

**Pass criteria:** Access `/admin` and return the flag from the response.

---

### Task 2 — JWT Algorithm Confusion (15 minutes)

**Setup:** A JWT API is running at `http://localhost:5001`.
The public key is at `http://localhost:5001/public.pem`.

**Task:** Log in as `alice`, then forge a JWT with `role=admin`
using the RS256→HS256 algorithm confusion attack.

**Pass criteria:** Access `/api/admin` and return the flag from the response.

---

### Task 3 — Linux Privilege Escalation (15 minutes)

**Setup:** SSH access to `localhost:2222` as `ctfplayer`.

**Task:** Escalate to root and read `/root/flag.txt`.

The examiner will tell you which single vector is present (cron, sudo, SUID,
or capability). You must execute the exploitation and read the flag.

**Pass criteria:** `cat /root/flag.txt` as root.

---

## Component 3 — Written Finding

### Instructions

Write one pentest finding for a vulnerability you discovered during the CTF
or live demos. The finding must meet professional pentest report standards.

### Required Sections

```markdown
## Finding: [Vulnerability Name]

### Severity
[Critical | High | Medium | Low | Informational]

### CVSS Score (approximate)
[e.g. 9.1 (Critical) — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N]

### CWE
[e.g. CWE-287: Improper Authentication]

### Description
[One paragraph: what the vulnerability is, where it exists in the application,
and what makes it exploitable.]

### Evidence
[HTTP request/response, command output, or code snippet showing the
vulnerability and its exploitation.]

### Impact
[One paragraph: what an attacker can do if this vulnerability is exploited.
Be specific: data accessed, actions taken, blast radius.]

### Remediation
[Specific code change, configuration, or control that fixes the root cause.
Not a generic "implement input validation" — the exact fix for this finding.]

### References
[CVE, CWE, OWASP reference, or relevant research.]
```

### Pass Criteria

| Criterion | Required |
|---|---|
| Vulnerability correctly named and categorised | Yes |
| Evidence is actual proof (not theoretical) | Yes |
| Impact is specific and accurate | Yes |
| Remediation is specific and correct | Yes |
| No factual errors | Yes |
| Professional writing (no typos, coherent) | Yes |

---

## Scoring

| Component | Pass Threshold |
|---|---|
| Oral Exam | 17 / 20 questions answered correctly |
| Live Demo | All 3 tasks completed within time limit |
| Written Finding | All 6 criteria met |

**All three components must pass. A fail on any component = full retake.**

---

## After Passing

You have completed the Foundation Track. You understand how systems work,
how attackers break them, and how defenders detect and stop the attack.

You are ready for the Offensive Track — Red Cell.

The first module, R-01, begins with reconnaissance: how to map an attack
surface you have never seen before, using only public information.

Everything from here is built on what you just proved you know.

---

## Retake Policy

- Oral exam: retake after 48 hours of review.
- Live demo: retake immediately (different challenge variant).
- Written finding: revise and resubmit within 24 hours.
- Full retake (failed 2+ components): one week before re-attempt.

---

## Questions

### Open Questions

*(none yet — add yours here)*

---

### Answered Questions

*(none yet)*

---

*Previous: [Day 049 — Foundation CTF Day](DAY-0049-Foundation-CTF-Day.md)*
*Next: Red Cell Module R-01 — Reconnaissance (Day 051)*
