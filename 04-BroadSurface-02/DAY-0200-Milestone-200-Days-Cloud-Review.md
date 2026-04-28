---
title: "Milestone — Day 200: Cloud Review and Broader Programme Checkpoint"
tags: [milestone, review, cloud-security, progress-check, ATT&CK, kill-chain,
       curriculum-map, reflection, 200-days]
module: 04-BroadSurface-02
day: 200
related_topics:
  - All cloud security lessons (Days 181–199)
  - Cloud Security Review (Day 196)
  - All prior milestones
---

# Day 200 — Milestone: 200 Days

> "Two hundred days. Let me tell you what that means and what it does not mean.
> It means you have been consistent, and consistency is the only non-negotiable
> in this field. It does not mean you are done. The attack surface keeps expanding;
> the techniques keep evolving; the threat actors keep adapting. What changes at
> Day 200 is your baseline. You now have enough foundation to learn anything new
> faster than most people will ever learn it. That is what these two hundred days
> built. Use it."
>
> — Ghost

---

## Goals

Today is structured reflection, not new content. By end of day:

1. Map your current position in the curriculum accurately.
2. Identify your three strongest areas and your three weakest areas.
3. Run an untimed full cloud kill chain from memory.
4. Set the learning targets for Days 201–210 (the remaining cloud practice days).
5. Acknowledge what you have built and recalibrate for what comes next.

---

## Where You Stand: Curriculum Map

```
Days 001–030 — Foundation Track
  F-01: TCP/IP, DNS, TLS, HTTP         ✓
  F-02: Linux fundamentals              ✓
  F-03: Networking for attackers        ✓
  F-04: Cryptography essentials         ✓
  F-05: Web architecture                ✓
  F-06: Auth and authorisation models   ✓

Days 031–060 — Web Exploitation (Part 1)
  SQLi, XSS, CSRF, SSRF                ✓
  File upload, path traversal, XXE      ✓
  Labs: DVWA, custom apps               ✓

Days 061–090 — Web Exploitation (Part 2)
  HTTP smuggling, cache poisoning       ✓
  Business logic, race conditions       ✓
  CORS, WebSockets, host header         ✓

Days 091–120 — Web Exploitation (Part 3)
  OAuth, JWT attacks                    ✓
  Vulnerability chaining                ✓
  Bug bounty methodology                ✓

Days 121–160 — API Security
  OWASP API Top 10                      ✓
  GraphQL, REST exploitation            ✓
  API rate limiting, mobile API         ✓

Days 161–165 — Bug Bounty Reporting
  Finding report writing                ✓
  CVSS scoring                          ✓

Days 166–180 — Authentication Attacks
  Credential attacks, JWT/OAuth         ✓
  Active Directory attacks              ✓
  Auth hardening                        ✓

Days 181–200 — Cloud Security (in progress)
  AWS IAM, SSRF/IMDS, S3, Lambda       ✓
  Containers, Azure, GCP                ✓
  Cloud persistence, detection          ✓
  Cloud hardening                       ✓
  Practice: IAM privesc, S3, Lambda     ✓

Days 201–210 — Cloud Practice (remaining)
  Azure practice                        ☐
  GCP practice                          ☐
  Persistence detection practice        ☐
  CloudTrail evasion and hunting        ☐
  Bug bounty recon in the cloud         ☐
  Full kill chain simulation            ☐
  Cloud competency check                ☐

Days 211–270 — Network Exploitation (upcoming)
Days 271–330 — Privilege Escalation — Linux and Windows (upcoming)
Days 331–400 — Post-Exploitation and Red Team Operations (upcoming)
Days 401–500 — Defensive Track — Detection and IR (upcoming)
Days 501–600 — Advanced Track — Binary, Reversing, Mobile (upcoming)
Days 601–730 — Ghost Level (upcoming)
```

---

## Self-Assessment: Cloud Module

Rate yourself 1–5 on each topic (1 = need to review; 5 = can explain, exploit,
detect, and fix without notes):

```
AWS IAM Fundamentals
  [ ] IAM policy document structure and evaluation order         /5
  [ ] Difference between identity-based and resource-based       /5
  [ ] Trust policies and when they apply                         /5

IAM Privilege Escalation
  [ ] CreatePolicyVersion path                                   /5
  [ ] PassRole + Lambda path                                     /5
  [ ] Role chaining                                              /5

SSRF to IMDS
  [ ] IMDSv1 exploitation steps                                  /5
  [ ] IMDSv2 token flow                                          /5
  [ ] Identifying SSRF entry points                              /5

S3 Attacks
  [ ] Enumerating buckets (authenticated and unauthenticated)    /5
  [ ] Exploiting public ACL vs public bucket policy              /5
  [ ] Terraform state file extraction                            /5

Lambda Attacks
  [ ] GetFunctionConfiguration for secret theft                  /5
  [ ] Command injection via event payload                        /5
  [ ] SSRF via Lambda event                                      /5

Container Attacks
  [ ] ECS task metadata credential theft                         /5
  [ ] Privileged container escape                                /5
  [ ] Docker socket escape                                       /5

Azure
  [ ] IMDS with Metadata: true header                            /5
  [ ] Managed identity token for management vs graph             /5
  [ ] Blob public access exploitation                            /5

GCP
  [ ] Metadata endpoint and Metadata-Flavor header               /5
  [ ] serviceAccountTokenCreator escalation                      /5
  [ ] GCS allUsers/allAuthenticatedUsers                         /5

Cloud Persistence
  [ ] Backdoor IAM user                                          /5
  [ ] Cross-account role with ExternalId                         /5
  [ ] Lambda beacon with EventBridge                             /5
  [ ] Shadow access key                                          /5

Detection and Hardening
  [ ] CloudTrail key fields for detection                        /5
  [ ] Writing Sigma rules for cloud events                       /5
  [ ] IMDSv2 enforcement methods                                 /5
  [ ] SCP to protect security services                           /5
  [ ] S3 Block Public Access (account level)                     /5
```

**Scoring:**
- 90+ total points: Cloud-ready — move through practice days at pace
- 70–89: Solid foundation — revisit your lowest-scoring topics before competency check
- <70: Spend additional days on the weakest areas before Days 209–210

---

## Full Kill Chain — Untimed Memory Exercise

Close your notes. Reproduce the full AWS cloud kill chain from scratch:

```
Phase 1 — Initial Access
  How did you get your initial foothold? (SSRF, credential leak, public bucket?)
  What was the SSRF vector? What URL did you probe first?

Phase 2 — Credential Extraction
  What IMDS endpoint? What HTTP method for IMDSv1 vs IMDSv2?
  What JSON fields contain the temporary credentials?
  How do you set them as environment variables?

Phase 3 — Enumeration
  First command after setting credentials. Why?
  How do you map available permissions without triggering access denied logs?
  What Pacu module? What manual equivalent?

Phase 4 — Privilege Escalation
  Which permissions did you have? Which escalation path did you choose?
  What are the exact API calls for CreatePolicyVersion escalation?
  What are the exact API calls for PassRole + Lambda escalation?

Phase 5 — Data Exfiltration
  How do you list and download S3 data?
  How do you extract Lambda secrets?
  How do you enumerate Secrets Manager?

Phase 6 — Persistence
  Which persistence mechanism? What does it survive?
  How would a defender detect your backdoor user?
  How would a defender detect your cross-account role?
```

Write your answers out fully before checking Day 192 or Day 196.

---

## Progress Perspective

### What 200 Days of Consistency Has Built

| Area | Before | Now |
|---|---|---|
| Web exploitation | Unknown | Full OWASP coverage, chaining, PoC reports |
| API security | Unknown | OWASP API Top 10, GraphQL, mass assignment |
| Authentication | Unknown | JWT/OAuth attacks, AD attacks, hardening |
| Cloud security | Unknown | Full AWS kill chain, Azure, GCP, persistence |
| Reporting | Unknown | Professional finding reports with CVSS |
| Detection | Unknown | Sigma rules, CloudTrail analysis, GuardDuty |

### What the Next 530 Days Will Add

| Days | Area | What changes |
|---|---|---|
| 211–270 | Network exploitation | You think at the packet level |
| 271–330 | Privilege escalation | Linux and Windows host compromise |
| 331–400 | Post-exploitation | Full red team operations |
| 401–500 | Defensive track | Detection, IR, threat hunting from the blue side |
| 501–600 | Advanced track | Binary exploitation, reversing, mobile |
| 601–730 | Ghost Level | Vulnerability research, zero-day mindset |

---

## Three Questions Before You Continue

Answer these without opening any reference material:

1. A company's cloud architecture uses EC2 behind an ALB with a `/fetch?url=`
   endpoint. IMDSv1 is enabled. Walk through the complete attack chain — every
   API call — from initial access to confirmed admin access.

2. You are the defender. CloudTrail fires an alert at 3:47 AM: `CreateUser`
   followed by `AttachUserPolicy` (AdministratorAccess) followed by
   `CreateAccessKey`. The calling identity is `arn:aws:sts::123456789012:
   assumed-role/ec2-webapp-role/i-0abc`. List your first five IR actions
   with the exact AWS CLI commands.

3. Name the five cloud hardening controls in priority order with the single
   attack class each one directly prevents.

---

## Setting Targets for Days 201–210

Based on your self-assessment scores, set a target for each remaining day:

| Day | Topic | Your focus based on gaps |
|---|---|---|
| 201 | Azure practice | Managed identity, Blob, AAD enumeration |
| 202 | GCP practice | Service account escalation, GCS, metadata |
| 203 | Cloud persistence detection | Hunt for your own backdoor artefacts |
| 204 | CloudTrail evasion and hunting | Write the detection that catches evasion |
| 205 | Cloud bug bounty recon | SSRF + S3 enumeration against a real programme |
| 206 | HTB cloud challenges | Speed and problem-solving under pressure |
| 207 | TryHackMe cloud rooms | Fill knowledge gaps from self-assessment |
| 208 | Full kill chain simulation | End-to-end with documentation |
| 209 | Report writing | Professional report for the Day 208 engagement |
| 210 | Cloud competency check | Gate assessment |

Write down the two topics where your self-assessment score was lowest.
Those are your priority for Days 201–210.

---

## Key Takeaways

1. **Consistency at 200 days means you have developed a security mindset**, not
   just memorised techniques. Techniques expire; the mindset for learning new
   techniques does not.
2. **Self-assessment is only useful if it is honest.** A 5/5 that you gave
   yourself without running the exploit will cost you on the competency check.
   Rate what you can actually do, not what you have read.
3. **The cloud kill chain is the same pattern as every other kill chain:** access →
   credential → enumerate → escalate → exfiltrate → persist. The service names
   change across AWS/Azure/GCP. The logic does not.
4. **The next major skill gap is host-level exploitation.** Web and cloud give you
   initial access. Network and privilege escalation give you the rest of the
   environment. Days 211–330 close that gap.
5. **You are now capable of doing real damage in an authorised engagement.** That
   means the ethical responsibility has also increased. Stay within scope. Document
   everything. Report what you find.

---

## Exercises

1. Complete the full self-assessment grid honestly. Identify your three lowest-
   scoring areas. Write a plan for how you will improve each before Day 210.
2. Run the untimed kill chain exercise. Time yourself anyway. Where did you hesitate?
   Those hesitation points are the gaps to fill.
3. Write a one-paragraph reflection: what was the hardest thing you learned in
   the cloud module and why? What clicked that you did not expect?
4. Research: what is coming in Days 211–270 (Network Exploitation)? Read the
   SYLLABUS. Identify two tools and two techniques you have never used. Start a
   note for Day 211 setup.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q200.1, Q200.2 …).
> Follow-up questions use hierarchical numbering (Q200.1.1, Q200.1.2 …).

---

## Navigation

← Previous: [Day 199 — Cloud Practice: Lambda and Serverless](DAY-0199-Cloud-Practice-Lambda-Serverless.md)
→ Next: [Day 201 — Cloud Practice: Azure](DAY-0201-Cloud-Practice-Azure.md)
