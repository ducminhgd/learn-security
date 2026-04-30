---
title: "Community and Resources — Twitter/X, Discord, HackerOne Community, Blogs"
tags: [community, resources, Twitter, X, Discord, HackerOne, blogs, researchers,
       networking, learning, podcasts, bug-bounty, operations]
module: 05-BugBountyOps-01
day: 274
related_topics:
  - Portfolio and Reputation Building (Day 272)
  - Studying Public Disclosures (Day 271)
  - Bug Bounty Methodology Synthesis (Day 275)
---

# Day 274 — Community and Resources

> "Security is a small world. The researchers you interact with online today
> are the ones who will invite you to private programmes, refer you for jobs,
> and co-author papers in five years. Engage seriously. Be generous with
> knowledge. Credit others' work. The community returns what you put in."
>
> — Ghost

---

## Goals

By the end of today's session you will be able to:

1. Identify the core community channels and their distinct character.
2. Build your professional presence on the channels that matter.
3. Distinguish high-signal resources from noise.
4. Apply a daily reading system that keeps you current without overwhelming you.
5. Engage constructively with the bug bounty community.

**Time budget:** 2–3 hours.

---

## Part 1 — Twitter / X

Twitter/X remains the fastest source of security research news and technique
sharing. New vulnerabilities, new tools, new disclosures — all appear on
Twitter before anywhere else.

### Who to Follow (Starting List)

Research and offensive techniques:
- `@LiveOverflow` — education, CTF, research
- `@NahamSec` — bug bounty methodology, streams, tips
- `@tomnomnom` — tools, recon, Go tooling for bug bounty
- `@streaak` — automation, methodology
- `@j3ssiejjj` — API security, recon
- `@Jhaddix` — methodology, recon, talks
- `@hacker0x01` — HackerOne news
- `@bugbountyforum` — programme news, tips

Platform and programme announcements:
- `@Hacker0x01` — HackerOne platform news
- `@Bugcrowd` — Bugcrowd news
- `@intigriti` — Intigriti news

Defensive / research balance:
- `@ProjectDiscovery` — Nuclei, httpx, subfinder updates
- `@PortSwigger` — Burp research blog updates
- `@_GoogleProject0` — Project Zero disclosure announcements

### Twitter Engagement Principles

- Do not comment on active bugs or techniques on public targets.
- Credit others when you use their technique, tool, or methodology.
- Share your own write-ups and CTF solutions — this builds visibility.
- Do not publicly call out specific researchers for bad practice.
  Handle disputes privately or through platform mediation.

---

## Part 2 — Discord Servers

Discord is where the real-time community conversations happen.

### Key Servers

| Server | Focus | Signal quality |
|---|---|---|
| HackerOne Community | Bug bounty, methodology, programme discussion | High |
| Bugcrowd Community | Bugcrowd-specific, methodology | High |
| NahamSec / NahamCon | Bug bounty education, NahamCon CTF announcements | High |
| Bug Bounty World | General BB discussion, tips, team-ups | Medium |
| TryHackMe | Education, CTF, beginners | Medium |
| HackTheBox | CTF, advanced practice | Medium |

### How to Use Discord Effectively

- **Lurk before posting.** Understand the culture and norms before
  participating.
- **Search before asking.** Your question has probably been asked before.
- **Contribute when you can.** If you know the answer to someone's question,
  answer it. This builds your reputation without requiring a write-up.
- **Private channels matter.** Many Discord servers have invite-only channels
  for trusted researchers. These are earned, not requested.

---

## Part 3 — Blogs and Written Resources

### Tier 1 — Regular, High-Quality Original Research

These publish original vulnerability research that moves the field:

- **PortSwigger Research** — portswigger.net/research
  (HTTP request smuggling, web cache poisoning, JWT attacks — all PortSwigger
  research)

- **Project Zero** — googleprojectzero.blogspot.com
  (Memory corruption, browser exploitation, real zero-days with full disclosure)

- **Orange Tsai's Blog** — blog.orange.tw
  (SSRF + cloud, new attack classes, conference-quality research)

- **James Kettle** — portswigger.net/research/james-kettle
  (Original research on HTTP smuggling, cache poisoning, CORS)

### Tier 2 — Bug Bounty Write-ups and Methodology

- **HackerOne Hacktivity** — disclosed reports (see Day 271)
- **Pentester Land** — pentester.land (curated write-up list)
- **BugBountyHunter (nahamsec)** — resources.nahamsec.dev
- **Bug Bounty Forum** — bugbountyforum.com
- **Detectify Blog** — blog.detectify.com (web security research)

### Tier 3 — Tool Documentation

Always read the docs for every tool you use:
- Nuclei docs: nuclei.projectdiscovery.io/docs
- ffuf wiki: github.com/ffuf/ffuf/wiki
- Burp documentation: portswigger.net/burp/documentation

---

## Part 4 — Podcasts and Video

For passive learning during commute / exercise:

| Resource | Format | Best for |
|---|---|---|
| Darknet Diaries | Podcast | Real-world breach stories, attacker narratives |
| Risky Business | Podcast | Security industry news, threat intelligence |
| Smashing Security | Podcast | Current events, accessible |
| HackTheBox Academy | Video/Lab | Structured learning, strong on technique |
| LiveOverflow | YouTube | Deep dives, binary exploitation, CTF |
| NahamSec | YouTube/Twitch | Bug bounty live streams, methodology |
| IppSec | YouTube | HackTheBox machine walkthroughs |

---

## Part 5 — Daily Reading System

Too much information creates noise. Apply a focused daily system.

### Morning Routine (15–20 minutes, before testing)

```
1. Hacktivity filter: last 7 days, High + Critical — read 3 reports (10 min)
2. Twitter/X feed: scan for new tool releases, new CVEs, new write-ups (5 min)
3. Discord: check #announcements channels on key servers (2 min)
```

### Weekly Batch (60 minutes, once per week)

```
1. PortSwigger Research — check for new publications
2. Google Project Zero — check for new disclosures
3. One deep-dive write-up from Pentester Land list
4. Update Nuclei templates: nuclei -update-templates
5. Check for new programme launches on HackerOne + Bugcrowd
```

### Monthly Batch (2–3 hours, once per month)

```
1. Technique radar review — update based on what you read this month
2. Programme allocation review — is current time distribution optimal?
3. Blog post from any major researcher (Orange Tsai, James Kettle, etc.)
4. One research paper or conference talk (Black Hat / DEF CON archive)
```

---

## Part 6 — Community Engagement Do's and Don'ts

### Do

- Share your own write-ups with credit to tools and prior work you built on.
- Ask specific, well-researched questions.
- Acknowledge when someone else found or published the technique first.
- Help new researchers who are genuinely stuck.
- Participate in community CTFs (NahamCon, HackerOne CTF, BSides CTFs).

### Do Not

- Disclose active, unreported vulnerabilities in public channels.
- Ask for help exploiting a specific live programme — this is soliciting others
  to participate in unauthorised access.
- Share credentials, API keys, or any data found during research.
- Copy another researcher's write-up without attribution.
- Post about "I got a critical on [company] — still triaging" before disclosure.
  This telegraphs the vulnerability before the company can fix it.

---

## Key Takeaways

1. **PortSwigger Research is the most valuable single source for web
   exploitation technique depth.** Every major web technique taught in
   Days 126–145 originated or was extensively documented there. Read it weekly.
2. **Twitter moves fast; quality is inconsistent.** The signal is new tool
   releases, new CVEs, and new write-up announcements. Filter aggressively.
   Follow researchers with a track record of original work.
3. **Discord is for real-time community — it is not for learning techniques.**
   Use it to stay connected, find collaborators, and get quick answers.
   Do not use it as a substitute for reading the actual research.
4. **Community reputation travels.** Being known as someone who gives thoughtful
   answers, credits others' work, and produces quality write-ups opens doors
   that skill alone cannot open.
5. **Information diet matters.** The researchers who learn fastest are not the
   ones who consume the most content — they are the ones who read selectively
   and apply what they read immediately.

---

## Exercises

1. Set up the morning routine from Part 5. Run it every day for the next
   week. After 7 days: (a) What techniques did you learn from Hacktivity?
   (b) What new tools or disclosures appeared on Twitter? (c) Did any
   reading directly influence what you tested that day?

2. Create or update your Twitter/X profile with a security focus. Follow
   the starter list from Part 1. Identify 5 more researchers not on the
   list whose work is directly relevant to your specialisation area.

3. Join the HackerOne Community Discord or Bug Bounty World Discord.
   Spend 30 minutes reading existing conversations before posting anything.
   Find one thread where you can contribute a useful answer.

4. Research the DEF CON 32 (or most recent) presentations archive.
   Find one talk directly relevant to a vulnerability class you specialise in.
   Write a 3-paragraph summary of the key contribution and how you would
   apply it to your testing methodology.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q274.1, Q274.2 …).
> Follow-up questions use hierarchical numbering (Q274.1.1, Q274.1.2 …).

---

## Navigation

← Previous: [Day 273 — Earnings Optimisation](DAY-0273-Earnings-Optimisation.md)
→ Next: [Day 275 — Bug Bounty Methodology Synthesis](DAY-0275-Bug-Bounty-Methodology-Synthesis.md)
