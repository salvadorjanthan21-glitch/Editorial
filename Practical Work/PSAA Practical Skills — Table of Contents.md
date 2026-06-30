

This is the hands-on companion to the Theory Heatmap. Where that document tracks _concepts_, this tracks _actions_ — the things you should be able to actually do, under time pressure, with no reference material open. Work through it roughly in the order a real ticket investigation would unfold.

---

## 1. Environment & Workflow Orientation — _(Ch1)_

- Navigate the provided SIEM workspace cold; locate raw log tables without hunting
- Set up a running evidence/notes log per ticket (you'll need this for the report later)
- Run the 7-step triage flow end-to-end on a sample alert: Review → Classify → Correlate → Enrich → Assess → Investigate → Verdict

## 2. Email & Phishing Investigation — _(Ch2–Ch3)_

- Open a raw email source / `.eml` file and read it as raw text, not a rendered preview
- Trace the `Received:` header chain backward to find the true originating IP
- Read `Authentication-Results` and call SPF/DKIM/DMARC as pass / fail / none from the raw header, not a summary tool
- Extract URLs and attachments; submit to VirusTotal / URLScan.io and interpret the verdict
- Decide and execute a reactive response: search & purge, sender block, `Remove-InboxRule`

## 3. Network Traffic Analysis — _(Ch3–Ch4)_

- Build Wireshark display filters from scratch (`ip.addr`, `http.request`, `dns`, `tcp.flags`)
- Use "Follow TCP/HTTP Stream" to reconstruct a full session
- Write tcpdump/BPF capture filters
- Identify beaconing intervals (time-delta patterns) consistent with C2
- Identify DNS tunneling (query length/entropy anomalies)
- Read a Snort rule, write one from a description, and correlate a triggered alert back to the PCAP

## 4. SIEM / KQL Querying — _(Ch5–Ch6)_

- Write `where`, `summarize`, `join`, `union` queries from a blank query box — not just read pre-built ones
- Reproduce, from memory, the query pattern for each of the 7 SIEM use cases: brute-force, impossible travel, data exfiltration, privilege escalation, lateral movement, C2, insider threat
- Pivot a single IOC (IP, user, hash) across `SigninLogs`, `SecurityEvent`, and `OfficeActivity`

## 5. Windows Endpoint Forensics — _(Ch4–Ch5)_

- Filter Event Viewer / exported logs for 4624, 4625, 4688, 4104 and explain what triggered each
- Read Sysmon EID 1, 3, 7, 8, 11, 22 entries and state what each represents in plain language
- Locate and interpret Prefetch, Amcache, Shellbags, and LNK files
- Check Registry Run keys, Scheduled Tasks, and Services (EID 7045) for persistence mechanisms

## 6. Linux Endpoint Forensics — _(Ch5)_

- Read `/var/log/auth.log` and identify auth-related events
- Run `last` / `lastb` to reconstruct login history
- Search `.bash_history` for attacker-run commands
- Inspect crontab and systemd timers for persistence

## 7. Memory & Disk Forensics — _(Ch7)_

- Run Volatility 3: `windows.pstree`, `windows.netscan`, `windows.malfind` against a sample image and interpret output
- Acquire or inspect an image using FTK Imager or `dd`
- Document chain of custody for a piece of evidence correctly

## 8. EDR Investigation — LimaCharlie — _(Ch5)_

- Read an existing D&R rule and explain its logic
- Write a basic D&R rule from a detection requirement
- Run an LCQL query against telemetry and trace a process tree through the stream

## 9. Threat Intelligence Enrichment — _(Ch7)_

- Enrich an IP, hash, or domain through VirusTotal, AbuseIPDB, and URLScan.io
- Place an indicator on the Pyramid of Pain and justify why
- Map a confirmed behavior to its MITRE ATT&CK technique ID (e.g., T1059.001, T1110, T1071.001)

## 10. Containment, Eradication & Recovery — _(Ch6)_

- Execute `Disable-NetAdapter` and `Revoke-AzureADUserAllRefreshToken` against a compromised account/host
- Remove a malicious scheduled task (`schtasks /Delete`) and a malicious inbox rule

## 11. Report Writing — Deliverable Construction — _(Ch1, Ch8)_

- Draft an Executive Summary in plain, non-technical language for a non-analyst reader
- Build a timeline that merges evidence from multiple sources into one coherent sequence
- Build the ATT&CK technique table directly from your investigation notes
- Build the IOC table
- Write Recommendations that tie back to a specific failed/missing control (not generic advice)

## 12. Exam-Day Practical Workflow — _(Ch8)_

- Practice time-boxing: decide in advance roughly how long each ticket gets inside the 48-hour window
- Decide your ticket order strategy (easy-first to build momentum vs. hardest-first while fresh)
- Keep the evidence log current _as you investigate_ — don't try to reconstruct it from memory when you sit down to write the report

---

_Pair each section here with its matching row in the Theory Heatmap — the theory tells you what something is, this tells you what to be able to do with it under exam conditions._