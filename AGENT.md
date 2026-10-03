# AGENT.md — Execution State & Roadmap (Organisation X DFIR)

_Last updated: 2026-10-03 (UTC) — existing uv env only (extra dir removed); Phases 1–2 re-verified in place_

## Current status
- Phase 1 (endpoint_security.csv + usb_events.csv triage): DONE.
- Phase 2 (web_activity.csv bulk analysis): DONE (chunked pandas, C2 confirmed).
- Phase 3 (timeline reconstruction): DONE (delay stats + per-host beacon timelines).
- Phase 4/5 (final CONTEXT update + incident report): DONE — see chat report below.

## Completed steps
1. Read README.md, usb_events.csv (8 rows), SHA256SUMS.
2. endpoint_security.csv (23,540 rows: 20,004 quarantine / 2,622 av_scan / 914 web_block, 247 endpoints, 19 units).
3. Parsed quarantine correctly via `FileType: ([^|]+)`:
   - 134 rows with `FileType == Malicious` across **33 endpoints** (dedup list in CONTEXT.md).
   - 23 rows type/extension quarantines (benign .desktop files) — ruled non-malicious.
   - Remainder (19,847) are `No Malicious files found.` re-list noise.
4. Parsed av_scan:
   - 0 `FOUND` signature lines; all `Knownviruses` summaries show `Infectedfiles:0`.
   - 179 action rows (`Beginning quarantine / Processing / Attempting / Quarantined and deleted / File not found`) across 13 endpoints.
   - 2 AV-only endpoints with NO malicious quarantine: EPAX5P5D (host-0b21, xbel) + EPLFOXSS (host-423b, evolution mail `1773731387.41169_0.EPLFOXSS` persistently `File not found` 01–19 Sep) — flagged as still-active/unquarantined.
5. Parsed web_block (914 rows, 74 endpoints): top = www.googleapis.com (347), www.facebook.com (179), api.ipify.org (142) — assessed as corporate policy blocks, NOT IOCs. 14/33 malicious endpoints overlap web_block; not diagnostic.
6. Parsed usb_events.csv: only EPD24DBC (host-7394, unit-foxtrot, Mass Storage abcd:1234, 22-09 18:23) + EP7FZ2XY (Logitech mouse 046d:c077, benign). Neither USB endpoint appears in Malicious/AV lists — requires web_activity pivot to rule out USB drop that evaded AV.
7. Extracted per-endpoint malicious file/hash ledger (see CONTEXT.md) + AV-handling ledger.

## Pending tasks
- [x] P2.1: Chunked pandas scan of web_activity.csv (2.8M rows): strip `.hgu_lan/.bbrouter/.dlink/.local`, extract IP-literals, rare domains, high-frequency beacons per suspect endpoint.
- [x] P2.2: Pivot suspect endpoints (33 mal + 2 AV-only + 1 USB EPD24DBC + EPLFOXSS) vs baseline: rare-domain analysis, C2 candidate scoring.
- [x] P2.3: Check web contacts before/after quarantine `Quarantined At` times.
- [x] P3: Build per-endpoint timeline (USB/Web visit → download → AV/quarantine → C2), compute event_time vs received_time skew.
- [x] P3b: Cross-endpoint campaign IOC clustering (shared hash 5e10b349..., shared C2).
- [x] P4/5: Finalize CONTEXT.md + write incident report (executive summary, narrative, remediation).
- [x] Engine: `cyber_forensics_engine/` scaffolded (uv, src/ x5, ui/, tests/), `triage`+`verify` pass, `pytest` 2 passed, `output/INCIDENT_REPORT.md+iocs.csv` generated.
- [x] Cleanup 2026-10-03: extra `cyber_forensics_engine/` removed per instruction; `uv sync` + `uv add pandas` in existing project; Phase 1 re-verified in place (23,540 rows / 134 Malicious / 33 endpoints / 0 FOUND / AV 179+13 / web_block 914+74 / USB 8, no overlap); Phase 2 spot-check reproduced C2 counts (svc-d44578 50, 198.18.165.210 43, svc-148367 152, 198.18.227.50 144, svc-89bec8 35, svc-89a41f 20, 198.18.40.61 18, freshysearch 61, anydesk relay 4, n7093 213; web 2,812,118 rows). No extra envs.
- [x] Phase 1 files: `phase1_triage.py` + `output/phase1_summary.md` + `output/phase1_iocs.csv` (60 dedup rows) generated via `uv run python phase1_triage.py`.
- [x] Phase 4 Prism LaTeX: `rich_triage.py` (rich tables) + `generate_latex.py` + `Latex/main.tex` (article, 0.85in, Prism palette, cover, TOC, TikZ 4-stage flowchart, longtable/tabularx with wrapped monospace, images/ placeholders) compiled via latexmk to `Latex/main.pdf` (8 pages, zero Overfull, zero errors).
- [x] Master-alignment refactor: Slave rewritten to Master (Challenge 1) structure/tone — centered cover + EXECUTIVE RISK OVERVIEW badges ([HIGH]/[MEDIUM]/[INFO]), navy TOC with rule, running header, Executive Summary + Risk Assessment + Key Concepts primer, Tools, Methodology (Analysis/Finding/Outcome), Timeline table, Step-by-Step with architecture TikZ + code boxes + real figures (`gen_figures.py` → `images/c2_beacon.png`, `timeline.png`), condensed findings, MITRE map (T1566.001/T1204.002/T1036/T1071.001/T1219/T1574.002-suspected), Appendix A 60-row IOCs + Appendix B reproducibility. Clean rebuild: `Latex/main.pdf` 10 pages, zero Overfull, zero errors.
- [x] Structured risk blocks (cover + leadership table with pill badges); Fig 1 respaced (7.5in) + pinned inline; vspace/page-break tweaks; `gen_terminal_shot.py` renders `rich_triage.py --abridged` (48-line one-page figure) → `images/triage_tables.png` embedded. Final: `Latex/main.pdf` 12 pages, zero Overfull, zero errors, all 3 figures embedded.

## Planned scripts / queries
- `py` chunked reader: `pd.read_csv(..., chunksize=200k, usecols=[endpoint_id,message])` — normalize: lower, strip LAN suffixes via regex `\.(hgu_lan|bbrouter|dlink|local)$`, split port.
- Frequency tables: global message counts vs per-suspect counts; IP regex `^\d+\.\d+\.\d+\.\d+$`.
- Beacon detection: group by (endpoint_id, cleaned_domain) count + time-span.
- Targeted dumps for: EPZRAPEL, EPLFOXSS, EPD24DBC, EP4YIFHV, EPVSWBNA, EPSES7ZK/EPQKOBYG, EPC2L3UH cluster.

## Hypotheses / open questions
- H1: `recently-used.xbel` SHA 5e10b349... across 9 endpoints = either widespread FP or worm-like payload reusing legit path — needs web pivot to decide. Currently treated as COMPROMISED (AV quarantined as Malicious) but confidence MEDIUM.
- H2: EPLFOXSS mail file = phishing initial access, AV failed (`File not found`), still compromised — needs web_activity confirmation.
- H3: EPD24DBC USB Mass Storage 22-09 = possible USB drop with no AV detection — needs web_activity + timeline check.
- H4: web_block = noise (not IOCs). True C2 likely in `web` log as unblocked IP/DDNS/suspicious TLD.
- H5: EP4YIFHV 20x `.bundle.js` + EPVSWBNA printer DLLs + HP printer EXEs = drive-by / trojanized installer vectors, not USB.
