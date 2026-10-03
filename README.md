# Project 3 — Organisation X SOC Endpoint & Log Analysis Framework

2-week SOC incident-response investigation (September 2026) spanning 250 Linux desktops
across 19 units. Verdict: a **multi-vector phishing / drive-by campaign** — **33 endpoints**
quarantined `FileType=Malicious` material (134 rows, 60 dedup endpoint+SHA), **2 AV-only
hosts** never reached quarantine, **8 C2 clusters** confirmed as per-victim beacon pairs.
Still-compromised hosts beaconed 1–3 weeks post-quarantine; USB is ruled out as the vector.
Report: `Latex/main.pdf` (12 pages, zero LaTeX overflows).

## Directory tree

```text
Log Analysis Report/                 # uv project: log-analysis-report
├── pyproject.toml                   # core: pandas, rich, matplotlib | group `full`: spec deps
├── main.py                          # CLI hub: triage | webc2 | timeline | report | ui
├── src/
│   ├── log_parser.py                # endpoint/usb ingestion + chunked web scans
│   ├── timeline_correlator.py       # delays, presence, quarantine first-seen
│   ├── anomaly_detector.py          # CONFIRMED_C2 map, AV gaps, USB verdicts
│   └── latex_generator.py           # report builder (via generate_latex.py)
├── ui/app.py                        # Streamlit dashboard (needs `full` extras)
├── scripts/run_all.py               # batch runner [--skip-web]
├── rich_triage.py                   # rich terminal tables [--abridged figure mode]
├── generate_latex.py                # Prism report source generator
├── gen_figures.py / gen_terminal_shot.py  # evidence PNGs -> Latex/images/
├── CONTEXT.md / AGENT.md            # forensic ledger + execution state
├── output/phase1_iocs.csv           # 60 dedup IOC rows
├── web_activity/{README.md,data/}   # endpoint_security.csv (23,540) + usb (8) +
│                                    # web_activity.csv (2,812,118 rows, Git LFS)
└── Latex/{main.tex,main.pdf,master.pdf,images/}  # report + style template + figures
```

## Methodology & log processing pipeline

| Stage | Module | Logic |
|---|---|---|
| Ingest | `log_parser` | `endpoint_security.csv` → quarantine (`FileType:` parse, dedup endpoint+SHA 134→60), AV (0 `FOUND`; 179 action rows/13 hosts), `web_block` (914 policy-noise rows); `usb_events.csv` (8 rows) |
| Web hunt | `log_parser` + `anomaly_detector` | Chunked pandas over 2.8M rows (19,027 uniq); strip `.hgu_lan/.bbrouter/.dlink/.local`; global message→endpoint cardinality, rare = eps≤3; **same-second domain+IP = one C2 session** |
| Anonymization model | `anomaly_detector` | Per-victim `svc-<hex>.gov.example` + `198.18.0.0/15` = C2; widespread `svc-*` = gov portals; Yahoo/`106.10.218.155` = mail CDN; `question`/`opt` = probes (all excluded with reasons) |
| Timeline | `timeline_correlator` | `event_time` with `received_time` band: quarantine med ~0h (max 203h), av_scan med 34h (max 562h), web_block med 21h; per-endpoint presence + quarantine first-seen |
| Reporting | `latex_generator` | `Latex/main.tex` (article 11pt, 0.85in, Prism palette, wrapped-monospace tables) → `latexmk` PDF |

## Chronological incident timeline & IoCs

| Timestamp | Event |
|---|---|
| 31-08 13:21 | `EPZRAPEL` hex-named file quarantined (pre-window); C2 follows 11–19 Sep |
| 02-09 | First xbel wave (`EPMQTKSL`, `EPC2L3UH` — 18 re-lists, heaviest; SHA `5e10b349…` ×9 hosts) |
| 03/07/08-09 | Lure + installer wave (Dash Camera, RAGHAV, printer binaries, Canon exe) |
| 10-09 11:22 | `EPSES7ZK` freshysearch hijacker chain starts (61/58/45/44 4-way bursts) |
| 11-09 | Peak: 20× bundle.js, `Final_Documents.zip`, Dash Camera pdf, `EPVC2P55`/`EPZRAPEL` C2 start |
| 12-09 | `EPLFOXSS` mail C2 (never quarantined); `EPWZ7L6L` staging; shared `n7093`/`n3618` active |
| 15-09 | Anydesk sessions post-zip; `Data1.cab` quarantined; `EPVSWBNA` banking (pre-infection) |
| 17–22-09 | Lakeside docs, `EPNPX6VY` DLL, HP×5 AV detect; `EPD24DBC` USB 22-09 (post-window, uncorroborated) |
| 23–26-09 | Tail quarantines (printer DLLs, libreoffice `.desktop` ×2, dash cam, xlsx/docx/so) |

C2 pairs: `svc-d44578`+`198.18.165.210`, `svc-148367`+`198.18.227.50`/`198.41.0.4`/`40.81.94.65`,
`svc-89bec8`+`198.18.251.94`, `svc-89a41f`+`198.18.40.61`, `svc-b76574`/`svc-171e30`,
freshysearch chain, Anydesk relays + `148.113.17.93/.8.189`, `n7093`/`n3618`+`34.93.158.11`
(co-suspects `EPCRFN4D`/`EPV7MB2K` share the cluster). Full table: `output/phase1_iocs.csv`.

## MITRE ATT&CK alignment & root cause

Lifecycle: **phishing/drive-by delivery → user execution → persistence + C2 beaconing**,
with AV-remediation gaps on 2 hosts and post-payload remote access on 1. USB and
`web_block` ruled out as vectors (evidence in `CONTEXT.md`).

| Technique | Name | Observed behaviour |
|---|---|---|
| T1566.001 | Spearphishing Attachment | Lure PDFs/DOCX/XLSX + evolution-mail payload (`EPLFOXSS`) |
| T1204.002 | Malicious File | User execution of quarantined payloads (docs, installers, `.desktop`, `.cab`) |
| T1036 | Masquerading | Legit names/paths reused (`recently-used.xbel`, `libreoffice-calc.desktop`, printer DLLs) |
| T1071.001 | Web Protocols | Per-victim C2 beacons + freshysearch redirect chain |
| T1219 | Remote Access Tools | Anydesk sessions post-payload (`EPGSQVEB`, 15/16/19 Sep) |
| T1574.002 | DLL Side-Loading (suspected) | Printer bundle layout (`launcher.exe` + `Strings.dll`/`zshp1020s.dll`) |

## Quickstart & reproducibility

```bash
uv sync                                        # core env (pandas, rich, matplotlib)
uv run python main.py triage                   # Phase 1 -> output/phase1_iocs.csv (60 rows)
uv run python main.py timeline                 # Phase 3: delays + presence + first-seen
uv run python main.py webc2                    # Phase 2: recount confirmed C2 (chunked scan)
uv run python main.py report [--compile]       # Phase 4: rebuild Latex/main.tex
uv run python scripts/run_all.py [--skip-web]  # batch runner
uv run python rich_triage.py [--abridged]      # rich terminal tables (screenshot mode)
uv sync --group full                           # production-spec extras (below), then:
uv run streamlit run ui/app.py                 # ...or: uv run python main.py ui
```

Production dependency spec (`pyproject.toml` group `full`, opt-in to keep default sync
light): polars, numpy, streamlit, plotly, scikit-learn, typer (+ core pandas, rich,
matplotlib). All timestamps local UTC+05:30. `web_activity.csv` (299MB) is Git-LFS-tracked.
MIT-licensed (see `LICENSE`).
