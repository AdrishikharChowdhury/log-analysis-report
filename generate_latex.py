"""Generate Latex/main.tex — Master-aligned Prism report (Organisation X endpoint forensics).
Run: uv run python generate_latex.py   (then latexmk -pdf Latex/main.tex from Latex/)
"""
import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parent
IOC_CSV = ROOT / "output" / "phase1_iocs.csv"
TEX = ROOT / "Latex" / "main.tex"


def _esc(t: str) -> str:
    out = t
    for a, b in [("&", "\\&"), ("%", "\\%"), ("$", "\\$"), ("#", "\\#"),
                 ("_", "\\_"), ("{", "\\{"), ("}", "\\}"),
                 ("~", "\\textasciitilde{}"), ("^", "\\textasciicircum{}")]:
        out = out.replace(a, b)
    return out


def esc(s: str) -> str:
    return _esc(s)


def _break_raw(tok: str, chunk: int) -> str:
    return "\\allowbreak{}".join(_esc(tok[i:i + chunk]) for i in range(0, len(tok), chunk))


def mono_wrap(raw: str, chunk: int = 8) -> str:
    toks = []
    for w in raw.split(" "):
        if "/" in w:
            subs = w.split("/")
            toks.append("/\\allowbreak{}".join(
                _break_raw(s, chunk) if len(s) > chunk else _esc(s) for s in subs))
        else:
            toks.append(_break_raw(w, chunk) if len(w) > chunk else _esc(w))
    cur, parts = "", []
    for tok in toks:
        cur = (cur + " " + tok).strip() if cur else tok
        if len(cur) > 30:
            parts.append(cur)
            cur = ""
    if cur:
        parts.append(cur)
    return "{\\ttfamily\\scriptsize\\raggedright " + " ".join(parts) + "\\par}"


def cell(s: str) -> str:
    return "{\\small\\raggedright " + esc(s) + "\\par}"


rows = list(csv.DictReader(open(IOC_CSV, encoding="utf-8")))
verdict = {
    "EPZRAPEL": "Still compromised", "EPVC2P55": "Still compromised",
    "EPT3KTUL": "Still compromised", "EPLFOXSS": "Active (never quarantined)",
    "EPWZ7L6L": "Compromised", "EPSES7ZK": "Hijacker + installer",
    "EPGSQVEB": "Remote-access persist", "EPFQSCDV": "Compromised + 2 co-suspects",
    "EPVSWBNA": "Compromised, C2 unknown", "EPMQTKSL": "File, likely cleaned",
    "EP4YIFHV": "Then cleaned", "EPD24DBC": "Monitor (USB uncorroborated)",
}
seen, cluster_rows = set(), ""
for r in rows:
    ep = r["endpoint_id"]
    if ep in seen:
        continue
    seen.add(ep)
    first = next(x for x in rows if x["endpoint_id"] == ep)
    cluster_rows += (f"{cell(ep)} & {cell(first['endpoint_name'])} & {cell(first['unit'])} & "
                     f"{mono_wrap(first['fname'])} & {cell(verdict.get(ep, 'Compromised; no web persist'))} \\\\\n\\hline\n")

ioc_rows = ""
for r in rows:
    ioc_rows += (f"{cell(r['endpoint_id'])} & {mono_wrap(r['fname'])} & "
                 f"{mono_wrap(r['sha'], 8)} \\\\\n\\hline\n")

# Condensed per-cluster findings (Section 6)
findings = [
    ("EPZRAPEL", "53EDA42869D4... (hex-named)", "svc-d44578 (50) + 198.18.165.210 (43); 11-19 Sep pairs", "Persists 3 wks post-quarantine"),
    ("EPVC2P55", "Data1.cab", "svc-148367 (152) + 198.18.227.50 + 198.41.0.4 + 40.81.94.65", "C2 after 15-09 quarantine"),
    ("EPT3KTUL", "Dash Camera-49600.00.pdf", "svc-89bec8 (35) + 198.18.251.94 + n7473 sub", "Persists to 20-09"),
    ("EPLFOXSS", "Evolution-mail payload (unquarantined)", "svc-89a41f (20) + 198.18.40.61 (18)", "AV File-not-found 01-19 Sep"),
    ("EPWZ7L6L", "ops-electron-app.desktop", "svc-b76574 (13) + svc-171e30 (10) + n2b40", "Staged pre-25-09 file"),
    ("EPSES7ZK", "hp_LJ1020 x5 (same SHA)", "freshysearch + search.freshy + searchtabnew + cloudfront", "Hijacker + installer"),
    ("EPGSQVEB", "Final_Documents.zip", "Anydesk relays + 148.113.17.93/.8.189", "Sessions post-payload"),
    ("EPFQSCDV", "recently-used.xbel", "n7093 (188) + n3618 (184) + 34.93.158.11; shared eps3", "2 co-suspects triage"),
    ("Others (25)", "xbel / lure docs / printer / desktop / cab / dll", "No unique beacon in window", "File evidence; cleaned or out-of-window"),
]
find_rows = ""
for e, p, c, v in findings:
    find_rows += f"{cell(e)} & {mono_wrap(p, 10)} & {mono_wrap(c, 12)} & {cell(v)} \\\\\n\\hline\n"

mitre = [
    ("T1566.001", "Spearphishing Attachment", "Lure PDFs/DOCX/XLSX (Dash Camera, RAGHAV, Lakeside, RETIREES, Staff Library) and the evolution-mail payload on EPLFOXSS."),
    ("T1204.002", "Malicious File", "User execution of quarantined payloads: documents, HP/printer installers, .desktop launchers, Data1.cab, Anydesk-linked zip."),
    ("T1036", "Masquerading", "Payloads reuse legitimate names and paths: recently-used.xbel, libreoffice-calc.desktop, printer DLL names, ops-electron-app.desktop."),
    ("T1071.001", "Web Protocols", "Per-victim C2 beacons (svc-<hex>.gov.example + 198.18.x.x same-second pairs) and the freshysearch redirect chain."),
    ("T1219", "Remote Access Tools", "Anydesk relay sessions on EPGSQVEB on 15/16/19 Sep, all after the 11-09 payload quarantine."),
    ("T1574.002", "DLL Side-Loading (suspected)", "Trojanized printer bundle layout on EPVSWBNA (launcher.exe with Strings.dll / zshp1020s.dll); unconfirmed at dynamic level."),
]
mitre_rows = ""
for t, n, b in mitre:
    mitre_rows += f"{cell(t)} & {cell(n)} & {cell(b)} \\\\\n\\hline\n"

timeline = [
    ("31-08 13:21", "EPZRAPEL file quarantined (pre-window)", "53EDA42869D4... hex-named file; C2 follows 11-19 Sep."),
    ("02-09", "First xbel wave", "EPMQTKSL + EPC2L3UH (18 re-lists, heaviest) share SHA 5e10b349...."),
    ("03/07/08-09", "Lure + installer wave", "Dash Camera PPP pdf, RAGHAV PDFs, printer binaries, win-lbp exe, oscar xbel."),
    ("09/10-09", "Juliett + kilo hits", "EPFQSCDV xbel; EPEEHWSG Library Books.xlsx."),
    ("10-09 11:22", "Hijacker chain starts", "EPSES7ZK freshysearch 4-way redirect bursts begin."),
    ("11-09", "Peak day", "bundle.js x20, Final_Documents.zip, Dash Camera pdf, EPVC2P55 C2 15:58, EPZRAPEL C2 19:27."),
    ("12-09", "Mail + staging C2", "EPLFOXSS pairs; EPWZ7L6L staging; shared n7093/n3618 cluster active."),
    ("13/14-09", "Document wave", "mydoc x4, RETIREES WELFARE xlsx; EPVC2P55 bursts."),
    ("15-09", "Anydesk + cab + banking", "EPGSQVEB sessions; Data1.cab 11:28; EPVSWBNA banking (pre-infection)."),
    ("17-22-09", "Late hits + USB", "Lakeside docs, EPNPX6VY dll, HP x5 AV detect; EPD24DBC USB 22-09 (post-window)."),
    ("23-26-09", "Tail quarantines", "Printer DLLs AV, libreoffice .desktop x2, dash cam pdf, xlsx/docx/so (post-window)."),
]
tl_rows = ""
for t, e, v in timeline:
    tl_rows += f"{cell(t)} & {cell(e)} & {cell(v)} \\\\\n\\hline\n"

tex = r"""%% GENERATED FILE - do not edit main.tex directly.
%% Source: generate_latex.py + output/phase1_iocs.csv  (uv run python generate_latex.py)
\documentclass[11pt,a4paper]{article}
\usepackage[margin=0.85in]{geometry}
\usepackage[table]{xcolor}
\usepackage{tabularx,longtable,booktabs,array,graphicx,enumitem,tikz,tocloft,fancyhdr,caption}
\usetikzlibrary{shapes.geometric,arrows.meta,positioning}
% Prism palette
\definecolor{navy}{HTML}{153B5B}
\definecolor{accentblue}{HTML}{1A56DB}
\definecolor{bluefill}{HTML}{EAF3F8}
\definecolor{greenfill}{HTML}{EAF6EE}
\definecolor{orangefill}{HTML}{FFF2DF}
\definecolor{purplefill}{HTML}{F2ECF8}
\definecolor{sevred}{HTML}{B42318}
\newcolumntype{Y}{>{\raggedright\arraybackslash}X}
\setlength{\tabcolsep}{3pt}\renewcommand{\arraystretch}{1.15}
\setlength{\emergencystretch}{2.5em}
\newcommand{\sev}[2]{\textcolor{#1}{\textbf{[#2]}}}
\newcommand{\badge}[2]{\colorbox{#1}{\color{white}\textbf{\small #2}}}
\newcommand{\codebox}[1]{\noindent\fcolorbox{navy!60}{bluefill}{\parbox{\dimexpr\linewidth-2\fboxsep-2\fboxrule}{\ttfamily\small #1}}}
% TOC styling (navy entries, dotted leaders, closing rule drawn after \tableofcontents)
\renewcommand{\cftsecfont}{\color{navy}\bfseries}
\renewcommand{\cftsecpagefont}{\color{navy}\bfseries}
\renewcommand{\cftsubsecfont}{\color{navy}}
\renewcommand{\cftdot}{\color{navy}.}
% Running header
\pagestyle{fancy}\fancyhf{}
\fancyhead[L]{\small\color{navy}\textbf{Organisation X: Endpoint Compromise Forensics}}
\fancyhead[R]{\small 03 Oct 2026}
\renewcommand{\headrulewidth}{0.6pt}
\usepackage{hyperref}
\hypersetup{colorlinks=true,linkcolor=navy,urlcolor=navy}
\title{}\author{}\date{}
\begin{document}
\thispagestyle{empty}
% ---------- Cover ----------
\begin{center}
{\small\color{accentblue}\textsc{Organisation X endpoint forensics --- September 2026}}\\[10pt]
{\LARGE\bfseries\color{navy} Endpoint Compromise Forensic Analysis}\\[2pt]
{\large\color{navy} of Multi-Endpoint Phishing \& C2 Beaconing Campaign}\\[10pt]
{\color{accentblue}\rule{0.22\linewidth}{3pt}}\\[16pt]
{\Large\bfseries Adrishikhar Chowdhury}\\[4pt]
{\color{navy} amiadrishikhar@gmail.com}\\[4pt]
{October 03, 2026}\\[2pt]
{\color{navy} SOC Lead, Organisation X}\\[14pt]
\end{center}
{\small\color{accentblue}\textbf{EXECUTIVE RISK OVERVIEW}}\\[4pt]
\begin{tabularx}{\linewidth}{@{}p{2.1cm}p{3.4cm}Y@{}}\toprule
\rowcolor{navy}\color{white}\textbf{Severity} & \color{white}\textbf{Vector} & \color{white}\textbf{Detail} \\\midrule
\badge{sevred}{HIGH} & {Persistent C2} & {Five hosts beacon 1--3 weeks post-quarantine via per-victim C2 domains paired with anonymized IPs in same-second sessions.} \\
\badge{sevred}{HIGH} & {Remote-access persist} & {Anydesk relays run after payload quarantine (EPGSQVEB); one phishing host never quarantined (EPLFOXSS, AV file-not-found 01--19 Sep).} \\
\badge{orange!70!black}{MEDIUM} & {Trojanized installers} & {HP/printer bundles, freshysearch redirect chain, and XDG desktop persistence.} \\
\badge{accentblue}{INFO} & {USB ruled out} & {EPD24DBC Mass Storage (22-09, post-window) uncorroborated; mouse benign. Phishing/drive-by, not a USB worm.} \\\bottomrule
\end{tabularx}

\vspace{6pt}
{\small\begin{tabular}{@{}>{\bfseries}l p{13.2cm}@{}}
Scope & endpoint\_security.csv (23,540 rows, 247 endpoints, 19 units) + usb\_events.csv (8) + web\_activity.csv (2,812,118 rows, 248 endpoints), all local UTC+05:30 \\
Findings & 33 endpoints FileType=Malicious (134 rows, 60 dedup) + 2 AV-only active + 8 C2 clusters \\
\end{tabular}}\newpage
% ---------- TOC ----------
\tableofcontents
\noindent{\color{accentblue}\rule{\linewidth}{1pt}}
\newpage
\section{Executive Summary}
Endpoint telemetry across \textasciitilde250 Linux desktops (19 units, September 2026) characterises a multi-vector phishing and drive-by campaign staging pseudorandom and lure-themed payloads from user-writable paths.
Artefact review confirmed quarantined payloads, a failed mail-payload remediation, per-victim C2 beaconing, hijacker bundling, and post-payload remote-access sessions.
Verified file hashes, beacon indicators, and MITRE mappings are provided for endpoint containment.
\subsection*{Risk Assessment (for leadership)}
\begin{tabularx}{\linewidth}{@{}p{2.1cm}p{3.4cm}Y@{}}\toprule
\rowcolor{navy}\color{white}\textbf{Severity} & \color{white}\textbf{Area} & \color{white}\textbf{Detail} \\\midrule
\badge{sevred}{HIGH} & {Staging at scale} & {33 endpoints quarantined FileType=Malicious material (134 rows, 60 dedup endpoint+SHA), including a 9-host shared xbel payload.} \\
\badge{sevred}{HIGH} & {Beaconing persistence} & {Five hosts re-contact per-victim C2 for days to weeks after quarantine; Anydesk persists post-payload on one host.} \\
\badge{orange!70!black}{MEDIUM} & {Installer trust abuse} & {Trojanized printer and HP bundles plus a browser-hijacker chain defeat signature-only inspection.} \\
\badge{accentblue}{INFO} & {Detection gap} & {AV never logged a FOUND line (all summaries Infectedfiles:0); 179 action rows across 13 hosts carry the signal, and two AV-only hosts never reached quarantine.} \\\bottomrule
\end{tabularx}
\subsection*{Key Concepts (plain-English primer)}
\textbf{C2 beacon pair.} The agent logs each contacted destination separately, so one connection appears as two same-second rows: a domain plus the IP it resolved to. Repeated domain+IP pairs at fixed times mean automated beaconing, not browsing.\\
\textbf{Rare-domain cardinality.} Counting how many endpoints ever contacted each destination separates campaign infrastructure (1--3 endpoints) from benign shared services (hundreds). LAN suffixes (\texttt{.hgu\_lan}, \texttt{.bbrouter}, \texttt{.dlink}, \texttt{.local}) are stripped first.\\
\textbf{Anonymized indicators.} Challenge data replaces real C2 with \texttt{svc-<hex>.gov.example} domains and \texttt{198.18.0.0/15} IPs; widespread \texttt{svc-*} names are genuine gov portals and are excluded.\\
\textbf{Clock skew.} Endpoints upload days late with wrong clocks, so timelines use \texttt{event\_time} with \texttt{received\_time} as a sanity band (quarantine median \textasciitilde0h; av\_scan median 34h).\\
\textbf{Quarantine re-listing.} The service re-lists the whole quarantine folder per scan, so one file appears many times; analysis dedups by endpoint+SHA (134 rows \textrightarrow{} 60).
\section{Tools Used}
Only tools that produced concrete evidence in this investigation are listed.
\begin{itemize}[leftmargin=*]
\item \textbf{Python 3.12 + pandas (chunked)} --- endpoint triage and 2.8M-row web cardinality/C2 scoring
\item \textbf{rich} --- terminal evidence tables (\texttt{rich\_triage.py})
\item \textbf{uv} --- reproducible environment (\texttt{uv sync}, \texttt{uv run})
\item \textbf{MiKTeX latexmk} --- this report build (\texttt{Latex/main.tex} \textrightarrow{} PDF)
\end{itemize}
\section{Methodology}
\subsection{Analysis}
Quarantine FileType parsing (\texttt{FileType:} field with dedup), AV action-line review (\texttt{Beginning quarantine / Attempting / File not found}), web\_block baselining, USB correlation, then chunked web\_activity rare-domain scoring with same-second pair resolution and clock-skew banding.
\subsection{Finding}
Phishing and drive-by traits (lure documents, mail payload, hijacker bundling, trojanized installers), per-victim C2 pairs on 8 clusters, Anydesk remote access, \texttt{.desktop} persistence, and two AV-remediation gaps; USB and web\_block ruled out as vectors; shared xbel hash links 9 hosts.
\subsection{Outcome}
Actionable IoCs (60 hashes, paths, 8 C2 clusters, MITRE map) compiled for isolation, firewall blocks, and EDR hunts.
\section{Reconstructed Timeline}
Quarantine dates are first-seen \texttt{Quarantined At}; web sessions fall in the 10--21 Sep window. Isolate and re-image any host showing this sequence.
\begin{center}\rowcolors{2}{bluefill}{white}
\begin{tabularx}{\linewidth}{p{2.6cm}Y Y}\toprule
\rowcolor{bluefill}\textbf{Timestamp} & \textbf{Event} & \textbf{Evidence} \\\midrule
""" + tl_rows + r"""\bottomrule\end{tabularx}\end{center}
\section{Step by Step Process Along with Screenshots}
\subsection*{Architecture Overview}
\vspace{1cm}
\begin{center}
\begin{tikzpicture}[node distance=1.0cm,
  box/.style={rectangle,rounded corners,draw=navy,thick,minimum width=2.8cm,minimum height=1.1cm,align=center,font=\small},
  arr/.style={-{Stealth[scale=1.1]},thick,color=navy}]
\node[box,fill=bluefill] (p1) {1. Triage + USB};
\node[box,fill=greenfill,right=of p1] (p2) {2. Chunked web C2};
\node[box,fill=orangefill,right=of p2] (p3) {3. Timeline + IOC};
\node[box,fill=purplefill,right=of p3] (p4) {4. Indicator + Report};
\draw[arr] (p1)--(p2); \draw[arr] (p2)--(p3); \draw[arr] (p3)--(p4);
\end{tikzpicture}
\end{center}
\subsection*{Step 1: Endpoint Triage \& Cryptographic Baselining}
Parsed 23,540 rows: 134 FileType=Malicious rows across 33 endpoints (60 dedup), 0 FOUND lines, 179 AV action rows, 914 policy web blocks, 8 USB rows with zero compromised overlap:

\vspace{1cm}
\codebox{uv run python rich\_triage.py\\\# scope, quarantine, AV gaps, USB, skew, C2 spot counts}

\subsection*{Step 2: Chunked Web C2 Hunt}
Rare-domain scoring over 2,812,118 rows (19,027 uniq destinations) isolated per-victim beacons; same-second domain+IP pairs confirm sessions. Widespread gov/Mozilla/Yahoo infra excluded as benign.
\IfFileExists{images/c2_beacon.png}{{\centering\includegraphics[width=0.95\linewidth]{images/c2_beacon.png}\captionof{figure}{Confirmed C2 indicators by hit count (verified web counts).}\par}}{}
\subsection*{Step 3: Timeline \& Clock-Skew Review}
Per-endpoint session dates (UTC+05:30) with quarantine median \textasciitilde0h and av\_scan median 34h bands; late uploaders (EPC2L3UH 18.4h, EPLFOXSS 31.8h, EPGSQVEB 32.9h) flagged offline.
\IfFileExists{images/timeline.png}{\begin{figure}[htbp]\centering\includegraphics[width=\linewidth]{images/timeline.png}\caption{C2 beacon active days per endpoint.}\end{figure}}{}
Terminal evidence tables are produced by rich\_triage.py; save a screenshot as images/triage\_tables.png to embed it here.

\IfFileExists{images/triage_tables.png}{\begin{figure}[h!]\centering\includegraphics[width=0.8\linewidth]{images/triage_tables.png}\caption{Rich Phase 1 terminal tables (abridged; full output via rich\_triage.py).}\end{figure}}{}

\subsection*{Step 4: Indicator Extraction \& Reporting}

\codebox{uv run python phase1\_triage.py \ \# output/phase1\_iocs.csv (60 rows)\\uv run python gen\_figures.py \ \# Latex/images/c2\_beacon.png, timeline.png\\uv run python generate\_latex.py \ \# Latex/main.tex\\cd Latex \&\& latexmk -pdf main.tex}
\newpage
\section{Technical Findings Summary}
Findings below use wrapped monospace cells so hashes and paths never overflow margins.
\begin{center}\rowcolors{2}{orangefill}{white}
\begin{tabularx}{\linewidth}{p{2.2cm}Y Y p{2.8cm}}\toprule
\rowcolor{orangefill}\textbf{Endpoint} & \textbf{Payload} & \textbf{C2 + counts} & \textbf{Persistence} \\\midrule
""" + find_rows + r"""\bottomrule\end{tabularx}\end{center}
\section{MITRE ATT\&CK Mapping}
\begin{center}\rowcolors{2}{purplefill}{white}
\begin{tabularx}{\linewidth}{p{2.2cm}p{3.2cm}Y}\toprule
\rowcolor{purplefill}\textbf{Technique} & \textbf{Name} & \textbf{Observed Behaviour} \\\midrule
""" + mitre_rows + r"""\bottomrule\end{tabularx}\end{center}
\section{Recommendations}
{\sloppy
\begin{enumerate}[leftmargin=*]
\item Isolate still-compromised hosts (EPZRAPEL, EPVC2P55, EPT3KTUL, EPLFOXSS, EPWZ7L6L, EPSES7ZK, EPGSQVEB, EPFQSCDV); triage co-suspects EPCRFN4D/\allowbreak{}EPV7MB2K/\allowbreak{}EPL4KXNW; collect quarantine dirs and agent logs before re-imaging.
\item Hunt retrospectively for the shared xbel SHA, the HP/printer bundle SHAs, and per-victim svc beacons using the verified hashes in Appendix A.
\item Remove desktop-file persistence and audit home download/desktop/share folders for residual payloads; revoke Anydesk access on EPGSQVEB.
\item Future work: run an authorised isolated capture to confirm callback behaviour of the anonymized C2 endpoints; do not assert payload contents beyond current evidence.
\end{enumerate}
}
\appendix
\section{Appendix A: Pipeline-Extracted IOCs (60 dedup rows)}
\rowcolors{2}{orangefill}{white}
\begin{longtable}{|p{2.2cm}|p{6.9cm}|p{4.6cm}|}\hline
\rowcolor{navy}\color{white}\textbf{Endpoint} & \color{white}\textbf{File} & \color{white}\textbf{SHA-256} \\\hline
\endfirsthead\hline\rowcolor{navy}\color{white}\textbf{Endpoint} & \color{white}\textbf{File} & \color{white}\textbf{SHA-256} \\\hline\endhead
""" + ioc_rows + r"""\end{longtable}
\section{Appendix B: Reproducibility}
\codebox{uv sync\\uv run python rich\_triage.py\\uv run python phase1\_triage.py\\uv run python gen\_figures.py\\uv run python generate\_latex.py\\cd Latex \&\& latexmk -pdf main.tex}
\end{document}
"""
TEX.write_text(tex, encoding="utf-8")
print(f"WROTE {TEX} ({len(tex)} chars)")
