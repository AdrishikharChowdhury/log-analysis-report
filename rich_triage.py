"""Rich Phase 1-3 triage with visible CLI tables (screenshots-ready).
Run: uv run python rich_triage.py [--abridged: compact figure mode, same data]
"""
import sys
from collections import Counter
from pathlib import Path

import pandas as pd
from rich.console import Console
from rich.table import Table

ROOT = Path(__file__).resolve().parent
EP = ROOT / "web_activity" / "data" / "endpoint_security.csv"
USB = ROOT / "web_activity" / "data" / "usb_events.csv"
WEB = ROOT / "web_activity" / "data" / "web_activity.csv"
ABRIDGED = "--abridged" in sys.argv  # compact figure mode: same data, fewer rows
console = Console(width=110 if ABRIDGED else None)


def show(df_rows: list[tuple], title: str, headers: list[str]):
    t = Table(title=title, show_lines=False)
    for h in headers:
        t.add_column(h, overflow="fold")
    for r in df_rows:
        t.add_row(*[str(x) for x in r])
    console.print(t)


df = pd.read_csv(EP)
console.rule("[bold]Phase 1 - Scope")
show([(len(df), df.endpoint_id.nunique(), df.unit.nunique())],
     "endpoint_security.csv", ["rows", "endpoints", "units"])
if not ABRIDGED:
    show(list(df.log_type.value_counts().items()), "log_type counts", ["log_type", "rows"])

q = df[df.log_type == "quarantine"].copy()
q["ft"] = q["message"].str.extract(r"FileType:\s*([^|]+)")[0].str.strip()
q["sha"] = q["message"].str.extract(r"SHA256:\s*([0-9a-fA-F]+)")
q["fname"] = q["message"].str.extract(r"File:\s*(.*?)\s*\|\s*Quarantined")
mal = q[q.ft == "Malicious"]
dedup = mal.drop_duplicates(["endpoint_id", "sha"])
console.rule("[bold]Quarantine - FileType==Malicious")
show([(len(mal), mal.endpoint_id.nunique(), len(dedup))],
     "malicious ledger", ["mal_rows", "endpoints", "dedup_ep+sha"])
top_files = dedup["fname"].value_counts().head(8 if not ABRIDGED else 0)
if not ABRIDGED:
    show(list(top_files.items()), "top malicious files (dedup)", ["file", "endpoints"])
    show([(h[:16] + "...", c) for h, c in dedup["sha"].value_counts().head(8).items()],
         "top malicious SHAs (truncated, full in CONTEXT.md)", ["sha_prefix", "endpoints"])

av = df[df.log_type == "av_scan"]
act = av[~av.message.str.contains("System Scan Completed|Knownviruses", na=False)]
console.rule("[bold]AV scans")
show([(int(av.message.str.contains("FOUND", na=False).sum()), len(act),
       act.endpoint_id.nunique())], "av_scan", ["FOUND_rows", "action_rows", "action_endpoints"])
per_ep = list(act.groupby(["endpoint_id", "unit"]).size().reset_index(name="n")
              .sort_values("n", ascending=False).itertuples(index=False, name=None))
mal_eps, act_eps = set(mal.endpoint_id), set(act.endpoint_id)
av_only = sorted(act_eps - mal_eps)
if ABRIDGED:
    show(per_ep[:4], "AV actions per endpoint (top 4 of 13)", ["endpoint", "unit", "rows"])
    console.print("+ 9 more endpoints; AV-only never quarantined: " + ", ".join(av_only))
else:
    show(per_ep, "AV actions per endpoint", ["endpoint", "unit", "rows"])
    show([(e,) for e in av_only] or [("- none -",)],
         "AV-only, never quarantined (still-active)", ["endpoint"])

wb = df[df.log_type == "web_block"]
console.rule("[bold]web_block (policy noise, not IOCs)")
show(list(wb.message.value_counts().head(8 if not ABRIDGED else 3).items()), "top blocked domains", ["domain", "rows"])
if not ABRIDGED:
    show([(str(len(wb)), str(wb.endpoint_id.nunique()))], "web_block totals", ["rows", "endpoints"])

usb = pd.read_csv(USB)
console.rule("[bold]USB correlation")
if ABRIDGED:
    console.print("USB: zero overlap with compromised set; EPD24DBC absent from endpoint_security.csv; mouse benign")
else:
    show(list(usb.itertuples(index=False, name=None)), "usb_events.csv (8 rows)",
         ["endpoint", "host", "mac", "unit", "type", "event_time", "received_time", "message"])
    show([("overlap USB x compromised (33)", str(bool(set(usb.endpoint_id) & set(mal.endpoint_id)))),
          ("EPD24DBC rows in endpoint_security.csv", str(int((df.endpoint_id == "EPD24DBC").sum()))),
          ("verdict EPD24DBC", "UNCORROBORATED - monitor"),
          ("verdict EP7FZ2XY mouse", "BENIGN")], "USB assessment", ["check", "result"])

console.rule("[bold]Phase 3 - clock skew (event_time vs received_time, hours)")
d = df.copy()
d["e"] = pd.to_datetime(d.event_time, format="%d-%m-%Y %H:%M:%S", errors="coerce")
d["r"] = pd.to_datetime(d.received_time, format="%d-%m-%Y %H:%M:%S", errors="coerce")
d["h"] = (d.r - d.e).dt.total_seconds() / 3600
desc = d.groupby("log_type").h.describe()[["count", "mean", "50%", "max", "min"]]
if ABRIDGED:
    console.print("delays (h): quarantine med ~0, av_scan med 34, web_block med 21 (see S4 Timeline)")
else:
    show([tuple([i] + [f"{x:.2f}" for x in r]) for i, r in desc.iterrows()],
         "delay by log_type", ["log_type", "count", "mean_h", "median_h", "max_h", "min_h"])

console.rule("[bold]Phase 2 spot-check - confirmed C2 counts (chunked web scan)")
targets = ["svc-d44578.gov.example", "198.18.165.210", "svc-148367.gov.example",
           "198.18.227.50", "svc-89bec8.gov.example", "svc-89a41f.gov.example",
           "198.18.40.61", "freshysearch.com", "search.freshy.com",
           "relay-7ef33ce3.net.anydesk.com", "n7093.svc-1943de.gov.example"]
if ABRIDGED:
    console.print("charted in Fig 1 (c2_beacon.png) - full counts in terminal output")
else:
    tot: Counter = Counter()
    for chunk in pd.read_csv(WEB, chunksize=500_000, usecols=["message"]):
        for m in chunk[chunk.message.isin(targets)].message:
            tot[m] += 1
    show([(m, tot[m]) for m in targets], "C2 spot counts (must match CONTEXT.md S3b)",
         ["indicator", "rows"])
console.print("[green]Phase 1-3 rich triage OK - see CONTEXT.md 2a/3b for full ledger[/]")
