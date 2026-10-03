"""CLI hub: log filtering, timeline analysis, reporting, UI. Run: uv run python main.py <cmd>."""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from src.anomaly_detector import all_indicators, av_gaps, score_indicators, usb_verdicts  # noqa: E402
from src.latex_generator import build_report  # noqa: E402
from src.log_parser import (  # noqa: E402
    load_endpoint_security, load_usb, parse_av, parse_quarantine, parse_web_block,
)
from src.timeline_correlator import delay_stats, endpoint_presence, quarantine_first_seen  # noqa: E402


def cmd_triage(_a):
    df = load_endpoint_security()
    q, av, wb, usb = parse_quarantine(df), parse_av(df), parse_web_block(df), load_usb()
    print(f"rows={len(df)} endpoints={df.endpoint_id.nunique()} units={df.unit.nunique()}")
    print(f"Malicious rows={q['malicious_rows']} endpoints={len(q['malicious_endpoints'])} "
          f"dedup={len(q['dedup'])}")
    print(f"AV FOUND={av['found_rows']} action_rows={av['action_rows']} "
          f"action_eps={len(av['action_endpoints'])}")
    print(f"AV-only gaps={av_gaps(av['action_endpoints'], q['malicious_endpoints'])}")
    print(f"web_block rows={wb['rows']} endpoints={len(wb['endpoints'])}")
    print(f"USB={sorted(usb.endpoint_id.unique())} "
          f"overlap={sorted(set(usb.endpoint_id) & set(q['malicious_endpoints'])) or 'NONE'}")
    meta = df.drop_duplicates("endpoint_id")[["endpoint_id", "endpoint_name", "mac", "unit"]]
    ioc = (q["dedup"][["endpoint_id", "fname", "sha"]].merge(meta, on="endpoint_id")
           [["endpoint_id", "endpoint_name", "mac", "unit", "fname", "sha"]]
           .sort_values(["endpoint_id", "sha"]))
    out = ROOT / "output" / "phase1_iocs.csv"
    out.parent.mkdir(exist_ok=True)
    ioc.to_csv(out, index=False)
    print(f"WROTE {out} ({len(ioc)} rows)")


def cmd_webc2(_a):
    print("targeted recount of confirmed C2 indicators (chunked web scan)...")
    print(score_indicators().to_string(index=False))


def cmd_timeline(_a):
    df = load_endpoint_security()
    print(delay_stats(df).round(2).to_string())
    q = parse_quarantine(df)
    eps = q["malicious_endpoints"] + ["EPAX5P5D", "EPLFOXSS", "EPD24DBC"]
    print(endpoint_presence(df, eps).to_string(index=False))
    print(quarantine_first_seen(df).head(12).to_string(index=False))


def cmd_report(a):
    tex = build_report()
    print(f"WROTE {tex}")
    if a.compile:
        r = subprocess.run(["latexmk", "-pdf", "-interaction=nonstopmode", "main.tex"],
                           cwd=ROOT / "Latex")
        print("compile rc=", r.returncode)


def cmd_ui(_a):
    try:
        import streamlit  # noqa: F401
    except ImportError:
        print("Dashboard needs the 'full' extras: uv sync --group full")
        print("Then: uv run streamlit run ui/app.py")
        return
    subprocess.run([sys.executable, "-m", "streamlit", "run", str(ROOT / "ui" / "app.py")])


P = argparse.ArgumentParser(prog="main.py", description="Project 3 SOC log-analysis hub")
sub = P.add_subparsers(dest="cmd", required=True)
sub.add_parser("triage", help="Phase 1: quarantine/AV/USB triage + IOC csv")
sub.add_parser("webc2", help="Phase 2: recount confirmed C2 indicators")
sub.add_parser("timeline", help="Phase 3: delays + presence + first-seen")
rp = sub.add_parser("report", help="Phase 4: rebuild Latex/main.tex")
rp.add_argument("--compile", action="store_true", help="also run latexmk")
sub.add_parser("ui", help="launch Streamlit dashboard (needs full extras)")
args = P.parse_args()
{"triage": cmd_triage, "webc2": cmd_webc2, "timeline": cmd_timeline,
 "report": cmd_report, "ui": cmd_ui}[args.cmd](args)
