"""Ingestion and filtering: endpoint_security.csv, usb_events.csv, chunked web_activity.csv."""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd

TS_FMT = "%d-%m-%Y %H:%M:%S"
LAN_SUFFIX_RE = re.compile(r"\.(hgu_lan|bbrouter|dlink|local)$", re.IGNORECASE)


def data_dir(explicit: str | Path | None = None) -> Path:
    if explicit:
        return Path(explicit)
    root = Path(__file__).resolve().parents[1]
    for cand in (root / "web_activity" / "data", root / "data"):
        if (cand / "endpoint_security.csv").exists():
            return cand
    raise FileNotFoundError("dataset not found (looked in web_activity/data/, data/)")


def strip_lan_suffix(domain: str) -> str:
    return LAN_SUFFIX_RE.sub("", domain.strip().lower()) if isinstance(domain, str) else domain


def load_endpoint_security(base: str | Path | None = None) -> pd.DataFrame:
    df = pd.read_csv(data_dir(base) / "endpoint_security.csv")
    for col in ("event_time", "received_time"):
        df[col + "_dt"] = pd.to_datetime(df[col], format=TS_FMT, errors="coerce")
    df["delay_h"] = (df["received_time_dt"] - df["event_time_dt"]).dt.total_seconds() / 3600
    return df


def parse_quarantine(df: pd.DataFrame) -> dict:
    q = df[df.log_type == "quarantine"].copy()
    q["filetype"] = q["message"].str.extract(r"FileType:\s*([^|]+)")[0].str.strip()
    q["sha"] = q["message"].str.extract(r"SHA256:\s*([0-9a-fA-F]+)")
    q["fname"] = q["message"].str.extract(r"File:\s*(.*?)\s*\|\s*Quarantined")
    mal = q[q.filetype == "Malicious"].copy()
    return {
        "rows": len(df), "quarantine_rows": len(q),
        "malicious_rows": len(mal),
        "malicious_endpoints": sorted(mal.endpoint_id.unique()),
        "dedup": mal.drop_duplicates(["endpoint_id", "sha"]),
        "type_quarantines": int(((q.filetype.notna()) & (q.filetype != "Malicious")).sum()),
    }


def parse_av(df: pd.DataFrame) -> dict:
    av = df[df.log_type == "av_scan"].copy()
    act = av[~av.message.str.contains("System Scan Completed|Knownviruses", na=False)].copy()
    return {
        "found_rows": int(av.message.str.contains("FOUND", na=False).sum()),
        "action_rows": len(act),
        "action_endpoints": sorted(act.endpoint_id.unique()),
        "per_endpoint": act.groupby(["endpoint_id", "unit"]).size().reset_index(name="n"),
    }


def parse_web_block(df: pd.DataFrame) -> dict:
    wb = df[df.log_type == "web_block"].copy()
    return {"rows": len(wb), "endpoints": sorted(wb.endpoint_id.unique()),
            "top": wb.message.value_counts().head(8)}


def load_usb(base: str | Path | None = None) -> pd.DataFrame:
    return pd.read_csv(data_dir(base) / "usb_events.csv")


def web_target_counts(base: str | Path | None = None, targets: list[str] | None = None,
                      chunksize: int = 500_000) -> Counter:
    """Targeted chunked scan of web_activity.csv (fast path for known indicators)."""
    tot: Counter = Counter()
    for chunk in pd.read_csv(data_dir(base) / "web_activity.csv", chunksize=chunksize,
                             usecols=["message"]):
        for m in chunk[chunk.message.isin(targets or [])].message:
            tot[m] += 1
    return tot


def web_global_cardinality(base: str | Path | None = None, pattern: str | None = None,
                           chunksize: int = 300_000) -> tuple[Counter, dict]:
    """Full scan: global message totals + endpoint sets (slow, ~minutes)."""
    total: Counter = Counter()
    eps: dict[str, set] = defaultdict(set)
    for chunk in pd.read_csv(data_dir(base) / "web_activity.csv", chunksize=chunksize,
                             usecols=["endpoint_id", "message"]):
        if pattern:
            chunk = chunk[chunk.message.str.contains(pattern, na=False, regex=True)]
        for ep, msg in zip(chunk["endpoint_id"], chunk["message"]):
            total[msg] += 1
            if len(eps[msg]) < 20:
                eps[msg].add(ep)
    return total, eps
