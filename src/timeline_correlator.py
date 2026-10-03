"""Chronological correlation, clock-skew analysis, multi-artifact pivots."""
from __future__ import annotations

import pandas as pd


def delay_stats(df: pd.DataFrame) -> pd.DataFrame:
    """event_time vs received_time (hours) per log_type."""
    return df.groupby("log_type")["delay_h"].describe()[["count", "mean", "50%", "max", "min"]]


def quarantine_first_seen(df: pd.DataFrame) -> pd.DataFrame:
    """First Malicious quarantine row per endpoint+file (campaign timeline seed)."""
    q = df[df.log_type == "quarantine"].copy()
    q["filetype"] = q["message"].str.extract(r"FileType:\s*([^|]+)")[0].str.strip()
    q["fname"] = q["message"].str.extract(r"File:\s*(.*?)\s*\|\s*Quarantined")
    mal = q[q.filetype == "Malicious"].copy()
    mal["event_dt"] = pd.to_datetime(mal["event_time"], format="%d-%m-%Y %H:%M:%S",
                                     errors="coerce")
    return (mal.sort_values("event_dt").drop_duplicates(["endpoint_id", "fname"])
               [["endpoint_id", "endpoint_name", "unit", "fname", "event_time"]]
               .sort_values(["event_time", "endpoint_id"]).reset_index(drop=True))


def endpoint_presence(df: pd.DataFrame, endpoints: list[str]) -> pd.DataFrame:
    """First/last seen per endpoint per log_type (upload-gap and activity check)."""
    sub = df[df.endpoint_id.isin(endpoints)].copy()
    return (sub.groupby(["endpoint_id", "log_type"])
               .agg(rows=("message", "size"), first=("event_time", "min"),
                    last=("event_time", "max"), median_delay_h=("delay_h", "median"))
               .reset_index().sort_values(["endpoint_id", "log_type"]))
