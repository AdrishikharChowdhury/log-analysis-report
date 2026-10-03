"""Anomaly detection: rare-domain C2 scoring, AV gaps, USB verdicts."""
from __future__ import annotations

import pandas as pd

from .log_parser import web_target_counts

# Verified per-victim C2 clusters (CONTEXT.md S3b): domain+IP same-second pairs.
CONFIRMED_C2: dict[str, list[str]] = {
    "EPZRAPEL": ["svc-d44578.gov.example", "198.18.165.210"],
    "EPVC2P55": ["svc-148367.gov.example", "198.18.227.50", "198.41.0.4", "40.81.94.65"],
    "EPT3KTUL": ["svc-89bec8.gov.example", "198.18.251.94", "n7473.svc-89bec8.gov.example"],
    "EPLFOXSS": ["svc-89a41f.gov.example", "198.18.40.61"],
    "EPWZ7L6L": ["svc-b76574.gov.example", "svc-171e30.gov.example", "n2b40.svc-e557f1.gov.example"],
    "EPSES7ZK": ["freshysearch.com", "search.freshy.com",
                 "i.wallpapers.searchtabnew.com", "dz2gehduwv9t4.cloudfront.net"],
    "EPGSQVEB": ["relay-7ef33ce3.net.anydesk.com", "148.113.17.93",
                 "relay-59e6d48d.net.anydesk.com", "148.113.8.189"],
    "EPFQSCDV": ["n7093.svc-1943de.gov.example", "n3618.svc-4f2a32.gov.example", "34.93.158.11"],
}

VERDICTS = {
    "EPZRAPEL": "STILL COMPROMISED", "EPVC2P55": "STILL COMPROMISED",
    "EPT3KTUL": "STILL COMPROMISED", "EPLFOXSS": "ACTIVE (never quarantined)",
    "EPWZ7L6L": "COMPROMISED", "EPSES7ZK": "HIJACKER + INSTALLER",
    "EPGSQVEB": "REMOTE-ACCESS PERSIST", "EPFQSCDV": "COMPROMISED + 2 CO-SUSPECTS",
}

# High-count but benign (excluded from C2 scoring with reasons).
BENIGN = {
    "question": "captive/DHCP probe (89 eps)", "opt": "captive/DHCP probe (150 eps)",
    "epdajrps.local": "romeo LAN box", "106.10.218.155": "Yahoo mail CDN",
    "c2shb-oao.ssp.yahoo.com": "'c2' is Yahoo content-server, not CnC",
}


def all_indicators() -> list[str]:
    return sorted({m for v in CONFIRMED_C2.values() for m in v})


def score_indicators(base=None) -> pd.DataFrame:
    """Re-count every confirmed indicator in web_activity.csv; flag deviations."""
    counts = web_target_counts(base, all_indicators())
    rows = [{"endpoint": ep, "indicator": m, "rows": counts.get(m, 0)}
            for ep, v in CONFIRMED_C2.items() for m in v]
    return pd.DataFrame(rows).sort_values(["endpoint", "rows"], ascending=[True, False])


def av_gaps(action_endpoints: list[str], mal_endpoints: list[str]) -> list[str]:
    """AV-fired but never quarantined -> still-active suspects."""
    return sorted(set(action_endpoints) - set(mal_endpoints))


def usb_verdicts(usb: pd.DataFrame, mal_endpoints: list[str], df: pd.DataFrame) -> pd.DataFrame:
    out = []
    for ep in sorted(usb.endpoint_id.unique()):
        n_ep = int((df.endpoint_id == ep).sum())
        out.append({
            "endpoint_id": ep,
            "in_compromised_set": ep in set(mal_endpoints),
            "endpoint_security_rows": n_ep,
            "verdict": ("BENIGN (mouse)" if "Mouse" in str(
                usb[usb.endpoint_id == ep].message.iloc[0])
                        else ("UNCORROBORATED - monitor" if n_ep == 0
                              else "REVIEW web pivot")),
        })
    return pd.DataFrame(out)
