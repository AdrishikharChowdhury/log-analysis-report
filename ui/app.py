"""Streamlit dashboard (optional): uv sync --group full && uv run streamlit run ui/app.py
Without streamlit installed, `python ui/app.py` prints this guidance instead."""
from pathlib import Path

try:
    import pandas as pd
    import streamlit as st
except ImportError:
    print("Dashboard needs the 'full' extras: uv sync --group full")
    print("Then: uv run streamlit run ui/app.py")
    raise SystemExit(0)

ROOT = Path(__file__).resolve().parents[1]
IOC = ROOT / "output" / "phase1_iocs.csv"

st.title("Organisation X — SOC triage (Project 3)")
if not IOC.exists():
    st.warning("Run `uv run python main.py triage` first (builds output/phase1_iocs.csv).")
    st.stop()
ioc = pd.read_csv(IOC)
st.metric("Compromised endpoints", int(ioc.endpoint_id.nunique()))
st.metric("Dedup IOC rows", len(ioc))
st.dataframe(ioc, use_container_width=True)
st.bar_chart(ioc.unit.value_counts())
st.caption("Full ledger: CONTEXT.md. Report: Latex/main.pdf.")
