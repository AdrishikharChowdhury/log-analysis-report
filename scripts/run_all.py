"""Batch runner: full pipeline end to end. Run: uv run python scripts/run_all.py [--skip-web]"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STEPS = ["triage", "timeline", "report"] if "--skip-web" in sys.argv else \
        ["triage", "webc2", "timeline", "report"]

for step in STEPS:
    print(f"=== {step} ===")
    r = subprocess.run([sys.executable, str(ROOT / "main.py"), step], cwd=ROOT)
    if r.returncode != 0:
        raise SystemExit(f"step failed: {step} (rc={r.returncode})")
print("run_all OK:", STEPS)
