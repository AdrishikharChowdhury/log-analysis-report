"""Render `rich_triage.py --abridged` terminal output as a dark terminal-style PNG.
Run: uv run python gen_terminal_shot.py  -> Latex/images/triage_tables.png
Same data as full output, compact row limits for a one-page figure.
"""
import subprocess
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent
r = subprocess.run(["uv", "run", "python", "rich_triage.py", "--abridged"],
                   capture_output=True, text=True, cwd=ROOT)
assert r.returncode == 0, r.stderr[-2000:]
text = r.stdout.strip("\n")
n = text.count("\n") + 1
print(f"rendering {n} lines")
assert n <= 50, f"too tall for one page: {n} lines"

fig_w = 10.0
fig_h = max(6.0, n * 0.185)
fig, ax = plt.subplots(figsize=(fig_w, fig_h), facecolor="#141422")
ax.set_axis_off()
ax.set_xlim(0, 1)
ax.set_ylim(0, 1)
ax.text(0.01, 0.99, text, fontfamily="monospace", fontsize=7.2,
        color="#E8E8F0", va="top", ha="left", wrap=False,
        linespacing=1.15)
fig.savefig(ROOT / "Latex/images/triage_tables.png", bbox_inches="tight",
            facecolor="#141422", dpi=150)
print("WROTE triage_tables.png")
