"""Evidence figures for Latex/images/ (verified counts from CONTEXT.md S3b).
Run: uv run python gen_figures.py
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

NAVY = "#153B5B"
IMG = "Latex/images"

plt.rcParams.update({"font.size": 9, "figure.dpi": 150})

# Figure 1: confirmed C2 hits per indicator (verified web counts)
labels = ["svc-d44578\nEPZRAPEL", "198.18.165.210", "svc-148367\nEPVC2P55",
          "198.18.227.50", "198.41.0.4", "40.81.94.65", "svc-89bec8\nEPT3KTUL",
          "svc-89a41f\nEPLFOXSS", "198.18.40.61", "freshysearch\nEPSES7ZK",
          "search.freshy", "anydesk relay\nEPGSQVEB", "n7093\nEPFQSCDV",
          "n3618", "34.93.158.11"]
values = [50, 43, 152, 143, 86, 75, 35, 20, 18, 61, 58, 4, 188, 184, 131]
fig, ax = plt.subplots(figsize=(9, 7.5))
ax.barh(labels, values, color=NAVY)
ax.set_xlabel("Web rows (10-21 Sep 2026 window)")
ax.set_title("Confirmed C2 indicators by hit count (unique per-victim beacons)")
ax.tick_params(axis="y", labelsize=8.5)
for i, v in enumerate(values):
    ax.text(v + 2, i, str(v), va="center", fontsize=8)
fig.tight_layout()
fig.savefig(f"{IMG}/c2_beacon.png", bbox_inches="tight")
print("WROTE c2_beacon.png")

# Figure 2: beacon active days per endpoint (verified session dates)
activity = {
    "EPZRAPEL": [11, 12, 13, 14, 16, 17, 18, 19],
    "EPVC2P55": [11, 14, 17, 18],
    "EPT3KTUL": [10, 11, 12, 19, 20],
    "EPLFOXSS": [12, 14, 16, 17],
    "EPWZ7L6L": [12, 15, 18, 19],
    "EPSES7ZK": [10, 12, 13, 14, 16, 18, 19, 20],
    "EPGSQVEB": [15, 16, 19],
}
fig, ax = plt.subplots(figsize=(9, 3.4))
for i, (ep, days) in enumerate(activity.items()):
    ax.scatter(days, [i] * len(days), s=60, color=NAVY, zorder=3)
    ax.hlines(i, 10, 21, colors="#B0C4D6", linewidths=1)
ax.set_yticks(range(len(activity)))
ax.set_yticklabels(list(activity.keys()))
ax.set_xticks(range(10, 22))
ax.set_xlabel("September 2026 (web window 10-21)")
ax.set_title("C2 beacon active days per endpoint (same-second domain+IP pairs)")
ax.grid(axis="x", alpha=0.3)
fig.tight_layout()
fig.savefig(f"{IMG}/timeline.png", bbox_inches="tight")
print("WROTE timeline.png")
