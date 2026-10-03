"""LaTeX report builder (single source of truth stays in generate_latex.py)."""
from __future__ import annotations

import runpy
from pathlib import Path


def build_report() -> Path:
    root = Path(__file__).resolve().parents[1]
    runpy.run_path(str(root / "generate_latex.py"), run_name="__main__")
    tex = root / "Latex" / "main.tex"
    if not tex.exists():
        raise FileNotFoundError(f"report source not produced: {tex}")
    return tex
