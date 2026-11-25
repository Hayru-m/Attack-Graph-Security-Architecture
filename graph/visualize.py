"""graph/graph_after.json -> graph/figures/attack_graph_tree.(png|svg)

Soldan sağa ağaç: crAPI System -> grup -> challenge.
Gruplar arası saldırı zinciri (örn. C5 -> C10) tek bir turuncu ok ile gösterilir.
Önce `python graph/build_graph.py` çalıştırılmış olmalı.
"""
import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Patch

GRAPH_PATH = Path("graph/graph_after.json")
OUT_DIR = Path("graph/figures")

# Renkler
C_ROOT = "#0F4C45"
C_GROUP = "#1F7A6D"
C_CHAL_FILL = "#DFF3EE"
C_CHAIN = "#D9480F"
C_LINE = "#9AA7AD"
C_TEXT_DARK = "#0B3B36"

# Yerleşim (x ekseni birimleri)
ROOT_X, ROOT_W = 0.2, 2.2
GROUP_X, GROUP_W = 3.4, 3.4
CHAL_X, CHAL_W = 7.8, 4.2
ROW_H = 1.0
BOX_H = 0.74


def box(ax, x, y, w, h, fill, edge, ls="-", lw=1.2):
    ax.add_patch(FancyBboxPatch(
        (x, y - h / 2), w, h,
        boxstyle="round,pad=0,rounding_size=0.12",
        facecolor=fill, edgecolor=edge, linewidth=lw, linestyle=ls, zorder=3))


def elbow(ax, x1, y1, x2, y2):
    mid = (x1 + x2) / 2
    ax.plot([x1, mid, mid, x2], [y1, y1, y2, y2], color=C_LINE, lw=1.3, zorder=1,
            solid_joinstyle="round")


def main() -> int:
    if not GRAPH_PATH.exists():
        print(f"Hata: {GRAPH_PATH} yok. Önce: python graph/build_graph.py")
        return 1

    data = json.loads(GRAPH_PATH.read_text(encoding="utf-8"))
    nodes = {n["id"]: n for n in data["nodes"]}
    groups = [n for n in data["nodes"] if n["type"] == "group"]
    challenges = [n for n in data["nodes"] if n["type"] == "challenge"]
    chains = [e for e in data["edges"] if e["type"] == "chain"]

    # Satır sırası: grup sırası korunur, grup içinde challenge numarasına göre
    ypos = {}
    row = 0
    for g in groups:
        members = sorted((c for c in challenges if c["group"] == g["id"]),
                         key=lambda c: c["number"])
        for c in members:
            ypos[c["id"]] = -row * ROW_H
            row += 1
        ys = [ypos[c["id"]] for c in members]
        ypos[g["id"]] = sum(ys) / len(ys)
    ypos["root"] = sum(ypos[g["id"]] for g in groups) / len(groups)

    n_rows = len(challenges)
    fig, ax = plt.subplots(figsize=(14, 1.0 * n_rows * 0.75 + 2.4))
    ax.set_xlim(0, 14.2)
    ax.set_ylim(-(n_rows - 1) * ROW_H - 1.4, 1.2)
    ax.axis("off")

    # Çizgiler (kutuların altında)
    for g in groups:
        elbow(ax, ROOT_X + ROOT_W, ypos["root"], GROUP_X, ypos[g["id"]])
    for c in challenges:
        elbow(ax, GROUP_X + GROUP_W, ypos[c["group"]], CHAL_X, ypos[c["id"]])

    # Kök
    box(ax, ROOT_X, ypos["root"], ROOT_W, 1.1, C_ROOT, C_ROOT)
    ax.text(ROOT_X + ROOT_W / 2, ypos["root"], "crAPI\nSystem", ha="center", va="center",
            color="white", fontsize=14, fontweight="bold", zorder=4)

    # Gruplar
    for g in groups:
        n = sum(1 for c in challenges if c["group"] == g["id"])
        box(ax, GROUP_X, ypos[g["id"]], GROUP_W, 0.9, C_GROUP, C_GROUP)
        ax.text(GROUP_X + GROUP_W / 2, ypos[g["id"]] + 0.12, g["label"], ha="center",
                va="center", color="white", fontsize=11.5, fontweight="bold", zorder=4)
        ax.text(GROUP_X + GROUP_W / 2, ypos[g["id"]] - 0.2, f"{n} challenge", ha="center",
                va="center", color="#CFEDE7", fontsize=9, zorder=4)

    # Challenge'lar
    for c in challenges:
        verified = c["status"] == "doğrulandı"
        box(ax, CHAL_X, ypos[c["id"]], CHAL_W, BOX_H, C_CHAL_FILL if verified else "white",
            C_GROUP, ls="-" if verified else (0, (4, 3)), lw=1.2)
        ax.text(CHAL_X + 0.2, ypos[c["id"]], c["label"], ha="left", va="center",
                color=C_TEXT_DARK, fontsize=11, fontweight="bold", zorder=4)
        ax.text(CHAL_X + 0.9, ypos[c["id"]], c["short_name"], ha="left", va="center",
                color=C_TEXT_DARK, fontsize=10.5, zorder=4)

    # Saldırı zinciri (gruplar arası): sağdan dışarı taşan yay
    for e in chains:
        a, b = e["source"], e["target"]
        xr = CHAL_X + CHAL_W
        ax.add_patch(FancyArrowPatch(
            (xr, ypos[a]), (xr, ypos[b]), connectionstyle="arc3,rad=-0.35",
            arrowstyle="-|>", mutation_scale=16, color=C_CHAIN, lw=2.2, zorder=5))
        ax.text(xr + 0.95, (ypos[a] + ypos[b]) / 2,
                f"Zincir\n{nodes[a]['label']} → {nodes[b]['label']}", ha="left",
                va="center", color=C_CHAIN, fontsize=10, fontweight="bold", zorder=5)

    # Başlık + gösterge
    ax.set_title(f"crAPI Saldırı Grafiği ({n_rows} challenge)", fontsize=16,
                 fontweight="bold", pad=14)
    handles = [
        Patch(facecolor=C_CHAL_FILL, edgecolor=C_GROUP, label="Doğrulandı"),
        Patch(facecolor="white", edgecolor=C_GROUP, linestyle="--", label="Analiz edildi"),
        Line2D([0], [0], color=C_CHAIN, lw=2.2, label="Saldırı zinciri"),
    ]
    ax.legend(handles=handles, loc="lower left", frameon=False, fontsize=10, ncol=3,
              bbox_to_anchor=(0.0, -0.02))

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for ext in ("png", "svg"):
        out = OUT_DIR / f"attack_graph_tree.{ext}"
        fig.savefig(out, dpi=200, bbox_inches="tight", facecolor="white")
        print(f"Kaydedildi: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())