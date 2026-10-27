"""Summarize recorded challenge outcomes and render category charts.

Run from the repository root with:
    python findings/analyze_challenges.py

The script reads findings/challenges.csv and writes findings/analysis.md plus
category charts under findings/figures/. Missing challenge records are reported
as missing; they are never treated as failed or validated tests.
"""

from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


FINDINGS_DIR = Path(__file__).resolve().parent
SOURCE = FINDINGS_DIR / "challenges.csv"
FIGURES_DIR = FINDINGS_DIR / "figures"
REPORT = FINDINGS_DIR / "analysis.md"
RANGES = ((1, 9, "01_09"), (10, 18, "10_18"))
REQUIRED_COLUMNS = {"challenge_no", "kategori", "durum"}

FINAL_POSITIVE = {"doğrulandı", "verified", "confirmed"}
FINAL_NEGATIVE = {
    "çürütüldü",
    "doğrulanamadı",
    "yanlış pozitif",
    "rejected",
    "not confirmed",
    "false positive",
    "not reproduced",
}
FINAL_STATUSES = FINAL_POSITIVE | FINAL_NEGATIVE
ANALYSIS_STATUSES = {"analiz_edildi", "analyzed", "inconclusive", "needs review"}
PENDING_STATUSES = {
    "beklemede",
    "pending",
    "planlandı",
    "planned",
    "not started",
    "not_started",
    "başlanmadı",
    "test edilmedi",
    "not tested",
}
KNOWN_STATUSES = FINAL_STATUSES | ANALYSIS_STATUSES | PENDING_STATUSES
STATUS_GROUPS = ("doğrulandı", "analiz_edildi", "diğer nihai sonuç")
STATUS_LABELS = {
    "doğrulandı": "Doğrulandı",
    "analiz_edildi": "Analiz edildi",
    "diğer nihai sonuç": "Diğer nihai sonuç",
}
STATUS_COLORS = {
    "doğrulandı": "#287D8E",
    "analiz_edildi": "#E3A344",
    "diğer nihai sonuç": "#9AA7AD",
}


def read_rows() -> list[dict[str, str]]:
    with SOURCE.open("r", encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        if not reader.fieldnames or not REQUIRED_COLUMNS.issubset(reader.fieldnames):
            missing = sorted(REQUIRED_COLUMNS - set(reader.fieldnames or []))
            raise ValueError(f"CSV is missing required columns: {', '.join(missing)}")

        rows: list[dict[str, str]] = []
        seen: set[int] = set()
        for line_number, row in enumerate(reader, start=2):
            try:
                challenge_no = int((row.get("challenge_no") or "").strip())
            except ValueError as exc:
                raise ValueError(
                    f"Invalid challenge_no on CSV line {line_number}"
                ) from exc
            if challenge_no in seen:
                raise ValueError(f"Duplicate challenge_no: {challenge_no}")
            seen.add(challenge_no)

            category = (row.get("kategori") or "").strip()
            status = (row.get("durum") or "").strip()
            if not category or not status:
                raise ValueError(
                    f"Challenge {challenge_no} needs both kategori and durum"
                )
            if status.casefold() not in KNOWN_STATUSES:
                raise ValueError(
                    f"Unrecognized status {status!r} for Challenge {challenge_no}; "
                    "use a known final, analysis, or pending status"
                )
            rows.append(
                {
                    **row,
                    "challenge_no": str(challenge_no),
                    "kategori": category,
                    "durum": status,
                }
            )
        return rows


def pct(value: int, total: int) -> str:
    return f"{(100 * value / total):.1f}%" if total else "—"


def status_group(status: str) -> str:
    normalized = status.casefold()
    if normalized in FINAL_POSITIVE:
        return "doğrulandı"
    if normalized in ANALYSIS_STATUSES:
        return "analiz_edildi"
    if normalized in FINAL_NEGATIVE:
        return "diğer nihai sonuç"
    raise ValueError(f"Status {status!r} is not a result status")


def make_chart(
    rows: list[dict[str, str]],
    start: int,
    end: int,
    suffix: str,
    missing: list[int],
    pending: list[int],
) -> str | None:
    if not rows:
        return None

    category_counts: dict[str, Counter[str]] = {}
    for row in rows:
        category = row["kategori"]
        category_counts.setdefault(category, Counter())[status_group(row["durum"])] += 1
    totals = {
        category: sum(counts.values())
        for category, counts in category_counts.items()
    }
    labels = sorted(totals, key=lambda category: (-totals[category], category.casefold()))
    total = len(rows)

    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    output = FIGURES_DIR / f"category_distribution_{suffix}.png"
    height = max(4.2, 0.62 * len(labels) + 1.8)
    fig, ax = plt.subplots(figsize=(10, height), constrained_layout=True)
    left = [0] * len(labels)
    active_groups = [
        group
        for group in STATUS_GROUPS
        if any(category_counts[category][group] for category in labels)
    ]
    for group in active_groups:
        values = [category_counts[category][group] for category in labels]
        bars = ax.barh(
            labels,
            values,
            left=left,
            label=STATUS_LABELS[group],
            color=STATUS_COLORS[group],
            edgecolor="white",
            linewidth=0.7,
        )
        for bar, value in zip(bars, values):
            if value:
                ax.text(
                    bar.get_x() + bar.get_width() / 2,
                    bar.get_y() + bar.get_height() / 2,
                    str(value),
                    ha="center",
                    va="center",
                    fontsize=8,
                    color="white" if group == "doğrulandı" else "#263238",
                    fontweight="bold",
                )
        left = [offset + value for offset, value in zip(left, values)]
    ax.invert_yaxis()
    ax.set_xlabel("Challenge kaydı (renk durumu gösterir)")
    status = "ÖN ANALİZ — " if missing or pending else ""
    ax.set_title(
        f"{status}Challenge {start}–{end}: kategori dağılımı ve durum\n"
        f"Sonuç bulunan {total}/{end - start + 1}; yüzdeler bu satırlar üzerinden"
    )
    max_value = max(totals.values())
    ax.set_xlim(0, max_value * 1.48)
    ax.xaxis.set_major_locator(plt.MaxNLocator(integer=True))
    ax.xaxis.grid(True, color="#DCE5E8", linewidth=0.8)
    ax.set_axisbelow(True)
    for spine in ("top", "right", "left"):
        ax.spines[spine].set_visible(False)
    for index, category in enumerate(labels):
        ax.text(
            totals[category] + max_value * 0.035,
            index,
            f"{totals[category]}  ({pct(totals[category], total)})",
            va="center",
            fontsize=9,
            color="#17343B",
        )
    ax.legend(title="Durum", loc="lower right", frameon=False)
    notes = []
    if missing:
        notes.append("Kayıt yok: " + ", ".join(map(str, missing)))
    if pending:
        notes.append("Beklemede: " + ", ".join(map(str, pending)))
    if notes:
        ax.text(
            0.99,
            -0.15,
            "  |  ".join(notes),
            transform=ax.transAxes,
            ha="right",
            va="top",
            fontsize=8,
            color="#8A3B12",
        )
    fig.savefig(output, dpi=180, facecolor="white")
    plt.close(fig)
    return output.relative_to(FINDINGS_DIR).as_posix()


def render_range(rows: list[dict[str, str]], start: int, end: int, suffix: str) -> tuple[str, list[int]]:
    recorded = [
        row for row in rows if start <= int(row["challenge_no"]) <= end
    ]
    present = {int(row["challenge_no"]) for row in recorded}
    missing = [number for number in range(start, end + 1) if number not in present]
    pending_rows = [row for row in recorded if row["durum"].casefold() in PENDING_STATUSES]
    pending = sorted(int(row["challenge_no"]) for row in pending_rows)
    tested = [row for row in recorded if row["durum"].casefold() not in PENDING_STATUSES]
    categories = Counter(row["kategori"] for row in tested)
    statuses = Counter(row["durum"] for row in recorded)
    finalized = [row for row in tested if row["durum"].casefold() in FINAL_STATUSES]
    confirmed = sum(row["durum"].casefold() in FINAL_POSITIVE for row in finalized)
    analyzed = sum(row["durum"].casefold() in ANALYSIS_STATUSES for row in tested)
    other_final = len(finalized) - confirmed
    validation_rate = pct(confirmed, len(finalized))
    confirmed_share = pct(confirmed, len(tested))
    category_statuses = {
        category: Counter(
            status_group(row["durum"])
            for row in tested
            if row["kategori"] == category
        )
        for category in categories
    }
    chart = make_chart(tested, start, end, suffix, missing, pending)
    state = " — ÖN ANALİZ (EKSİK/BEKLEYEN TEST)" if missing or pending else ""

    lines = [
        f"## Challenge {start}–{end}{state}",
        "",
        f"- Planlanan Challenge numarası: {end - start + 1}",
        f"- CSV'de kayıtlı Challenge satırı: {len(recorded)} ({pct(len(recorded), end - start + 1)} kapsam)",
        f"- Beklemede olmayan sonuç satırı: {len(tested)} ({pct(len(tested), end - start + 1)} kapsam)",
        f"- Beklemede olan Challenge numaraları: {', '.join(map(str, pending)) if pending else 'yok'}",
        f"- CSV'de kaydı bulunmayan numaralar: {', '.join(map(str, missing)) if missing else 'yok'}",
        f"- Duruma göre: doğrulandı {confirmed}, analiz edildi {analyzed}, diğer nihai sonuç {other_final}",
        f"- Sonuç satırları içindeki doğrulanmış payı: {confirmed_share} ({confirmed}/{len(tested)})",
        f"- Nihai sonuçlar içindeki doğrulama oranı: {validation_rate} ({confirmed}/{len(finalized)})",
        "- Durum sayıları: " + (", ".join(f"`{name}`: {count}" for name, count in sorted(statuses.items())) or "yok"),
        "",
    ]

    if categories:
        lines += [
            "| Kategori | Sonuç kaydı | Pay | Doğrulandı | Analiz edildi | Diğer nihai sonuç |",
            "|---|---:|---:|---:|---:|---:|",
        ]
        for category, count in sorted(categories.items(), key=lambda item: (-item[1], item[0].casefold())):
            by_status = category_statuses[category]
            lines.append(
                f"| {category} | {count} | {pct(count, len(tested))} | "
                f"{by_status['doğrulandı']} | {by_status['analiz_edildi']} | "
                f"{by_status['diğer nihai sonuç']} |"
            )
        lines.append("")
        leading_count = max(categories.values())
        leading_categories = sorted(
            category for category, count in categories.items() if count == leading_count
        )
        lines.append(
            f"- En sık görülen kategori: {', '.join(leading_categories)} "
            f"({leading_count}/{len(tested)}, {pct(leading_count, len(tested))})."
        )
        lines.append("")
    else:
        lines += ["Bu aralıkta test sonucu bulunan satır yok.", ""]

    if chart:
        lines += [f"![Challenge {start}–{end} kategori dağılımı; renkler durumları gösterir]({chart})", ""]
        if missing or pending:
            lines += [
                "> Bu grafik ön analizdir. Kategori paydası yalnızca beklemede olmayan kayıtlı sonuç satırlarıdır. Bekleyen veya kaydı olmayan Challenge'lar başarılı, başarısız ya da doğrulanmış sayılmamıştır.",
                "",
            ]
    return "\n".join(lines), missing


def main() -> None:
    rows = read_rows()
    planned_numbers = {
        number
        for start, end, _ in RANGES
        for number in range(start, end + 1)
    }
    out_of_scope = sorted(
        int(row["challenge_no"])
        for row in rows
        if int(row["challenge_no"]) not in planned_numbers
    )
    if out_of_scope:
        raise ValueError(
            "Challenge numbers are outside the configured analysis ranges: "
            + ", ".join(map(str, out_of_scope))
        )

    recorded_numbers = {int(row["challenge_no"]) for row in rows}
    missing_numbers = sorted(planned_numbers - recorded_numbers)
    pending_rows = [row for row in rows if row["durum"].casefold() in PENDING_STATUSES]
    result_rows = [row for row in rows if row["durum"].casefold() not in PENDING_STATUSES]
    final_rows = [row for row in result_rows if row["durum"].casefold() in FINAL_STATUSES]
    confirmed = sum(row["durum"].casefold() in FINAL_POSITIVE for row in final_rows)
    analyzed = sum(row["durum"].casefold() in ANALYSIS_STATUSES for row in result_rows)
    other_final = len(final_rows) - confirmed
    planned_count = len(planned_numbers)
    sections = [
        "# Challenge testlerinin istatistiksel özeti",
        "",
        "## Genel kapsam",
        "",
        f"- Planlanan Challenge numarası: {planned_count}",
        f"- CSV'de kayıtlı benzersiz Challenge: {len(recorded_numbers)} ({pct(len(recorded_numbers), planned_count)} kapsam)",
        f"- Beklemede olmayan sonuç kaydı: {len(result_rows)}; beklemede: {len(pending_rows)}; kaydı yok: {len(missing_numbers)}",
        f"- Durum sayıları: doğrulandı {confirmed}, analiz edildi {analyzed}, diğer nihai sonuç {other_final}",
        f"- Kayıtlı sonuçlar içindeki doğrulanmış payı: {pct(confirmed, len(result_rows))} ({confirmed}/{len(result_rows)})",
        f"- Nihai sonuçlar içindeki doğrulama oranı: {pct(confirmed, len(final_rows))} ({confirmed}/{len(final_rows)})",
        f"- Kaydı bulunmayan numaralar: {', '.join(map(str, missing_numbers)) if missing_numbers else 'yok'}",
        "",
        "## Yöntem",
        "",
        "- Kaynak: `findings/challenges.csv`. Postman koleksiyonu istek ve test betiklerini içerir; çalıştırma sonuçlarının dışa aktarımı değildir.",
        "- Analiz birimi benzersiz `challenge_no` içeren CSV satırıdır; kanıt dosyaları veya yinelenen ekran görüntüleri ayrı bulgu olarak sayılmaz. Her challenge tek ana kategoriye sayılır.",
        "- Kategori paydası ilgili aralıktaki beklemede olmayan, CSV'de kayıtlı sonuç satırlarıdır. `analiz_edildi` kategori sayımına girer ve grafikte doğrulanmış bulgulardan ayrı renkle gösterilir.",
        "- Doğrulanmış pay = `doğrulandı` ÷ beklemede olmayan kayıtlı sonuç satırları. Doğrulama oranı = `doğrulandı` ÷ nihai durumu olan testler (`doğrulandı` + nihai olumsuz sonuç). Analiz edilen, bekleyen ve kaydı olmayan satırlar bu oranın paydasına girmez.",
        "- Kayıt kapsamı, planlanan challenge numaralarına göre hesaplanır. Eksik kayıtlar tamamlanmış veya başarısız sayılmaz; aralık raporlarında ayrıca listelenir.",
        "- Kategori yoğunluğu, test kayıtlarının dağılımını gösterir; tek başına zafiyet önemini veya risk seviyesini göstermez.",
        "- CSV güncellendikten sonra rapor ve grafikler depo kökünden `python findings/analyze_challenges.py` komutuyla yeniden üretilir.",
        "",
    ]
    for start, end, suffix in RANGES:
        section, _ = render_range(rows, start, end, suffix)
        sections.append(section)
    REPORT.write_text("\n".join(sections).rstrip() + "\n", encoding="utf-8")
    print(f"Wrote {REPORT}")
    for _, _, suffix in RANGES:
        chart = FIGURES_DIR / f"category_distribution_{suffix}.png"
        if chart.exists():
            print(f"Wrote {chart}")


if __name__ == "__main__":
    main()
