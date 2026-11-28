#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
crAPI dönem projesi için açıklanabilir risk puanlama ve bütçe kısıtlı savunma seçimi.
Bu modül mevcut findings/challenges.csv dosyasını okur; kaynak CSV'yi değiştirmez.
Savunma etkileri simülasyon varsayımlarıdır, canlı sistemde uygulanmış sonuç değildir.
"""
from __future__ import annotations

import argparse
import csv
import itertools
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

# Ağırlıklar: etki %35, istismar edilebilirlik %30,
# maruziyet %20, kanıt güveni %15.
WEIGHTS = {
    "impact": 0.35,
    "exploitability": 0.30,
    "exposure": 0.20,
    "evidence_confidence": 0.15,
}

# Puanlar uzman-kural tabanlı başlangıç varsayımlarıdır; CVSS değildir.
CATEGORY_PROFILE = {
    "BOLA": (5, 4),
    "Broken Authentication": (5, 4),
    "Excessive Data Exposure": (4, 3),
    "Lack of Resources & Rate Limiting": (4, 4),
    "BFLA": (5, 4),
    "Server-Side Request Forgery (SSRF)": (5, 4),
    "Mass Assignment (API6:2023)": (4, 4),
    "NoSQL Injection": (5, 4),
    "SQL Injection": (5, 4),
}

# Her kontrol için maliyet "bütçe birimi" cinsindendir; para birimi değildir.
CONTROLS = [
    {
        "control_id": "C01",
        "name": "Nesne seviyesinde yetkilendirme",
        "cost": 5,
        "effectiveness": 0.85,
        "challenges": [1, 2, 9],
        "rationale": "Her nesne erişiminde oturum sahibi ile nesne sahibini sunucu tarafında karşılaştır.",
        "implementation": "Object-level authorization / ownership check",
    },
    {
        "control_id": "C02",
        "name": "Fonksiyon seviyesinde RBAC/ABAC kontrolü",
        "cost": 4,
        "effectiveness": 0.85,
        "challenges": [7],
        "rationale": "Yönetici işlevlerini rol/izin kontrolü olmadan standart kullanıcıya açma.",
        "implementation": "Function-level authorization",
    },
    {
        "control_id": "C03",
        "name": "Rate limiting ve OTP deneme sınırı",
        "cost": 3,
        "effectiveness": 0.80,
        "challenges": [3, 6],
        "rationale": "Kullanıcı, IP ve işlem bazında hız sınırı; OTP için deneme limiti ve geçici kilitleme uygula.",
        "implementation": "Rate limiting / throttling",
    },
    {
        "control_id": "C04",
        "name": "Yanıt alanı allowlist'i ve veri minimizasyonu",
        "cost": 3,
        "effectiveness": 0.75,
        "challenges": [4, 5],
        "rationale": "API yanıtlarında yalnızca istemcinin ihtiyaç duyduğu alanları DTO/serializer allowlist'i ile döndür.",
        "implementation": "Response schema / data minimization",
    },
    {
        "control_id": "C05",
        "name": "Mass assignment için DTO allowlist'i",
        "cost": 3,
        "effectiveness": 0.85,
        "challenges": [10],
        "rationale": "İstemciden gelen alanları izinli alan listesiyle sınırla; dahili alanların yazılmasını engelle.",
        "implementation": "Input allowlist / DTO binding",
    },
    {
        "control_id": "C06",
        "name": "SSRF URL doğrulama ve egress kısıtlaması",
        "cost": 5,
        "effectiveness": 0.85,
        "challenges": [8, 11],
        "rationale": "Hedef URL'leri allowlist ile doğrula; loopback, private ve metadata ağlarına çıkışı engelle.",
        "implementation": "SSRF validation / network egress policy",
    },
    {
        "control_id": "C07",
        "name": "NoSQL sorgu şeması ve operatör allowlist'i",
        "cost": 4,
        "effectiveness": 0.85,
        "challenges": [12],
        "rationale": "Girdi tiplerini doğrula; istemci girdisinin sorgu operatörü veya nesne haline gelmesini engelle.",
        "implementation": "NoSQL query validation",
    },
    {
        "control_id": "C08",
        "name": "Parametreli SQL sorguları",
        "cost": 4,
        "effectiveness": 0.90,
        "challenges": [13],
        "rationale": "SQL sorgularını string birleştirme yerine parametreli sorgu/prepared statement ile çalıştır.",
        "implementation": "Parameterized queries",
    },
    {
        "control_id": "C09",
        "name": "Hassas endpoint'lerde kimlik doğrulama zorunluluğu",
        "cost": 4,
        "effectiveness": 0.90,
        "challenges": [14],
        "rationale": "Hassas veri/işlem sunan tüm endpoint'lerde token ve oturum doğrulamasını zorunlu kıl.",
        "implementation": "Authentication middleware / deny by default",
    },
    {
        "control_id": "C10",
        "name": "JWT imza ve algoritma doğrulamasını güçlendirme",
        "cost": 4,
        "effectiveness": 0.90,
        "challenges": [15],
        "rationale": "Güçlü anahtar kullan; izin verilen algoritmayı sabitle; imza, issuer, audience ve süreyi doğrula.",
        "implementation": "JWT validation hardening",
    },
]

CONTROL_BY_CHALLENGE = {
    challenge_no: control
    for control in CONTROLS
    for challenge_no in control["challenges"]
}


def read_challenges(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(f"Bulgu CSV dosyası bulunamadı: {path}")
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise ValueError("findings/challenges.csv boş.")
    required = {"challenge_no", "kategori", "durum", "endpoint", "cwe", "notlar"}
    missing = required - set(rows[0].keys())
    if missing:
        raise ValueError(f"CSV kolonları eksik: {', '.join(sorted(missing))}")
    return rows


def evidence_confidence(status: str) -> tuple[int, str]:
    normalized = (status or "").strip().casefold()
    if normalized == "doğrulandı":
        return 5, "Doğrulandı olarak kayıtlı"
    if normalized == "analiz_edildi":
        return 2, "Analiz edildi; nihai doğrulama yok"
    return 1, "Durum doğrulanmış değil"


def score_finding(row: dict[str, str]) -> dict[str, Any]:
    try:
        number = int(row.get("challenge_no", "0"))
    except ValueError:
        number = 0

    category = (row.get("kategori") or "").strip()
    impact, exploitability = CATEGORY_PROFILE.get(category, (3, 3))

    # Challenge 8 analiz aşamasında olduğu için istismar edilebilirlik puanı
    # daha temkinli tutulur; kanıt güveni ayrıca 2/5 olarak puanlanır.
    if number == 8:
        exploitability = 3
    elif number == 14:
        # Authorization denetimi olmadan hassas endpoint erişimi: daha yüksek kolaylık.
        exploitability = 5
    elif number == 15:
        # JWT sahteciliği için anahtar/algoritma koşulunun istismarı gerekir.
        exploitability = 4

    # Envanter endpoint bazında internetten erişilebilirliği doğrulamıyor.
    # Bu nedenle tüm bulgular için 3/5 nötr maruziyet varsayımı kullanılır.
    exposure = 3
    confidence, confidence_note = evidence_confidence(row.get("durum", ""))

    raw = (
        WEIGHTS["impact"] * impact / 5
        + WEIGHTS["exploitability"] * exploitability / 5
        + WEIGHTS["exposure"] * exposure / 5
        + WEIGHTS["evidence_confidence"] * confidence / 5
    )
    score = round(raw * 100, 2)

    if score >= 90:
        level = "Kritik"
    elif score >= 80:
        level = "Yüksek"
    elif score >= 65:
        level = "Orta"
    else:
        level = "Düşük"

    control = CONTROL_BY_CHALLENGE.get(number)
    return {
        "challenge_no": number,
        "category": category,
        "status": row.get("durum", ""),
        "endpoint": row.get("endpoint", ""),
        "cwe": row.get("cwe", ""),
        "impact": impact,
        "exploitability": exploitability,
        "exposure": exposure,
        "evidence_confidence": confidence,
        "evidence_note": confidence_note,
        "risk_score": score,
        "risk_level": level,
        "recommended_control_id": control["control_id"] if control else "",
        "recommended_control": control["name"] if control else "",
        "control_cost_units": control["cost"] if control else "",
        "control_effectiveness_assumption": control["effectiveness"] if control else "",
        "notes": row.get("notlar", ""),
        "scoring_note": "Kural tabanlı proje içi puan; CVSS değildir.",
    }


def choose_controls(risks: list[dict[str, Any]], budget: int) -> dict[str, Any]:
    risk_by_no = {r["challenge_no"]: r["risk_score"] for r in risks}
    best = None
    # 10 kontrol için tüm alt kümeleri denemek (2^10) hesaplama açısından uygundur.
    for count in range(len(CONTROLS) + 1):
        for subset in itertools.combinations(CONTROLS, count):
            cost = sum(c["cost"] for c in subset)
            if cost > budget:
                continue
            benefit = sum(
                risk_by_no.get(ch_no, 0) * control["effectiveness"]
                for control in subset
                for ch_no in control["challenges"]
            )
            ids = tuple(c["control_id"] for c in subset)
            candidate = (benefit, -cost, ids, subset)
            if best is None or candidate[:3] > best[:3]:
                best = candidate

    selected = list(best[3]) if best else []
    selected_ids = {c["control_id"] for c in selected}
    selected_cost = sum(c["cost"] for c in selected)
    total_benefit = round(best[0], 2) if best else 0.0
    return {
        "budget_units": budget,
        "selected_cost_units": selected_cost,
        "remaining_budget_units": budget - selected_cost,
        "selected_control_ids": sorted(selected_ids),
        "selected_controls": selected,
        "modeled_risk_reduction_points": total_benefit,
        "optimization_method": "Exact subset search (0/1 knapsack enumeration)",
        "objective": "Budget sınırı içinde toplam modellenmiş risk azaltımını ençoklamak",
    }


def build_scenarios(risks: list[dict[str, Any]], selection: dict[str, Any]) -> tuple[dict, dict, list[dict]]:
    selected_ids = set(selection["selected_control_ids"])
    selected_controls = {c["control_id"]: c for c in CONTROLS if c["control_id"] in selected_ids}

    before_rows = []
    after_rows = []
    base_total = 0.0
    residual_total = 0.0

    for risk in risks:
        base = float(risk["risk_score"])
        control = CONTROL_BY_CHALLENGE.get(risk["challenge_no"])
        chosen = control if control and control["control_id"] in selected_controls else None
        efficacy = float(chosen["effectiveness"]) if chosen else 0.0
        residual = round(base * (1 - efficacy), 2)
        base_total += base
        residual_total += residual

        before_rows.append({
            "challenge_no": risk["challenge_no"],
            "risk_score": base,
            "risk_level": risk["risk_level"],
            "status": risk["status"],
        })
        after_rows.append({
            "challenge_no": risk["challenge_no"],
            "baseline_risk_score": base,
            "residual_risk_score": residual,
            "risk_reduction_pct_for_finding": round(efficacy * 100, 1),
            "selected_control_id": chosen["control_id"] if chosen else "",
            "selected_control": chosen["name"] if chosen else "",
            "status": risk["status"],
            "scenario_type": "simülasyon",
        })

    reduction_pct = ((base_total - residual_total) / base_total * 100) if base_total else 0
    common = {
        "target": "crAPI",
        "finding_count": len(risks),
        "validated_finding_count": sum(1 for r in risks if r["status"].strip().casefold() == "doğrulandı"),
        "analysis_only_finding_count": sum(1 for r in risks if r["status"].strip().casefold() == "analiz_edildi"),
        "budget_units": selection["budget_units"],
        "selected_control_ids": selection["selected_control_ids"],
        "selected_cost_units": selection["selected_cost_units"],
        "note": "Bu senaryo, önerilen kontrollerin varsayılan etkinlik oranlarıyla modellenmiş simülasyondur; canlı sistemde uygulanmış kontrol sonucu değildir.",
    }
    before = {
        **common,
        "scenario": "before_defense",
        "total_risk_points": round(base_total, 2),
        "findings": before_rows,
    }
    after = {
        **common,
        "scenario": "after_defense_simulation",
        "total_baseline_risk_points": round(base_total, 2),
        "total_residual_risk_points": round(residual_total, 2),
        "risk_reduction_points": round(base_total - residual_total, 2),
        "risk_reduction_percent": round(reduction_pct, 2),
        "findings": after_rows,
    }
    return before, after, after_rows


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def scalarize_graph_attributes(graph) -> None:
    for _, attrs in graph.nodes(data=True):
        for key, value in list(attrs.items()):
            if value is None:
                attrs[key] = ""
            elif isinstance(value, (dict, list, tuple, set)):
                attrs[key] = json.dumps(value, ensure_ascii=False, default=str)
    for _, _, attrs in graph.edges(data=True):
        for key, value in list(attrs.items()):
            if value is None:
                attrs[key] = ""
            elif isinstance(value, (dict, list, tuple, set)):
                attrs[key] = json.dumps(value, ensure_ascii=False, default=str)


def enrich_attack_graph(risks: list[dict[str, Any]], selection: dict[str, Any]) -> str:
    try:
        import networkx as nx
    except ImportError:
        return "NetworkX bulunamadı; graf zenginleştirme atlandı."

    graphml_path = ROOT / "graph" / "attack_graph.graphml"
    json_path = ROOT / "graph" / "attack_graph.json"
    graph = None

    if graphml_path.exists() and graphml_path.stat().st_size > 0:
        graph = nx.read_graphml(graphml_path, force_multigraph=True)
    elif json_path.exists() and json_path.stat().st_size > 0:
        data = json.loads(json_path.read_text(encoding="utf-8"))
        try:
            graph = nx.node_link_graph(data, directed=True, multigraph=True, edges="edges")
        except TypeError:
            graph = nx.node_link_graph(data, directed=True, multigraph=True)
    else:
        return "attack_graph.graphml/json bulunamadı; graf zenginleştirme atlandı."

    if not graph.is_directed():
        graph = nx.MultiDiGraph(graph)

    selected_ids = set(selection["selected_control_ids"])
    finding_ids = set(graph.nodes)

    for risk in risks:
        challenge_no = risk["challenge_no"]
        finding_id = f"finding:challenge:{challenge_no}"
        risk_node = f"risk:challenge:{challenge_no}"
        graph.add_node(
            risk_node,
            node_type="risk",
            challenge_no=str(challenge_no),
            risk_score=float(risk["risk_score"]),
            risk_level=risk["risk_level"],
            evidence_confidence=int(risk["evidence_confidence"]),
            scenario="baseline",
        )
        if finding_id in finding_ids:
            graph.add_edge(finding_id, risk_node, relation="has_risk")

    for control in CONTROLS:
        is_selected = control["control_id"] in selected_ids
        control_node = f"control:{control['control_id']}"
        graph.add_node(
            control_node,
            node_type="defense_control",
            control_id=control["control_id"],
            label=control["name"],
            cost_units=int(control["cost"]),
            effectiveness_assumption=float(control["effectiveness"]),
            selected=bool(is_selected),
            implementation_status="proposed_not_deployed",
        )
        for challenge_no in control["challenges"]:
            risk_node = f"risk:challenge:{challenge_no}"
            if risk_node in graph:
                graph.add_edge(
                    risk_node,
                    control_node,
                    relation="mitigated_by",
                    selected=bool(is_selected),
                )

    scalarize_graph_attributes(graph)
    out_graphml = ROOT / "graph" / "attack_graph_defended.graphml"
    out_json = ROOT / "graph" / "attack_graph_defended.json"
    nx.write_graphml(graph, out_graphml)
    write_json(out_json, nx.node_link_data(graph, link="edges"))
    return f"Zenginleştirilmiş graf: {out_graphml.relative_to(ROOT)} ve {out_json.relative_to(ROOT)}"


def create_plot(risks: list[dict[str, Any]], after_rows: list[dict[str, Any]]) -> str:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return "Matplotlib bulunamadı; grafik görseli atlandı."

    after_by_no = {r["challenge_no"]: r["residual_risk_score"] for r in after_rows}
    labels = [f"C{r['challenge_no']:02d}" for r in risks]
    before_values = [r["risk_score"] for r in risks]
    after_values = [after_by_no[r["challenge_no"]] for r in risks]

    fig, ax = plt.subplots(figsize=(12, 6))
    x = list(range(len(labels)))
    width = 0.38
    ax.bar([i - width / 2 for i in x], before_values, width, label="Önlem öncesi")
    ax.bar([i + width / 2 for i in x], after_values, width, label="Önlem sonrası (simülasyon)")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel("Risk puanı (0-100)")
    ax.set_title("crAPI bulgu bazlı risk karşılaştırması")
    ax.set_ylim(0, 105)
    ax.legend()
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()

    output = ROOT / "report" / "risk_comparison.png"
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=160)
    plt.close(fig)
    return f"Risk grafiği: {output.relative_to(ROOT)}"


def build_report(risks: list[dict[str, Any]], selection: dict[str, Any],
                 before: dict, after: dict, graph_message: str, plot_message: str) -> str:
    lines = [
        "# crAPI Risk Analizi ve Bütçe Kısıtlı Savunma Seçimi",
        "",
        "## Kapsam",
        f"- İncelenen bulgu: {len(risks)}",
        f"- Doğrulanmış bulgu: {before['validated_finding_count']}",
        f"- Analiz aşamasındaki bulgu: {before['analysis_only_finding_count']}",
        "- Challenge 16-18 bu çalışmanın kapsamı dışındadır.",
        "",
        "## Risk modeli",
        "Risk puanı 0-100 aralığında, proje içi kural tabanlı bir modeldir; CVSS puanı değildir.",
        "",
        "| Boyut | Ağırlık |",
        "|---|---:|",
        f"| Etki | %{WEIGHTS['impact']*100:.0f} |",
        f"| İstismar edilebilirlik | %{WEIGHTS['exploitability']*100:.0f} |",
        f"| Maruziyet | %{WEIGHTS['exposure']*100:.0f} |",
        f"| Kanıt güveni | %{WEIGHTS['evidence_confidence']*100:.0f} |",
        "",
        "Maruziyet için endpoint bazında doğrulanmış erişim verisi bulunmadığından tüm bulgularda 3/5 nötr varsayımı kullanılmıştır. Challenge 8 analiz aşamasında olduğu için kanıt güveni 2/5, doğrulanmış bulgularda 5/5 alınmıştır.",
        "",
        "## Bütçe kısıtlı kontrol seçimi",
        f"- Bütçe: {selection['budget_units']} birim",
        f"- Kullanılan bütçe: {selection['selected_cost_units']} birim",
        f"- Kalan bütçe: {selection['remaining_budget_units']} birim",
        f"- Seçilen kontroller: {', '.join(selection['selected_control_ids']) if selection['selected_control_ids'] else 'Yok'}",
        "",
        "| Kontrol | Maliyet | Etkinlik varsayımı |",
        "|---|---:|---:|",
    ]
    for c in selection["selected_controls"]:
        lines.append(f"| {c['control_id']} - {c['name']} | {c['cost']} | %{c['effectiveness']*100:.0f} |")
    lines += [
        "",
        "## Önlem öncesi / sonrası",
        f"- Önlem öncesi toplam risk puanı: {before['total_risk_points']}",
        f"- Simüle edilen artık risk puanı: {after['total_residual_risk_points']}",
        f"- Modellenen risk azalımı: {after['risk_reduction_points']} puan (%{after['risk_reduction_percent']})",
        "",
        "| Bulgu | Durum | Önce | Sonra (simülasyon) | Seçilen kontrol |",
        "|---:|---|---:|---:|---|",
    ]
    after_map = {r["challenge_no"]: r for r in after["findings"]}
    for r in risks:
        a = after_map[r["challenge_no"]]
        lines.append(
            f"| {r['challenge_no']} | {r['status']} | {r['risk_score']} | "
            f"{a['residual_risk_score']} | {a['selected_control'] or 'Seçilmedi'} |"
        )
    lines += [
        "",
        "## Sınırlılıklar ve yorum",
        "- Risk boyutları ve kontrol etkinlikleri uzman-kural tabanlı başlangıç varsayımlarıdır; ampirik olarak kalibre edilmemiştir.",
        "- Savunma seçimi, belirtilen bütçe birimi ve etkinlik varsayımları altında 0/1 knapsack alt küme taramasıyla yapılmıştır.",
        "- Önlem sonrası değerler gerçek ortamda uygulanmış veya yeniden test edilmiş sonuçlar değildir; senaryo simülasyonudur.",
        "- CWE/CAPEC aday eşleştirmeleri bu risk puanlamasında doğrulanmış kabul edilmemiştir.",
        "- ATT&CK tekniği mevcut girdilerde bulunmadığından ATT&CK düğümü üretilmemiştir.",
        "- OpenAPI ile eşleşmeyen dört bulgu endpoint'i graf üzerinde unlisted olarak korunur; sessizce başka endpoint ile eşleştirilmez.",
        "",
        "## Üretilen çıktılar",
        "- `risk_scoring/results.csv`",
        "- `risk_scoring/control_recommendations.csv`",
        "- `risk_scoring/risk_model_metadata.json`",
        "- `defense/control_catalog.csv`",
        "- `defense/selection.json`",
        "- `graph/graph_before.json`",
        "- `graph/graph_after.json`",
        "- `graph/attack_graph_defended.graphml` ve `.json` (graf girdisi mevcutsa)",
        "- `report/risk_comparison.png`",
        "",
        "## Teknik notlar",
        f"- {graph_message}",
        f"- {plot_message}",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="crAPI risk ve savunma senaryosu üreticisi")
    parser.add_argument("--budget", type=int, default=None,
                        help="Bütçe birimi (varsayılan defense/budget_config.json içindeki değer)")
    args = parser.parse_args()

    findings_path = ROOT / "findings" / "challenges.csv"
    risks = [score_finding(row) for row in read_challenges(findings_path)]

    budget_path = ROOT / "defense" / "budget_config.json"
    budget_path.parent.mkdir(parents=True, exist_ok=True)
    if budget_path.exists():
        budget_config = json.loads(budget_path.read_text(encoding="utf-8"))
    else:
        budget_config = {
            "budget_units": 20,
            "note": "Örnek/karşılaştırma amaçlı bütçe birimidir; TL veya başka para birimi değildir."
        }
        write_json(budget_path, budget_config)

    budget = args.budget if args.budget is not None else int(budget_config.get("budget_units", 20))
    if budget < 0:
        raise ValueError("Bütçe negatif olamaz.")

    selection = choose_controls(risks, budget)
    before, after, after_rows = build_scenarios(risks, selection)

    write_csv(ROOT / "risk_scoring" / "results.csv", risks)
    recommendations = []
    for r in risks:
        control = CONTROL_BY_CHALLENGE.get(r["challenge_no"])
        if control:
            recommendations.append({
                "challenge_no": r["challenge_no"],
                "category": r["category"],
                "control_id": control["control_id"],
                "control_name": control["name"],
                "cost_units": control["cost"],
                "effectiveness_assumption": control["effectiveness"],
                "rationale": control["rationale"],
                "deployment_status": "öneri; uygulanmış değil",
            })
    write_csv(ROOT / "risk_scoring" / "control_recommendations.csv", recommendations)

    catalog_rows = [{
        "control_id": c["control_id"],
        "name": c["name"],
        "cost_units": c["cost"],
        "effectiveness_assumption": c["effectiveness"],
        "covered_challenges": ";".join(map(str, c["challenges"])),
        "implementation": c["implementation"],
        "rationale": c["rationale"],
        "status": "proposed_not_deployed",
    } for c in CONTROLS]
    write_csv(ROOT / "defense" / "control_catalog.csv", catalog_rows)

    write_json(ROOT / "defense" / "selection.json", {
        **{k: v for k, v in selection.items() if k != "selected_controls"},
        "selected_controls": selection["selected_controls"],
        "selection_is_simulation": True,
    })
    write_json(ROOT / "graph" / "graph_before.json", before)
    write_json(ROOT / "graph" / "graph_after.json", after)
    write_json(ROOT / "risk_scoring" / "risk_model_metadata.json", {
        "model_type": "weighted_rule_based",
        "is_cvss": False,
        "weights": WEIGHTS,
        "score_range": [0, 100],
        "exposure_default": 3,
        "confidence_mapping": {
            "doğrulandı": 5,
            "analiz_edildi": 2,
            "other": 1,
        },
        "control_effectiveness_values_are_assumptions": True,
        "simulation_only": True,
        "scope": "crAPI challenges 1-15; challenges 16-18 excluded",
    })

    graph_message = enrich_attack_graph(risks, selection)
    plot_message = create_plot(risks, after_rows)
    report = build_report(risks, selection, before, after, graph_message, plot_message)
    report_path = ROOT / "report" / "risk_defense_report.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report, encoding="utf-8")

    print("\n========== RISK & DEFENSE PIPELINE ==========")
    print(f"Bulgu sayısı: {len(risks)}")
    print(f"Doğrulanmış: {before['validated_finding_count']}")
    print(f"Analiz aşamasında: {before['analysis_only_finding_count']}")
    print(f"Bütçe: {budget} birim")
    print(f"Seçilen kontroller: {', '.join(selection['selected_control_ids']) or 'Yok'}")
    print(f"Önceki toplam risk: {before['total_risk_points']}")
    print(f"Simüle artık risk: {after['total_residual_risk_points']}")
    print(f"Risk azalımı: %{after['risk_reduction_percent']}")
    print(f"Graf: {graph_message}")
    print(f"Görsel: {plot_message}")
    print(f"Rapor: {report_path.relative_to(ROOT)}")
    print("\nNot: Önlem sonrası değerler simülasyondur; canlı uygulama sonucu değildir.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"HATA: {exc}", file=sys.stderr)
        raise
