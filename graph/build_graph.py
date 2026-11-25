"""findings/challenges.csv -> graph/graph_after.json

Yapı: crAPI System -> saldırı grubu -> challenge.
CSV'deki 'attack' sütunundaki "5 -> 10" gibi değerler, gruplar arası tek bir
'chain' (saldırı zinciri) kenarı olarak eklenir.
"""
import csv
import json
import re
import sys
from pathlib import Path

CSV_PATH = Path("findings/challenges.csv")
OUTPUT_PATH = Path("graph/graph_after.json")

ROOT_ID = "root"

# (grup_id, gösterilecek ad, kategori içinde aranacak anahtar kelimeler)
GROUPS = [
    ("access_control", "Access Control", ("bola", "bfla")),
    ("authentication", "Authentication", ("broken authentication",)),
    ("data_exposure", "Sensitive Data Exposure", ("data exposure",)),
    ("injection", "Injection", ("sql injection", "nosql")),
    ("request_manipulation", "Request Manipulation", ("ssrf", "mass assignment")),
    ("resource_abuse", "Resource Abuse", ("resources", "rate limit")),
]
OTHER_GROUP = ("other", "Other", ())

# Uzun kategori adları için grafikte kullanılacak kısa adlar
SHORT_NAMES = {
    "Lack of Resources & Rate Limiting": "Rate Limiting",
    "Server-Side Request Forgery (SSRF)": "SSRF",
    "Mass Assignment (API6:2023)": "Mass Assignment",
    "Excessive Data Exposure": "Data Exposure",
    "Broken Authentication (Missing Authentication)": "Missing Auth",
    "Broken Authentication (Improper JWT Validation)": "JWT Validation",
}

CHAIN_RE = re.compile(r"(\d+)\s*->\s*(\d+)")


def find_group(kategori: str):
    k = kategori.lower()
    for group in GROUPS:
        if any(word in k for word in group[2]):
            return group
    return OTHER_GROUP


def main() -> int:
    if not CSV_PATH.exists():
        print(f"Hata: {CSV_PATH} bulunamadı. Komutu depo kökünden çalıştır.")
        return 1

    nodes = [{"id": ROOT_ID, "label": "crAPI System", "type": "root"}]
    edges = []
    seen_groups = set()
    challenge_ids = set()
    chains = set()

    with open(CSV_PATH, "r", encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))

    for row in rows:
        no = (row.get("challenge_no") or "").strip()
        if not no.isdigit():
            continue
        kategori = (row.get("kategori") or "Bilinmeyen").strip()
        gid, glabel, _ = find_group(kategori)

        if gid not in seen_groups:
            seen_groups.add(gid)
            nodes.append({"id": gid, "label": glabel, "type": "group"})
            edges.append({"source": ROOT_ID, "target": gid, "type": "contains"})

        cid = f"c{int(no)}"
        challenge_ids.add(cid)
        nodes.append({
            "id": cid,
            "label": f"C{int(no)}",
            "short_name": SHORT_NAMES.get(kategori, kategori),
            "type": "challenge",
            "number": int(no),
            "group": gid,
            "category": kategori,
            "status": (row.get("durum") or "").strip(),
            "endpoint": (row.get("endpoint") or "").strip(),
            "cwe": (row.get("cwe") or "").strip(),
            "capec": (row.get("capec") or "").strip(),
        })
        edges.append({"source": gid, "target": cid, "type": "contains"})

        m = CHAIN_RE.search(row.get("attack") or "")
        if m:
            chains.add((f"c{int(m.group(1))}", f"c{int(m.group(2))}"))

    for src, dst in sorted(chains):
        if src in challenge_ids and dst in challenge_ids:
            edges.append({"source": src, "target": dst, "type": "chain"})
        else:
            print(f"Uyarı: zincir {src} -> {dst} CSV'de olmayan bir challenge içeriyor, atlandı.")

    # Grup sırası CSV'deki ilk görünüşe değil, GROUPS listesine göre olsun
    order = {g[0]: i for i, g in enumerate(GROUPS + [OTHER_GROUP])}
    type_rank = {"root": 0, "group": 1, "challenge": 2}
    nodes.sort(key=lambda n: (type_rank[n["type"]],
                              order.get(n["id"], 0),
                              n.get("number", 0)))

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump({"nodes": nodes, "edges": edges}, f, ensure_ascii=False, indent=2)

    print(f"{len(challenge_ids)} challenge, {len(seen_groups)} grup, "
          f"{len(chains)} zincir -> {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())