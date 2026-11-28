
import csv
import json
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parents[1]

CSV_PATH = ROOT / "recon" / "service_inventory.csv"
OPENAPI_PATH = ROOT / "recon" / "openapi_spec.json"
OUTPUT_PATH = ROOT / "recon" / "service_inventory.md"

HTTP_METHODS = {
    "get", "post", "put", "patch", "delete",
    "options", "head", "trace"
}


def clean(value):
    value = str(value or "").strip()
    return value.replace("\n", " ").replace("\r", " ")


def main():
    if not CSV_PATH.exists():
        raise FileNotFoundError(CSV_PATH)

    with CSV_PATH.open(
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as file:
        reader = csv.DictReader(file)
        fields = reader.fieldnames or []
        rows = list(reader)

    if not rows:
        raise ValueError("service_inventory.csv dosyasında kayıt bulunamadı.")

    openapi = {}
    if OPENAPI_PATH.exists():
        openapi = json.loads(
            OPENAPI_PATH.read_text(encoding="utf-8")
        )

    paths = openapi.get("paths", {})

    operations = []
    for path, methods in paths.items():
        for method, operation in methods.items():
            if method.lower() in HTTP_METHODS:
                operations.append((path, method, operation))

    status_field = next(
        (field for field in fields if field.lower() == "source_status"),
        None
    )

    statuses = Counter(
        clean(row.get(status_field, ""))
        for row in rows
    ) if status_field else Counter()

    lines = [
        "# crAPI Service Inventory",
        "",
        "> Bu belge recon/service_inventory.csv dosyasından",
        "> otomatik oluşturulmuştur.",
        "> Kaynak CSV'deki bilgiler değiştirilmeden aktarılmıştır.",
        "",
        "## 1. Genel Bakış",
        "",
        f"- Envanterdeki servis/kayıt sayısı: **{len(rows)}**",
        f"- OpenAPI endpoint yolu sayısı: **{len(paths)}**",
        f"- OpenAPI benzersiz operasyon sayısı: **{len(operations)}**",
        f"- Postman toplam istek sayısı: **{openapi.get('x-postman-total-requests', 'Belirtilmemiş')}**",
        "",
        "## 2. Kaynak Durumu Dağılımı",
        "",
    ]

    if statuses:
        for status, count in statuses.items():
            lines.append(f"- `{status or 'Belirtilmemiş'}`: {count}")
    else:
        lines.append("- CSV dosyasında source_status alanı bulunamadı.")

    lines.extend([
        "",
        "## 3. Servis Envanteri",
        "",
        "Aşağıdaki kayıtlar kaynak CSV'deki alanlarla oluşturulmuştur.",
        "Boş alanlar `Belirtilmemiş` olarak gösterilir.",
        ""
    ])

    for index, row in enumerate(rows, start=1):
        service_name = clean(
            row.get("service_name")
            or row.get("service_id")
            or f"Service {index}"
        )

        service_id = clean(row.get("service_id"))

        lines.extend([
            f"### {index}. {service_name}",
            ""
        ])

        if service_id:
            lines.append(f"- **service_id:** `{service_id}`")

        for field in fields:
            if field in ("service_name", "service_id"):
                continue

            value = clean(row.get(field))

            if not value:
                value = "Belirtilmemiş"

            lines.append(f"- **{field}:** {value}")

        lines.append("")

    lines.extend([
        "## 4. OpenAPI Kaynak Özeti",
        "",
        "OpenAPI belgesi Postman koleksiyonundan oluşturulmuştur.",
        "",
        f"- OpenAPI sürümü: `{openapi.get('openapi', 'Bulunamadı')}`",
        f"- Kaynak koleksiyon: `{openapi.get('x-postman-source', 'Belirtilmemiş')}`",
        f"- Toplam Postman isteği: {openapi.get('x-postman-total-requests', 'Belirtilmemiş')}",
        f"- Benzersiz operasyon: {len(operations)}",
        f"- Benzersiz path: {len(paths)}",
        "",
        "### 4.1 API Etiketleri",
        ""
    ])

    tag_counts = Counter()

    for _, _, operation in operations:
        for tag in operation.get("tags", []):
            tag_counts[tag] += 1

    if tag_counts:
        for tag, count in sorted(tag_counts.items()):
            lines.append(f"- **{tag}:** {count} operasyon")
    else:
        lines.append("- OpenAPI etiket bilgisi bulunamadı.")

    lines.extend([
        "",
        "## 5. Veri Kalitesi ve Sınırlamalar",
        "",
        "- Bu belge kaynak CSV'deki bilgileri yansıtır.",
        "- `source_status` alanı, bilginin doğrulama durumunu belirtir.",
        "- Doğrulanmamış teknoloji, port veya bağımlılık bilgileri kesin kabul edilmemelidir.",
        "- OpenAPI belgesi Postman koleksiyonunda bulunan isteklerden üretilmiştir.",
        "- Postman koleksiyonunda bulunmayan endpoint'ler bu belgede varsayılmamıştır.",
        "- API response şemaları koleksiyonda yeterli bilgi yoksa oluşturulmamıştır.",
        "- Servis envanteri ile gerçek çalışma ortamı ayrıca karşılaştırılmalıdır.",
        "",
        "## 6. Sonraki Çalışmalar",
        "",
        "1. Servislerin gerçek teknoloji ve port bilgilerinin doğrulanması.",
        "2. Servisler arası bağımlılıkların kontrol edilmesi.",
        "3. API endpoint'lerinin servislerle ilişkilendirilmesi.",
        "4. Erişilebilirlik ve saldırı grafı analizinde bu envanterin kullanılması.",
        ""
    ])

    OUTPUT_PATH.write_text(
        "\n".join(lines),
        encoding="utf-8"
    )

    print("INVENTORY REPORT CREATED")
    print("Output:", OUTPUT_PATH)
    print("Service records:", len(rows))
    print("OpenAPI paths:", len(paths))
    print("OpenAPI operations:", len(operations))
    print("Source status categories:", len(statuses))


if __name__ == "__main__":
    main()
