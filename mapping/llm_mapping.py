"""Offline, rule-based CWE/CAPEC mapping review for findings/challenges.csv.

Despite the historical filename, this module does not call an LLM. It uses a
small, curated rule set and official MITRE definition links to propose review
candidates. It never edits the source CSV and never marks a mapping verified.

Usage from the repository root:
    python mapping/llm_mapping.py
    python mapping/llm_mapping.py --check

The normal command prints a JSON report to stdout. No API key, network access,
or non-standard Python package is needed at runtime.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = REPO_ROOT / "findings" / "challenges.csv"
SOURCE_REVIEWED_ON = "2026-10-27"


# The registry records the official entry title, abstraction, and definition
# URL reviewed while preparing this rule set. It is not a live MITRE feed and
# it does not assert that MITRE endorses a finding-to-entry mapping.
CWE_CATALOG: dict[str, dict[str, str]] = {
    "CWE-639": {
        "title": "Authorization Bypass Through User-Controlled Key",
        "abstraction": "Base",
        "mapping_guidance": "allowed",
    },
    "CWE-307": {
        "title": "Improper Restriction of Excessive Authentication Attempts",
        "abstraction": "Base",
        "mapping_guidance": "allowed",
    },
    "CWE-213": {
        "title": "Exposure of Sensitive Information Due to Incompatible Policies",
        "abstraction": "Base",
        "mapping_guidance": "allowed; fit depends on policy conflict",
    },
    "CWE-200": {
        "title": "Exposure of Sensitive Information to an Unauthorized Actor",
        "abstraction": "Class",
        "mapping_guidance": "allowed; broad parent weakness",
    },
    "CWE-201": {
        "title": "Insertion of Sensitive Information Into Sent Data",
        "abstraction": "Base",
        "mapping_guidance": "allowed",
    },
    "CWE-359": {
        "title": "Exposure of Private Personal Information to an Unauthorized Actor",
        "abstraction": "Base",
        "mapping_guidance": "allowed",
    },
    "CWE-497": {
        "title": "Exposure of Sensitive System Information to an Unauthorized Control Sphere",
        "abstraction": "Base",
        "mapping_guidance": "allowed",
    },
    "CWE-770": {
        "title": "Allocation of Resources Without Limits or Throttling",
        "abstraction": "Base",
        "mapping_guidance": "allowed",
    },
    "CWE-799": {
        "title": "Improper Control of Interaction Frequency",
        "abstraction": "Class",
        "mapping_guidance": "allowed with review; inspect more-specific children",
    },
    "CWE-285": {
        "title": "Improper Authorization",
        "abstraction": "Class",
        "mapping_guidance": "discouraged for real-world mapping due to abstraction",
    },
    "CWE-862": {
        "title": "Missing Authorization",
        "abstraction": "Class",
        "mapping_guidance": "allowed with review",
    },
    "CWE-863": {
        "title": "Incorrect Authorization",
        "abstraction": "Class",
        "mapping_guidance": "allowed with review",
    },
    "CWE-918": {
        "title": "Server-Side Request Forgery (SSRF)",
        "abstraction": "Base",
        "mapping_guidance": "allowed",
    },
    "CWE-915": {
        "title": "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
        "abstraction": "Base",
        "mapping_guidance": "allowed",
    },
}

CAPEC_CATALOG: dict[str, dict[str, Any]] = {
    "CAPEC-1": {
        "title": "Accessing Functionality Not Properly Constrained by ACLs",
        "abstraction": "Standard",
        "deprecated": False,
    },
    "CAPEC-49": {
        "title": "Password Brute Forcing",
        "abstraction": "Standard",
        "deprecated": False,
    },
    "CAPEC-77": {
        "title": "Manipulating User-Controlled Variables",
        "abstraction": "Standard",
        "deprecated": False,
    },
    "CAPEC-112": {
        "title": "Brute Force",
        "abstraction": "Meta",
        "deprecated": False,
    },
    "CAPEC-118": {
        "title": "Collect and Analyze Information",
        "abstraction": "Category",
        "deprecated": False,
    },
    "CAPEC-125": {
        "title": "Flooding",
        "abstraction": "Meta",
        "deprecated": False,
    },
    "CAPEC-130": {
        "title": "Excessive Allocation",
        "abstraction": "Meta",
        "deprecated": False,
    },
    "CAPEC-210": {
        "title": "Abuse Existing Functionality",
        "abstraction": "Category",
        "deprecated": False,
    },
    "CAPEC-233": {
        "title": "Privilege Escalation",
        "abstraction": "Meta",
        "deprecated": False,
    },
    "CAPEC-315": {
        "title": "DEPRECATED: TCP/IP Fingerprinting Probes",
        "abstraction": "Standard",
        "deprecated": True,
    },
    "CAPEC-664": {
        "title": "Server Side Request Forgery",
        "abstraction": "Standard",
        "deprecated": False,
    },
}


def official_url(kind: str, identifier: str) -> str:
    number = identifier.split("-", 1)[1]
    if kind == "cwe":
        return f"https://cwe.mitre.org/data/definitions/{number}.html"
    return f"https://capec.mitre.org/data/definitions/{number}.html"


def field(row: dict[str | None, Any], *names: str) -> str:
    for name in names:
        value = row.get(name)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def read_findings(source: Path) -> tuple[list[dict[str, Any]], list[str]]:
    if not source.is_file():
        raise FileNotFoundError(f"Findings CSV not found: {source}")

    findings: list[dict[str, Any]] = []
    global_warnings: list[str] = []
    seen_numbers: set[str] = set()
    with source.open("r", encoding="utf-8-sig", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        if not reader.fieldnames:
            return [], ["CSV başlığı veya kayıt satırı bulunamadı."]

        for row_number, row in enumerate(reader, start=2):
            challenge_no = field(row, "challenge_no", "challenge", "id")
            if not challenge_no:
                challenge_no = f"satır-{row_number}"
                global_warnings.append(
                    f"CSV satırı {row_number}: challenge_no eksik; geçici kimlik {challenge_no} kullanıldı."
                )
            if challenge_no in seen_numbers:
                global_warnings.append(
                    f"CSV satırı {row_number}: challenge_no {challenge_no!r} yineleniyor."
                )
            seen_numbers.add(challenge_no)

            category = field(row, "kategori", "category")
            status = field(row, "durum", "status")
            existing_cwe = field(row, "cwe", "CWE")
            existing_capec = field(row, "capec", "CAPEC")
            description = field(
                row,
                "notlar",
                "description",
                "açıklama",
                "aciklama",
                "finding_description",
            )
            endpoint = field(row, "endpoint", "path", "url")
            warnings: list[str] = []
            if not category:
                warnings.append("Kategori alanı eksik; kategori kuralı uygulanamadı.")
            if not description:
                warnings.append(
                    "Açıklama/not alanı eksik; eşleme yalnızca mevcut kategori ve endpoint sinyallerine dayanabilir."
                )
            if not status:
                warnings.append("Durum alanı eksik; bulgunun doğrulanma durumu bilinmiyor.")
            if not existing_cwe:
                warnings.append("Mevcut CWE alanı boş; yalnızca aday CWE önerileri üretilecek.")
            if not existing_capec:
                warnings.append("Mevcut CAPEC alanı boş; yalnızca aday CAPEC önerileri üretilecek.")
            if not endpoint:
                warnings.append("Endpoint alanı eksik; saldırı yüzeyi bağlamı değerlendirilemedi.")

            findings.append(
                {
                    "challenge_no": challenge_no,
                    "category": category,
                    "status": status,
                    "description": description,
                    "endpoint": endpoint,
                    "existing_cwe": existing_cwe,
                    "existing_capec": existing_capec,
                    "warnings": warnings,
                }
            )

    if not findings:
        global_warnings.append("CSV'de eşlenecek challenge satırı yok.")
    return findings, global_warnings


def candidate(
    kind: str,
    identifier: str,
    confidence: str,
    rationale: str,
    *,
    caveat: str = "",
) -> dict[str, Any]:
    catalog = CWE_CATALOG if kind == "cwe" else CAPEC_CATALOG
    entry = catalog.get(identifier)
    if entry is None:
        title = "Katalogda bulunmuyor"
        abstraction = "unknown"
        deprecated = False
        guidance = "Kaynak doğrulanmadı"
        source_status = "not_in_curated_mitre_registry"
    else:
        title = str(entry["title"])
        abstraction = str(entry["abstraction"])
        deprecated = bool(entry.get("deprecated", False))
        guidance = str(entry.get("mapping_guidance", "definition only; case mapping not endorsed"))
        source_status = "official_definition_reviewed_offline"

    is_general = kind == "capec" and abstraction in {"Category", "Meta"}
    flags: list[str] = []
    if deprecated:
        flags.append("deprecated")
    if is_general:
        flags.append("overly_general_category_or_meta_pattern")
    if caveat:
        flags.append("conditional_or_limited_fit")

    result = {
        "type": "software_weakness" if kind == "cwe" else "attack_pattern",
        "id": identifier,
        "title": title,
        "abstraction": abstraction,
        "confidence": confidence,
        "rationale": rationale,
        "source_url": official_url(kind, identifier),
        "source_status": source_status,
        "source_reviewed_on": SOURCE_REVIEWED_ON if entry else None,
        "mapping_verification_status": "candidate_not_verified_human_review_required",
        "mitre_case_mapping_endorsed": False,
        "deprecated": deprecated,
        "too_general": is_general,
        "flags": flags,
        "human_review_required": True,
    }
    if guidance:
        result["mitre_mapping_guidance"] = guidance
    if caveat:
        result["caveat"] = caveat
    return result


def infer_candidates(finding: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    category = finding["category"].casefold()
    text = " ".join(
        (finding["category"], finding["description"], finding["endpoint"])
    ).casefold()
    cwe: list[dict[str, Any]] = []
    capec: list[dict[str, Any]] = []
    flags: list[str] = []

    mass_assignment_signal = "mass assignment" in text or (
        "conversion_params" in text
        and any(token in text for token in ("üzerine yaz", "overwrite", "modify", "değiştir"))
    )
    if mass_assignment_signal:
        cwe.append(candidate(
            "cwe", "CWE-915", "high",
            "İstemci girdisinin nesnedeki dahili alanı değiştirebildiği anlatılıyor; CWE-915 dinamik belirlenen nesne özniteliklerinin kontrolsüz değiştirilmesini ve mass assignment terimini kapsar.",
        ))
        capec.append(candidate(
            "capec", "CAPEC-77", "low",
            "Kullanıcı denetimli alanların uygulama davranışını değiştirmesiyle kavramsal benzerlik var; CAPEC-77 mass assignment'a özel değildir.",
            caveat="Yalnızca alanların gerçekten kullanıcı tarafından kontrol edilip iş mantığını etkilediği doğrulanırsa değerlendirilmeli.",
        ))
        flags.append("Mevcut CAPEC-315 deprecated ve TCP/IP fingerprinting ile ilgilidir; bu bulguyu açıklamıyor.")

    elif "ssrf" in category or "server-side request forgery" in text or "server side request forgery" in text:
        cwe.append(candidate(
            "cwe", "CWE-918", "high",
            "Kullanıcı girdisinin sunucuyu başka bir hedefe istek göndermeye zorladığı belirtiliyor; bu SSRF tanımıyla örtüşür.",
        ))
        capec.append(candidate(
            "capec", "CAPEC-664", "high",
            "CAPEC-664, kötü amaçlı girdinin sunucu tarafında istek başlatmaya zorlamasını doğrudan tanımlar.",
        ))
        if finding["status"].casefold() in {"analiz_edildi", "analyzed", "inconclusive", "needs review"}:
            flags.append("CSV durumu analiz_edildi; eşleme uyumu yüksek olsa da zafiyet henüz nihai olarak doğrulanmış sayılmamalı.")

    elif "bola" in category or "broken object level authorization" in text or "nesne seviyesinde yetkilendirme" in text:
        cwe.append(candidate(
            "cwe", "CWE-639", "high",
            "Başka kullanıcıya ait kayda, istekle denetlenen vehicle_id/report_id/order_id üzerinden erişim anlatılıyor; CWE-639 kullanıcı denetimli anahtarla yetkilendirme atlatmayı tanımlar.",
        ))
        capec.append(candidate(
            "capec", "CAPEC-1", "medium",
            "Yetkilendirme çerçevesinin kısıtlamadığı işlev veya sorgu üzerinden korunan kayda erişim, CAPEC-1 ile olası biçimde örtüşür.",
            caveat="CAPEC-1 işlev/ACL erişimine odaklanır; BOLA'nın nesne sahipliği kontrolüyle bire bir eşdeğer değildir.",
        ))
        if finding["existing_capec"].upper() == "CAPEC-210":
            flags.append("Mevcut CAPEC-210 genel bir CAPEC kategorisidir; tekniğe özgü saldırı örüntüsü olarak fazla geneldir.")
        if finding["existing_capec"].upper() == "CAPEC-1":
            flags.append("Mevcut CAPEC-1 olasıdır ancak işlev ACL'sini anlatır; nesne düzeyi sahiplik kontrolü ayrıca incelenmeli.")

    elif "broken authentication" in category or "otp" in text or "one-time password" in text:
        cwe.append(candidate(
            "cwe", "CWE-307", "high",
            "OTP doğrulama girişimlerini sınırlamama, aşırı kimlik doğrulama denemelerinin kısıtlanmamasıyla uyumludur.",
        ))
        capec.append(candidate(
            "capec", "CAPEC-112", "medium",
            "OTP değerleri üzerinde deneme-yanılma yapıldıysa genel brute-force örüntüsü uygun olabilir.",
            caveat="CAPEC-112 meta düzeyindedir; CSV açıklaması çok sayıda OTP tahmin denemesini açıkça kanıtlamıyor. CAPEC-49 ise parola brute force'a özeldir.",
        ))
        if finding["existing_capec"].upper() == "CAPEC-49":
            flags.append("Mevcut CAPEC-49 parola brute force içindir; OTP tahmini olduğu kanıtlanmadıkça doğrudan eşleşme sayılmamalı.")

    elif "lack of resources" in category or "rate limiting" in category or "rate limit" in text:
        cwe.append(candidate(
            "cwe", "CWE-799", "medium",
            "Kayıt art arda gelen isteklerin sınırlandırılmamasını açıkça anlatıyor; CWE-799 etkileşim sıklığının kontrolünü ele alır.",
            caveat="CWE-799 Class düzeyindedir ve MITRE daha özel alt CWE olup olmadığının dikkatle incelenmesini ister.",
        ))
        cwe.append(candidate(
            "cwe", "CWE-770", "medium",
            "İsteklerin kaynak tükettiği belirtiliyor; CWE-770 sınırsız veya kısıtlanmamış kaynak tahsisini kapsar.",
        ))
        capec.append(candidate(
            "capec", "CAPEC-125", "medium",
            "Çok sayıda istekle kaynak tüketimi ve rate limiting zayıflığı CAPEC-125 Flooding tanımıyla örtüşür.",
            caveat="CAPEC-125 meta düzeyinde genel bir saldırı örüntüsüdür; uygulama protokolü/ölçeği verilmediğinden daha özel alt örüntü seçilmedi.",
        ))
        if finding["existing_capec"].upper() == "CAPEC-130":
            flags.append("Mevcut CAPEC-130 az sayıda özel hazırlanmış istekle aşırı tahsise odaklanır; tekrar hacmi/rate-limit senaryosuyla karıştırılmamalı.")

    elif "bfla" in category or "function level authorization" in text or "admin" in text and "yetkisiz" in text:
        cwe.append(candidate(
            "cwe", "CWE-862", "medium",
            "Standart kullanıcının yönetici işlevini çalıştırması, o eylem için yetkilendirme kontrolü eksikse CWE-862 ile örtüşür.",
            caveat="Yetki kontrolü mevcut fakat yanlış uygulanmışsa CWE-863 daha uygun olabilir; uygulama ayrıntısı yok.",
        ))
        cwe.append(candidate(
            "cwe", "CWE-863", "low",
            "Yetkilendirme kontrolünün yanlış karar verdiği ortaya çıkarsa CWE-863 alternatifidir.",
            caveat="CSV, kontrolün tamamen eksik mi yoksa hatalı mı olduğunu ayırmıyor.",
        ))
        capec.append(candidate(
            "capec", "CAPEC-1", "medium",
            "Yetkisiz standart kullanıcının ACL ile kısıtlanması gereken yönetim URL'sine erişmesi CAPEC-1 ile olası biçimde örtüşür.",
        ))
        capec.append(candidate(
            "capec", "CAPEC-233", "medium",
            "Daha yüksek ayrıcalık gerektiren eylemin yapılması genel ayrıcalık yükseltme örüntüsüne uyabilir.",
            caveat="CAPEC-233 meta düzeyindedir; doğrudan HTTP işlevine erişim için CAPEC-1 daha özgül olabilir.",
        ))
        if finding["existing_cwe"].upper() == "CWE-285":
            flags.append("Mevcut CWE-285 yüksek seviyeli Class'tır; MITRE gerçek dünya eşlemelerinde daha özgül CWE-862/CWE-863 seçeneklerini önerir.")
        if finding["existing_capec"].upper() == "CAPEC-233":
            flags.append("CAPEC-233 genel/meta düzeyde ayrıcalık yükseltmedir; işlev seviyesindeki admin URL erişimi için fazla genel kalabilir.")

    elif "excessive data exposure" in category and any(token in text for token in ("pii", "e-posta", "email", "telefon", "phone")):
        cwe.append(candidate(
            "cwe", "CWE-359", "high",
            "E-posta/telefon gibi kişisel bilgilerin yetkisiz aktörlere açılması CWE-359'un özel kişisel bilgi tanımıyla örtüşür.",
        ))
        cwe.append(candidate(
            "cwe", "CWE-201", "high",
            "Hassas alanların API yanıtında istemciye gönderilmesi, gönderilen veriye hassas bilgi eklenmesiyle örtüşür.",
        ))
        capec.append(candidate(
            "capec", "CAPEC-118", "low",
            "Bilgi toplama/hedefin beklenenden fazla bilgi vermesi üst kategorisi senaryoyla ilişkili olabilir.",
            caveat="CAPEC-118 bir Category'dir; saldırganın sorgu/erişim tekniği verilmeden daha özel CAPEC seçilemez.",
        ))
        if finding["existing_cwe"].upper() == "CWE-213":
            flags.append("CWE-213 politika uyuşmazlığı gerektirir; yalnızca gereksiz PII yanıtı anlatımı CWE-359/CWE-201 ile daha doğrudan örtüşüyor.")
        if finding["existing_capec"].upper() == "CAPEC-118":
            flags.append("CAPEC-118 bilgi toplama kategorisidir; ayrıntılı bir saldırı örüntüsü değildir.")

    elif "excessive data exposure" in category or "conversion_params" in text or "internal" in text or "iç dönüştürme" in text:
        cwe.append(candidate(
            "cwe", "CWE-201", "medium",
            "İç parametrelerin API yanıtında istemciye gönderilmesi hassas bilgi gönderimiyle örtüşebilir.",
            caveat="Alanların gerçekten hassas olup olmadığı ve alıcının yetkisiz olup olmadığı kanıtla doğrulanmalı.",
        ))
        cwe.append(candidate(
            "cwe", "CWE-200", "medium",
            "Hassasiyet ve erişim sınırı net değilken CWE-200 genel bir bilgi ifşası adayıdır.",
            caveat="CWE-200 geniş bir Class düzeyi eşlemedir; verinin ne olduğu belirlenmeden daha dar CWE seçilmemeli.",
        ))
        cwe.append(candidate(
            "cwe", "CWE-497", "low",
            "Sızan alan sistem düzeyinde hassas uygulama/ortam bilgisi ise CWE-497 değerlendirilebilir.",
            caveat="conversion_params'ın sistem düzeyinde bilgi olduğu CSV'den doğrulanamıyor.",
        ))
        capec.append(candidate(
            "capec", "CAPEC-118", "low",
            "Bilgi edinme kategorisi üst düzeyde ilişkili olabilir.",
            caveat="CAPEC-118 kategori seviyesindedir; saldırı tekniği kaydedilmediği için daha özgül örüntü önerilmiyor.",
        ))
        if finding["existing_cwe"].upper() == "CWE-200":
            flags.append("CWE-200 genel bir Class'tır; conversion_params'ın hassasiyet ve yetkisiz alıcı bağlamı netleştirilmeli.")
        if finding["existing_capec"].upper() == "CAPEC-118":
            flags.append("CAPEC-118 bilgi toplama kategorisidir; saldırı tekniği için fazla geneldir.")

    else:
        flags.append("Kategori/açıklama için güvenilir bir özel kural bulunamadı; otomatik CWE/CAPEC önerisi üretilmedi.")

    return cwe, capec, flags


def existing_mapping(kind: str, value: str, candidate_ids: set[str]) -> dict[str, Any] | None:
    if not value:
        return None
    normalized = value.strip().upper()
    catalog = CWE_CATALOG if kind == "cwe" else CAPEC_CATALOG
    entry = catalog.get(normalized)
    flags: list[str] = []
    if entry is None:
        title = None
        source_status = "not_in_curated_mitre_registry"
        flags.append("Resmi tanım bu betiğin çevrimdışı kaynak kayıtlarında yok; ID ve başlık ayrıca doğrulanmalı.")
    else:
        title = entry["title"]
        source_status = "official_definition_reviewed_offline"
        if kind == "capec" and entry.get("deprecated"):
            flags.append("Deprecated CAPEC ID.")
        if kind == "capec" and entry.get("abstraction") == "Category":
            flags.append("CAPEC kategorisi; tekniğe özgü saldırı örüntüsü değil.")
        elif kind == "capec" and entry.get("abstraction") == "Meta":
            flags.append("Meta düzeyde genel saldırı örüntüsü; özgüllüğü kontrol edilmeli.")
        if kind == "cwe" and entry.get("mapping_guidance", "").startswith("discouraged"):
            flags.append("MITRE gerçek dünya zafiyet eşlemesi için bu yüksek soyutlama düzeyini önermiyor.")
    assessment = (
        "candidate_also_proposed_but_not_verified"
        if normalized in candidate_ids
        else "not_supported_by_current_rule_set_unverified"
    )
    return {
        "id": value,
        "normalized_id": normalized,
        "title": title,
        "source_url": official_url(kind, normalized)
        if normalized in catalog
        else None,
        "source_status": source_status,
        "assessment": assessment,
        "verified": False,
        "flags": flags,
    }


def evaluate(finding: dict[str, Any]) -> dict[str, Any]:
    cwe_candidates, capec_candidates, flags = infer_candidates(finding)
    warnings = list(finding["warnings"])
    if not finding["status"]:
        finding_status = "unknown"
    elif finding["status"].casefold() in {"analiz_edildi", "analyzed", "inconclusive", "needs review"}:
        finding_status = "not_final"
        flags.append("Bulgu durumu nihai değil; bu durum eşleme önerisinin doğrulanması anlamına gelmez.")
    else:
        finding_status = "recorded_status_only"

    return {
        "challenge_no": finding["challenge_no"],
        "category": finding["category"] or None,
        "finding_status": finding["status"] or None,
        "finding_validation_state": finding_status,
        "description": finding["description"] or None,
        "endpoint": finding["endpoint"] or None,
        "existing_mappings": {
            "cwe": existing_mapping(
                "cwe", finding["existing_cwe"], {item["id"] for item in cwe_candidates}
            ),
            "capec": existing_mapping(
                "capec", finding["existing_capec"], {item["id"] for item in capec_candidates}
            ),
        },
        "candidates": {"cwe": cwe_candidates, "capec": capec_candidates},
        "review_required": True,
        "review_flags": flags,
        "warnings": warnings,
    }


def build_report(source: Path) -> dict[str, Any]:
    findings, warnings = read_findings(source)
    return {
        "engine": "offline_rule_based",
        "llm_used": False,
        "network_used": False,
        "source_csv": str(source),
        "official_registry_reviewed_on": SOURCE_REVIEWED_ON,
        "mapping_semantics": {
            "CWE": "software weakness / root cause category",
            "CAPEC": "attack pattern / adversary technique",
        },
        "limitations": [
            "This is a curated, deterministic rule set, not an LLM or live MITRE lookup.",
            "An official entry definition does not by itself prove that it maps to this finding.",
            "Every candidate remains unverified and requires a human review against evidence.",
            "Missing fields produce warnings; the CSV is read-only and is never updated.",
        ],
        "warnings": warnings,
        "findings": [evaluate(finding) for finding in findings],
    }


def check_report(report: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not report["findings"]:
        errors.append("No challenge rows were evaluated.")
    for finding in report["findings"]:
        candidates = finding["candidates"]
        if not candidates["cwe"]:
            errors.append(f"Challenge {finding['challenge_no']}: no CWE candidate or rationale.")
        if not candidates["capec"]:
            errors.append(f"Challenge {finding['challenge_no']}: no CAPEC candidate or rationale.")
        for kind in ("cwe", "capec"):
            for item in candidates[kind]:
                if item["mitre_case_mapping_endorsed"] or item["mapping_verification_status"] != "candidate_not_verified_human_review_required":
                    errors.append(f"Challenge {finding['challenge_no']}: candidate was incorrectly marked verified.")
                if not item["rationale"].strip() or not item["source_url"]:
                    errors.append(f"Challenge {finding['challenge_no']}: candidate lacks a rationale or source URL.")
    return errors


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_SOURCE,
        help="CSV path (default: findings/challenges.csv)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check that every input row receives CWE and CAPEC candidates without marking them verified.",
    )
    args = parser.parse_args()

    try:
        report = build_report(args.input.resolve())
    except (OSError, csv.Error) as error:
        print(f"mapping error: {error}", file=sys.stderr)
        return 2

    if args.check:
        errors = check_report(report)
        if errors:
            for error in errors:
                print(f"FAIL: {error}")
            return 1
        print(
            f"PASS: {len(report['findings'])} CSV challenge satırında CWE ve CAPEC adayı üretildi; "
            "hiçbiri doğrulanmış olarak işaretlenmedi."
        )
        for finding in report["findings"]:
            cwe_ids = ", ".join(item["id"] for item in finding["candidates"]["cwe"])
            capec_ids = ", ".join(item["id"] for item in finding["candidates"]["capec"])
            print(f"Challenge {finding['challenge_no']}: CWE [{cwe_ids}] | CAPEC [{capec_ids}]")
        return 0

    json.dump(report, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
