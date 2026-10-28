# Attack-Graph-Security-Architecture
Attack-Graph-Security-Architecture(OWASP crAPI)
.\venv\Scripts\Activate.ps1
cd target\crAPI\deploy\docker
docker compose -f docker-compose.yml --compatibility up -d
docker ps 
crAPI: http://localhost:8888
MailHog: http://localhost:8025
cd target\crAPI\deploy\docker(dockerda değilsen kapatamazsın)
docker compose stop

## CWE/CAPEC eşleme

`mapping/llm_mapping.py`, `findings/challenges.csv` dosyasını okuyarak her kayıt için CWE (yazılım zayıflığı) ve CAPEC (saldırı örüntüsü) adayları üretir. Mevcut eşlemeler adaylardan ayrı gösterilir; öneriler doğrulanmış sayılmaz ve kanıtlarla insan incelemesi gerektirir.

Depo kökünden normal çalıştırma JSON raporunu stdout'a yazar:

```bash
python mapping/llm_mapping.py
```

CSV'deki her kayıt için CWE ve CAPEC adayı üretildiğini kontrol etmek için:

```bash
python mapping/llm_mapping.py --check
```

Mevcut sürüm çevrimdışı ve kural tabanlıdır; gerçek bir LLM veya harici API kullanmaz.

Projenizin `README.md` dosyasına doğrudan kopyalayıp yapıştırabileceğiniz, haftalık iş paketleri (WBS) ve ekip sorumluluklarını düzenleyen Markdown formatı:

---

## 👥 Ekip ve Rol Dağılımı

| Üye | Rol & Odak Alanı |
| --- | --- |
| **Elif** | Proje Yönetimi & Veri Analizi |
| **Burçak** | Veri Analizi |
| **Hayru** | Siber Güvenlik & Web |

---

## 📅 Proje İş Planı ve Görev Matrisi

| Hafta | Elif (Proje Yön. + Veri Analizi) | Burçak (Veri Analizi) | Hayru (Siber Güvenlik + Web) |
| --- | --- | --- | --- |
| **H01** | Proje yönetim planı ve haftalık görev takip sisteminin (Notion) kurulması | CWE/CAPEC/ATT&CK katalogları ve literatür kaynaklarının ön taraması | GitHub repo kurulumu, klasör yapısı (`recon/`, `findings/`, `mapping/`, `graph/`, `defense/`, `risk_scoring/`, `report/`), `.gitignore` |
| **H02** | Haftalık iletişim planı ve ilerleme raporu formatının oluşturulması | VAmPI ve crAPI için veri seti/veri şeması ön araştırması | `.env`, `venv` kurulumu, `requirements.txt` yüklenmesi, crAPI `target/` altına klonlanması |
| **H03** | OpenAPI/Postman collection organizasyonu ve servis envanteri koordinasyonu | Servis envanterini veri tablosuna (CSV) dönüştürme, ilk veri şeması tasarımı | crAPI Docker ile ayağa kaldırma, çalıştığını doğrulama, `service_inventory.md` |
| **H04** | `challenges.csv` yönetimi, haftalık ilerleme raporu | Test sonuçlarının ön analizi (kategori yoğunluk dağılımı) | Challenge 1–9 (BOLA, Broken Auth, Excessive Data Exposure, Rate Limiting) Postman testleri |
| **H05** | Tüm bulguların konsolidasyonu, doğrulanamayan zafiyetlerin takibi | Bulgu istatistikleri (doğrulama oranı, kategori dağılım grafiği) | Challenge 10–18 (Mass Assignment, SSRF, Injection, JWT, LLM/Chatbot) testleri |
| **H06** | Mapping sürecinin koordinasyonu, LLM prompt tasarımı üzerinde iş birliği | `mapping/llm_mapping.py` yazımı, CWE/CAPEC eşleme | Mapping için teknik destek (API bağlantıları, ortam kurulumu) |
| **H07** | `mapping_results.json` kalite kontrolü, ilerleme raporu | `networkx` kurulumu, attack graph ilk düğümlerinin oluşturulması | `mitreattack-python` doğrulama entegrasyonu, teknik testler |
| **H08** | *Boş — Vize sınavlarına odaklanılacak* | *Boş — Vize sınavlarına odaklanılacak* | *Boş — Vize sınavlarına odaklanılacak* |
| **H09** | Attack graph yapısının gözden geçirilmesi, dokümantasyon | `graph_before.json` tamamlama, ilk görselleştirme | Zincirleme senaryolarının teknik doğrulaması (Postman ile gerçek test, Challenge 5→10, 8→9) |
| **H10** | Risk skorlama metodolojisinin koordinasyonu, format standardizasyonu | `risk_scoring/risk_model.py` yazımı (CVSS + graf merkeziliği + zincir uzunluğu) | CVSS bileşenlerinin teknik olarak toplanması (exploitability skorları) |
| **H11** | Savunma katmanı planının proje yönetimi, zaman takibi | Savunma öncesi (baseline) veri setinin hazırlanması | WAF (ModSecurity) + segmentasyon kurulumu, `defense/docker-compose.defense.yml` |
| **H12** | İlerleme değerlendirmesi, MVP/stretch kapsam kararları | Savunma sonrası ilk veri toplama | Savunma katmanını test etme, zaman kalırsa IAM/SIEM başlangıcı |
| **H13** | Before/after karşılaştırmasının koordinasyonu | `graph_after.json` oluşturma, normalize metrikler (yüzdesel azalma, oranlar) | Ölçüm testlerini teknik olarak koşturma (18 senaryo tekrar) |
| **H14** | Rapor taslağının genel yazımı ve bütünlüğü (`draft.md`), 2209-B form yönetimi | Bulgular bölümü için grafik/tablo/istatistik hazırlama | Teknik bulguların rapor için derlenmesi (metodoloji, kurulum detayları) |
| **H15** | Rapor/form son hali, sunum slaytlarının hazırlanması | Veri görselleştirmelerinin son hali, sunum grafikleri | Jüri soru-cevap provası (teknik sorular) |
| **H16** | *Boş — Final sınavlarına odaklanılacak* | *Boş — Final sınavlarına odaklanılacak* | *Boş — Final sınavlarına odaklanılacak* |
| **H17** | Sunum provası, genel koordinasyon | Sunum provası, veri/grafik desteği | Sunum provası, teknik demo |

---
