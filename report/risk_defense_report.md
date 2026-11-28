# crAPI Risk Analizi ve Bütçe Kısıtlı Savunma Seçimi

## Kapsam
- İncelenen bulgu: 15
- Doğrulanmış bulgu: 14
- Analiz aşamasındaki bulgu: 1
- Challenge 16-18 bu çalışmanın kapsamı dışındadır.

## Risk modeli
Risk puanı 0-100 aralığında, proje içi kural tabanlı bir modeldir; CVSS puanı değildir.

| Boyut | Ağırlık |
|---|---:|
| Etki | %35 |
| İstismar edilebilirlik | %30 |
| Maruziyet | %20 |
| Kanıt güveni | %15 |

Maruziyet için endpoint bazında doğrulanmış erişim verisi bulunmadığından tüm bulgularda 3/5 nötr varsayımı kullanılmıştır. Challenge 8 analiz aşamasında olduğu için kanıt güveni 2/5, doğrulanmış bulgularda 5/5 alınmıştır.

## Bütçe kısıtlı kontrol seçimi
- Bütçe: 20 birim
- Kullanılan bütçe: 20 birim
- Kalan bütçe: 0 birim
- Seçilen kontroller: C01, C03, C04, C06, C08

| Kontrol | Maliyet | Etkinlik varsayımı |
|---|---:|---:|
| C01 - Nesne seviyesinde yetkilendirme | 5 | %85 |
| C03 - Rate limiting ve OTP deneme sınırı | 3 | %80 |
| C04 - Yanıt alanı allowlist'i ve veri minimizasyonu | 3 | %75 |
| C06 - SSRF URL doğrulama ve egress kısıtlaması | 5 | %85 |
| C08 - Parametreli SQL sorguları | 4 | %90 |

## Önlem öncesi / sonrası
- Önlem öncesi toplam risk puanı: 1213.0
- Simüle edilen artık risk puanı: 541.35
- Modellenen risk azalımı: 671.65 puan (%55.37)

| Bulgu | Durum | Önce | Sonra (simülasyon) | Seçilen kontrol |
|---:|---|---:|---:|---|
| 1 | doğrulandı | 86.0 | 12.9 | Nesne seviyesinde yetkilendirme |
| 2 | doğrulandı | 86.0 | 12.9 | Nesne seviyesinde yetkilendirme |
| 3 | doğrulandı | 86.0 | 17.2 | Rate limiting ve OTP deneme sınırı |
| 4 | doğrulandı | 73.0 | 18.25 | Yanıt alanı allowlist'i ve veri minimizasyonu |
| 5 | doğrulandı | 73.0 | 18.25 | Yanıt alanı allowlist'i ve veri minimizasyonu |
| 6 | doğrulandı | 79.0 | 15.8 | Rate limiting ve OTP deneme sınırı |
| 7 | doğrulandı | 86.0 | 86.0 | Seçilmedi |
| 8 | analiz_edildi | 71.0 | 10.65 | SSRF URL doğrulama ve egress kısıtlaması |
| 9 | doğrulandı | 86.0 | 12.9 | Nesne seviyesinde yetkilendirme |
| 10 | doğrulandı | 79.0 | 79.0 | Seçilmedi |
| 11 | doğrulandı | 86.0 | 12.9 | SSRF URL doğrulama ve egress kısıtlaması |
| 12 | doğrulandı | 86.0 | 86.0 | Seçilmedi |
| 13 | doğrulandı | 86.0 | 8.6 | Parametreli SQL sorguları |
| 14 | doğrulandı | 78.0 | 78.0 | Seçilmedi |
| 15 | doğrulandı | 72.0 | 72.0 | Seçilmedi |

## Sınırlılıklar ve yorum
- Risk boyutları ve kontrol etkinlikleri uzman-kural tabanlı başlangıç varsayımlarıdır; ampirik olarak kalibre edilmemiştir.
- Savunma seçimi, belirtilen bütçe birimi ve etkinlik varsayımları altında 0/1 knapsack alt küme taramasıyla yapılmıştır.
- Önlem sonrası değerler gerçek ortamda uygulanmış veya yeniden test edilmiş sonuçlar değildir; senaryo simülasyonudur.
- CWE/CAPEC aday eşleştirmeleri bu risk puanlamasında doğrulanmış kabul edilmemiştir.
- ATT&CK tekniği mevcut girdilerde bulunmadığından ATT&CK düğümü üretilmemiştir.
- OpenAPI ile eşleşmeyen dört bulgu endpoint'i graf üzerinde unlisted olarak korunur; sessizce başka endpoint ile eşleştirilmez.

## Üretilen çıktılar
- `risk_scoring/results.csv`
- `risk_scoring/control_recommendations.csv`
- `risk_scoring/risk_model_metadata.json`
- `defense/control_catalog.csv`
- `defense/selection.json`
- `graph/graph_before.json`
- `graph/graph_after.json`
- `graph/attack_graph_defended.graphml` ve `.json` (graf girdisi mevcutsa)
- `report/risk_comparison.png`

## Teknik notlar
- Zenginleştirilmiş graf: graph\attack_graph_defended.graphml ve graph\attack_graph_defended.json
- Risk grafiği: report\risk_comparison.png
