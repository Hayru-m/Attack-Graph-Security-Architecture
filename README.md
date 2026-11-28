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

# Attack Graph Security Architecture

## 1. Proje Hakkında

Bu proje, OWASP crAPI üzerinde bulunan API güvenlik zafiyetlerinin kanıta dayalı olarak analiz edilmesini, zafiyetler arasındaki ilişkilerin saldırı grafı (Attack Graph) biçiminde modellenmesini ve risk tabanlı savunma önerilerinin oluşturulmasını amaçlamaktadır.

Proje kapsamında crAPI üzerinde incelenen güvenlik bulguları; servisler, API endpoint'leri, CWE ve CAPEC zafiyet taksonomileri ile ilişkilendirilmiştir. Elde edilen veriler kullanılarak NetworkX tabanlı bir saldırı grafı oluşturulmuş ve risk puanlama modeli geliştirilmiştir.

Ayrıca sınırlı savunma bütçesi altında uygulanabilecek güvenlik kontrollerinin seçilmesi için optimizasyon yaklaşımı kullanılmıştır. Son aşamada ModSecurity ve OWASP Core Rule Set (CRS) kullanılarak gerçek bir WAF entegrasyonu gerçekleştirilmiş ve SQL Injection tespit/engelleme testleri yapılmıştır.

## 2. Projenin Amaçları

- crAPI üzerindeki API güvenlik bulgularını yapılandırılmış biçimde analiz etmek.
- Bulguları CWE ve CAPEC taksonomileriyle ilişkilendirmek.
- API servisleri ve endpoint'leri arasındaki ilişkileri modellemek.
- Saldırı grafı oluşturmak ve görselleştirmek.
- Bulgulara yönelik risk puanları hesaplamak.
- Bütçe kısıtı altında uygun savunma kontrollerini seçmek.
- Savunma öncesi ve sonrası teorik risk değerlerini karşılaştırmak.
- ModSecurity ve OWASP CRS ile WAF tabanlı tespit ve engelleme davranışını test etmek.

## 3. Kullanılan Teknolojiler

| Teknoloji / Araç | Kullanım Amacı |
|---|---|
| Python | Veri işleme ve analiz |
| NetworkX | Saldırı grafı oluşturma |
| Docker | crAPI ve WAF ortamlarının çalıştırılması |
| Postman | API isteklerinin test edilmesi |
| OWASP crAPI | Zafiyetli API test ortamı |
| OpenAPI | API endpoint envanteri |
| CWE | Zafiyet sınıflandırması |
| CAPEC | Saldırı örüntülerinin sınıflandırılması |
| ModSecurity | Web Application Firewall |
| OWASP CRS | Güvenlik kural seti |
| Matplotlib | Grafik ve rapor görselleştirmeleri |

## 4. Proje Mimarisi

Proje temel olarak beş aşamadan oluşmaktadır:

1. Bulguların ve API bilgilerinin hazırlanması.
2. CWE/CAPEC eşleştirmesi.
3. Saldırı grafının oluşturulması.
4. Risk analizi ve savunma kontrolü seçimi.
5. WAF entegrasyonu ve testleri.

### Genel veri akışı

```text
crAPI
  |
  v
API Findings + Evidence
  |
  v
OpenAPI / Service Inventory
  |
  v
CWE - CAPEC Mapping
  |
  v
Attack Graph Construction
  |
  v
Risk Scoring
  |
  v
Budget-Constrained Defense Selection
  |
  v
Before / After Risk Comparison
  |
  v
ModSecurity + OWASP CRS Testing
```

## 5. Veri Hazırlama ve Taksonomi Eşleştirmesi

Projedeki güvenlik bulguları yapılandırılmış veriler üzerinden işlenmiştir.

CWE ve CAPEC eşleştirmeleri `mapping/build_mapping.py` dosyası aracılığıyla oluşturulmaktadır.

Çıktı:

```text
mapping/cwe_capec_attack.json
```

Eşleştirme sürecinde mevcut kayıtlar ile aday eşleştirmeler birbirinden ayrılmıştır. Doğrulanmamış aday eşleştirmeler kesin eşleşme olarak değerlendirilmemektedir.

Mevcut eşleştirme işlemi offline ve kural tabanlıdır. Bu aşamada LLM veya harici ağ bağlantısı kullanılmamıştır.

## 6. API Keşfi ve Servis Envanteri

crAPI Postman koleksiyonu üzerinden API endpoint bilgileri çıkarılmıştır.

OpenAPI çıktısı:

```text
recon/openapi_spec.json
```

Servis envanteri:

```text
recon/service_inventory.md
```

Envanter CSV çıktısı da servis ve endpoint bilgilerini yapılandırılmış biçimde saklamaktadır.

Mevcut analiz sonuçları:

- 10 servis
- 34 benzersiz API path
- 37 benzersiz operasyon
- 49 Postman request kaydı
- 15 güvenlik bulgusu
- 11 bulgu için OpenAPI eşleşmesi
- 4 eşleşmeyen bulgu endpoint'i

OpenAPI koleksiyonunda response schema bilgilerinin bulunmaması ve bazı endpoint'lerin birebir eşleşmemesi nedeniyle eksik bilgiler tahmin yoluyla tamamlanmamıştır.

## 7. Saldırı Grafı

Saldırı grafı `graph/build_graph.py` kullanılarak oluşturulmaktadır.

Graf içerisinde aşağıdaki düğüm türleri bulunmaktadır:

- Servisler
- API endpoint'leri
- Güvenlik bulguları
- CWE kayıtları
- CAPEC kayıtları
- ATT&CK teknikleri (yalnızca doğrulanmış teknik kimlikleri bulunduğunda)

Graf çıktıları:

```text
graph/attack_graph.graphml
graph/attack_graph.json
graph/graph_nodes.csv
graph/graph_edges.csv
graph/graph_summary.json
```

Görselleştirme çıktıları:

```text
graph/attack_graph.png
graph/attack_graph_overview.png
```

Mevcut grafın özet sonuçları:

| Ölçüt | Sonuç |
|---|---:|
| Toplam düğüm | 101 |
| Toplam kenar | 181 |
| Servis düğümü | 10 |
| Endpoint düğümü | 41 |
| Finding düğümü | 15 |
| CWE düğümü | 18 |
| CAPEC düğümü | 16 |
| ATT&CK düğümü | 0 |

ATT&CK teknik kimlikleri doğrulanmış veriyle sağlanmadığı için graf üzerinde ATT&CK düğümü oluşturulmamıştır.

## 8. Risk Puanlama Modeli

Risk analizi `risk_scoring/risk_model.py` üzerinden gerçekleştirilmektedir.

Modelde dört temel kriter kullanılmaktadır:

| Kriter | Ağırlık |
|---|---:|
| Etki (Impact) | %35 |
| Sömürülebilirlik (Exploitability) | %30 |
| Maruziyet (Exposure) | %20 |
| Kanıt güveni (Evidence Confidence) | %15 |

Puanlama 0–100 aralığında kullanılan dahili bir sezgisel modeldir; CVSS puanı olarak değerlendirilmemelidir.

Kanıt güveni, bulgunun doğrulanma durumuna göre değerlendirilmiştir. Endpoint seviyesinde maruziyet doğrulamasının bulunmadığı durumlarda nötr değer kullanılmıştır.

### Risk analizi çıktıları

```text
risk_scoring/results.csv
risk_scoring/control_recommendations.csv
risk_scoring/risk_model_metadata.json
```

## 9. Bütçe Kısıtlı Savunma Kontrolü Seçimi

Savunma kontrolleri `defense/control_catalog.csv` içerisinde tanımlanmıştır.

Her kontrol için maliyet, etkililik ve ilişkili bulgular belirtilmiştir.

Kontrol seçimi, bütçe kısıtına göre 0/1 Knapsack optimizasyon yaklaşımıyla yapılmaktadır.

Mevcut örnek konfigürasyonda bütçe 20 birimdir.

Seçilen kontroller:

- C01: Object-Level Authorization
- C03: Rate Limiting and OTP
- C04: Response Allowlist / Data Minimization
- C06: SSRF URL Validation and Egress Control
- C08: Parameterized SQL

Seçim çıktıları:

```text
defense/control_catalog.csv
defense/budget_config.json
defense/selection.json
```

**Önemli:** Bu kontrollerin seçilmesi, ilgili kontrollerin crAPI üzerinde fiziksel olarak uygulandığı anlamına gelmez. Bu aşama bütçe kısıtlı savunma önerisi ve optimizasyon simülasyonudur.

## 10. Risk Karşılaştırması

Mevcut risk modeli çalıştırıldığında elde edilen örnek sonuçlar:

| Ölçüt | Değer |
|---|---:|
| Başlangıç toplam risk | 1213.00 |
| Simüle edilmiş artık risk | 541.35 |
| Modelin risk azalması | %55.37 |
| Savunma bütçesi | 20 |

Bu değerler, tanımlanan kontrol maliyetleri ve etkililik varsayımlarıyla hesaplanan model sonuçlarıdır. Gerçek sistemde ölçülmüş bir güvenlik iyileşmesi olarak yorumlanmamalıdır.

Rapor çıktıları:

```text
report/risk_defense_report.md
report/risk_comparison.png
```

## 11. ModSecurity ve OWASP CRS Entegrasyonu

Projenin savunma testleri kapsamında ModSecurity, OWASP CRS 4.25.2 ile birlikte Docker üzerinde çalıştırılmıştır.

WAF, mevcut crAPI web servisine reverse proxy olarak bağlanmıştır.

Kullanılan yapılandırma:

```text
defense/docker_compose.defense.yml
```

Bağlantı mimarisi:

```text
Postman / Client
      |
      v
localhost:8889
      |
      v
ModSecurity + OWASP CRS
      |
      v
crapi-web:80
      |
      v
crAPI Services
```

Portlar:

| Port | Açıklama |
|---|---|
| 8888 | Doğrudan crAPI erişimi |
| 8889 | ModSecurity üzerinden crAPI erişimi |

WAF yalnızca yerel makineden erişilebilecek şekilde `127.0.0.1:8889` adresine bağlanmıştır.

### WAF testleri

İlk aşamada `DetectionOnly` modu kullanılmıştır.

Bu modda SQL Injection örüntüsü tespit edilmiş, ancak istek engellenmemiştir.

Test payload:

```text
1 UNION SELECT NULL
```

Tespit edilen CRS kuralları:

- 942100
- 942190
- 942360

SQL Injection testinde toplam anomali puanı 15 olarak kaydedilmiştir.

İkinci aşamada `MODSEC_RULE_ENGINE: On` ayarı etkinleştirilmiştir.

Aynı test isteği tekrar gönderildiğinde:

```text
HTTP/1.1 403 Forbidden
```

yanıtı alınmıştır.

Engelleme logunda:

- 942100: SQL Injection tespiti
- 949110: Anomali eşiğinin aşılması ve engelleme
- 980170: Anomali puanlarının raporlanması

kayıtları görülmüştür.

Normal `/health` isteği ise WAF üzerinden HTTP 200 OK yanıtı vermiştir.

### WAF testinin kapsamı

Bu testler, ModSecurity'nin SQL Injection örüntülerini tespit edebildiğini ve anomali eşiği aşıldığında isteği engellediğini göstermektedir.

Testler, crAPI üzerindeki bütün zafiyetlerin WAF tarafından engellendiğini kanıtlamaz. Özellikle BOLA, BFLA ve JWT kaynaklı yetkilendirme problemleri için uygulama seviyesinde güvenlik kontrolleri gereklidir.

Ayrıca WAF üzerinde kullanılan genel `/health` SQL Injection testi, Challenge 13'ün gerçek endpoint testiyle aynı değildir. Bu iki test ayrı değerlendirilmelidir.

## 12. Projeyi Çalıştırma

### Gereksinimler

- Windows
- Docker Desktop
- Docker Compose
- Python
- Proje Python sanal ortamı
- Postman

### Python ortamını etkinleştirme

Proje ana klasöründe PowerShell açın:

```powershell
.\venv\Scripts\Activate.ps1
```

### crAPI ortamını başlatma

crAPI Docker Compose yapılandırması kullanılarak servisler başlatılır. Mevcut kurulumdaki Compose dosyası:

```text
target/crAPI/deploy/docker/docker-compose.yml
```

Proje ana klasöründen:

```powershell
docker compose -f .\target\crAPI\deploy\docker\docker-compose.yml up -d
```

Çalışan konteynerleri kontrol etmek için:

```powershell
docker ps
```

### Mapping oluşturma

```powershell
python mapping/build_mapping.py
```

### Saldırı grafını oluşturma

```powershell
python graph/build_graph.py
```

### Grafı görselleştirme

```powershell
python graph/visualize.py
```

### Risk ve savunma modelini çalıştırma

```powershell
python risk_scoring/risk_model.py
```

### ModSecurity'yi başlatma

Proje ana klasöründe:

```powershell
docker compose -f defense/docker_compose.defense.yml config
docker compose -f defense/docker_compose.defense.yml up -d
```

WAF durumunu kontrol etme:

```powershell
docker ps --filter "name=crapi-modsecurity"
```

Normal isteği test etme:

```powershell
curl.exe -i "http://localhost:8889/health"
```

WAF loglarını görüntüleme:

```powershell
docker logs --tail 100 crapi-modsecurity
```

WAF konteynerini durdurma:

```powershell
docker compose -f defense/docker_compose.defense.yml down
```

Bu komut yalnızca WAF Compose servisini durdurur; crAPI servislerinin kendi Compose yapılandırmasını kapatmaz.

## 13. Sınırlamalar

- CWE/CAPEC aday eşleştirmeleri doğrulanmış eşleştirmelerden ayrı tutulmaktadır.
- ATT&CK teknik kimlikleri bulunmayan bulgular için teknik ID üretilmemiştir.
- OpenAPI response schema bilgileri sınırlıdır.
- Dört bulgu endpoint'i OpenAPI koleksiyonuyla birebir eşleştirilememiştir.
- Risk puanlama modeli CVSS değildir; proje içi sezgisel bir modeldir.
- Savunma kontrollerinin maliyet ve etkililik değerleri varsayımlara dayanmaktadır.
- Savunma kontrolü seçimi, kontrolün uygulamaya deploy edildiği anlamına gelmez.
- ModSecurity testi SQL Injection örüntülerinin tespit ve engellenmesini doğrulamaktadır; bütün API güvenlik problemlerini çözmez.
- WAF test endpoint'i ile bazı bulgu kayıtlarındaki endpoint bilgileri arasında ayrıca doğrulanması gereken farklılıklar bulunmaktadır.

## 14. Sonuç

Bu çalışma kapsamında crAPI üzerindeki güvenlik bulguları yapılandırılmış veriler hâline getirilmiş, CWE/CAPEC eşleştirmeleri gerçekleştirilmiş, servis ve endpoint ilişkileri modellenmiş ve saldırı grafı oluşturulmuştur.

Oluşturulan risk modeli ile bulguların önceliklendirilmesi ve sınırlı bütçe altında savunma kontrollerinin seçilmesi sağlanmıştır.

Ek olarak ModSecurity ve OWASP CRS entegrasyonu gerçekleştirilerek SQL Injection örüntülerinin tespit ve engelleme davranışı gerçek Docker ortamında test edilmiştir.

Proje; API güvenlik analizini, saldırı grafı modellemesini, risk tabanlı savunma önerilerini ve WAF entegrasyon testlerini bir araya getiren bütünleşik bir çalışma sunmaktadır.
