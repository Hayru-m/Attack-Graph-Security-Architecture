# Haftalık İlerleme Raporu (Weekly Log)

## 2. Hafta (28 Eylül - 4 Ekim)
### Yapılanlar
- Geliştirme ortamı hazırlandı (Python sanal ortamı, bağımlılıklar: requests, networkx, pandas).
- VAmPI ve crAPI için ilk veri seti/şema taslağı oluşturuldu.
- Haftalık raporlama ve takip standardı belirlendi.

### Engeller
- Yok.

### Sonraki Hafta
- crAPI Docker konteynerlerinin ayağa kaldırılması ve doğrulama.
- Postman ve OpenAPI spec dosyalarının çıkarılması.
- Servis envanteri tablosunun (`service_inventory.csv`) tamamlanması.

### Kanıtlar
- `requirements.txt`, `findings/schema.csv`

---

## 3. Hafta (5 - 11 Ekim)
### Yapılanlar
- crAPI Docker ortamında başarıyla ayağa kaldırıldı.
- Postman koleksiyonu ve OpenAPI spesifikasyonu repodan çıkarılıp `recon/` altına kaydedildi.
- Docker Compose incelenerek `recon/service_inventory.csv` hazırlandı.

### Engeller
- Chatbot servisinin bağımlılıkları ve LLM API yapılandırması inceleniyor.

### Sonraki Hafta
- Challenge 1-9 güvenlik testlerinin Postman üzerinden gerçekleştirilmesi.
- `findings/challenges.csv` üzerinde test sonuçlarının güncellenmesi ve ön analiz.

### Kanıtlar
- `recon/service_inventory.csv`, `recon/openapi_spec.json`, `recon/postman_collection.json`