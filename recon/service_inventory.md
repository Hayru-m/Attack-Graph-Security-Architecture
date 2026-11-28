# crAPI Service Inventory

> Bu belge recon/service_inventory.csv dosyasından
> otomatik oluşturulmuştur.
> Kaynak CSV'deki bilgiler değiştirilmeden aktarılmıştır.

## 1. Genel Bakış

- Envanterdeki servis/kayıt sayısı: **10**
- OpenAPI endpoint yolu sayısı: **34**
- OpenAPI benzersiz operasyon sayısı: **37**
- Postman toplam istek sayısı: **49**

## 2. Kaynak Durumu Dağılımı

- `Observed in current docker-compose; implementation not yet verified`: 1
- `Official crAPI docs + current compose`: 5
- `Current compose; language needs source verification`: 1
- `Current compose`: 3

## 3. Servis Envanteri

Aşağıdaki kayıtlar kaynak CSV'deki alanlarla oluşturulmuştur.
Boş alanlar `Belirtilmemiş` olarak gösterilir.

### 1. api.mypremiumdealership.com

- **service_id:** `svc-gateway`
- **target:** crAPI
- **service_type:** API gateway
- **technology:** Gateway service (implementation to verify)
- **language:** Belirtilmemiş
- **port:** 443/internal
- **protocol:** HTTPS
- **exposure:** Internal/container; gateway entry point
- **depends_on:** crapi-web; crapi-identity; crapi-workshop; crapi-community
- **data_store:** Belirtilmemiş
- **api_surface:** External API ingress / routing
- **security_relevance:** Trust boundary; routing and exposure point
- **source_status:** Observed in current docker-compose; implementation not yet verified

### 2. crapi-web

- **service_id:** `svc-web`
- **target:** crAPI
- **service_type:** Web / ingress
- **technology:** Nginx/OpenResty-based web service
- **language:** JavaScript/UI
- **port:** 80,443 (published 8888/30080/8443/30443)
- **protocol:** HTTP/HTTPS
- **exposure:** Host-exposed
- **depends_on:** identity; community; workshop; chatbot; mailhog
- **data_store:** Belirtilmemiş
- **api_surface:** Main UI + reverse-proxy/API routing
- **security_relevance:** Primary external attack surface
- **source_status:** Official crAPI docs + current compose

### 3. crapi-identity

- **service_id:** `svc-identity`
- **target:** crAPI
- **service_type:** Application service
- **technology:** Java
- **language:** Java
- **port:** 8080
- **protocol:** HTTP/HTTPS internal
- **exposure:** Internal
- **depends_on:** postgresdb; mongodb; mailhog
- **data_store:** PostgreSQL; MongoDB
- **api_surface:** /identity/api/*
- **security_relevance:** Authentication, authorization, JWT, user/vehicle identity
- **source_status:** Official crAPI docs + current compose

### 4. crapi-community

- **service_id:** `svc-community`
- **target:** crAPI
- **service_type:** Application service
- **technology:** Go
- **language:** Go
- **port:** 8087
- **protocol:** HTTP/HTTPS internal
- **exposure:** Internal
- **depends_on:** postgresdb; mongodb; crapi-identity
- **data_store:** PostgreSQL; MongoDB
- **api_surface:** /community/api/*
- **security_relevance:** Posts/comments; cross-user data and object authorization
- **source_status:** Official crAPI docs + current compose

### 5. crapi-workshop

- **service_id:** `svc-workshop`
- **target:** crAPI
- **service_type:** Application service
- **technology:** Python
- **language:** Python
- **port:** 8000
- **protocol:** HTTP/HTTPS internal
- **exposure:** Internal
- **depends_on:** postgresdb; mongodb; crapi-identity; crapi-community
- **data_store:** PostgreSQL; MongoDB
- **api_surface:** /workshop/api/*
- **security_relevance:** Vehicles, mechanics, reports, shop/orders; rich business logic
- **source_status:** Official crAPI docs + current compose

### 6. crapi-chatbot

- **service_id:** `svc-chatbot`
- **target:** crAPI
- **service_type:** LLM-backed application service
- **technology:** Chatbot service
- **language:** Python (verify in source)
- **port:** 5002; MCP 5500 published
- **protocol:** HTTP/MCP
- **exposure:** Host-exposed MCP; API-facing through web
- **depends_on:** mongodb; identity; chromadb; web
- **data_store:** MongoDB; ChromaDB
- **api_surface:** Chatbot / MCP endpoints
- **security_relevance:** Prompt injection, credential/data exposure, tool/action authorization
- **source_status:** Current compose; language needs source verification

### 7. postgresdb

- **service_id:** `db-postgres`
- **target:** crAPI
- **service_type:** Relational database
- **technology:** PostgreSQL 14
- **language:** Belirtilmemiş
- **port:** 5432
- **protocol:** PostgreSQL
- **exposure:** Internal
- **depends_on:** Belirtilmemiş
- **data_store:** PostgreSQL
- **api_surface:** Database only
- **security_relevance:** Persistent application data; SQL injection impact target
- **source_status:** Current compose

### 8. mongodb

- **service_id:** `db-mongo`
- **target:** crAPI
- **service_type:** NoSQL database
- **technology:** MongoDB 4.4
- **language:** Belirtilmemiş
- **port:** 27017
- **protocol:** MongoDB
- **exposure:** Internal
- **depends_on:** Belirtilmemiş
- **data_store:** MongoDB
- **api_surface:** Database only
- **security_relevance:** Persistent NoSQL data; NoSQL injection impact target
- **source_status:** Current compose

### 9. chromadb

- **service_id:** `db-chroma`
- **target:** crAPI
- **service_type:** Vector database
- **technology:** ChromaDB
- **language:** Belirtilmemiş
- **port:** 8000/internal
- **protocol:** HTTP
- **exposure:** Internal
- **depends_on:** Belirtilmemiş
- **data_store:** ChromaDB persistent volume
- **api_surface:** Vector store API
- **security_relevance:** Chatbot retrieval layer; trust boundary for LLM context
- **source_status:** Current compose

### 10. mailhog

- **service_id:** `svc-mailhog`
- **target:** crAPI
- **service_type:** Mail testing service
- **technology:** MailHog
- **language:** Belirtilmemiş
- **port:** 8025 UI; 1025 SMTP/internal
- **protocol:** HTTP/SMTP
- **exposure:** Host-exposed UI; SMTP internal
- **depends_on:** mongodb
- **data_store:** MongoDB
- **api_surface:** Mail UI / SMTP sink
- **security_relevance:** OTP/reset-token observation and authentication workflow support
- **source_status:** Official crAPI docs + current compose

## 4. OpenAPI Kaynak Özeti

OpenAPI belgesi Postman koleksiyonundan oluşturulmuştur.

- OpenAPI sürümü: `3.0.3`
- Kaynak koleksiyon: `recon/postman_collection.json`
- Toplam Postman isteği: 49
- Benzersiz operasyon: 37
- Benzersiz path: 34

### 4.1 API Etiketleri

- **.Well Known:** 1 operasyon
- **Community:** 5 operasyon
- **Identity:** 18 operasyon
- **Mail service:** 1 operasyon
- **Workshop:** 12 operasyon

## 5. Veri Kalitesi ve Sınırlamalar

- Bu belge kaynak CSV'deki bilgileri yansıtır.
- `source_status` alanı, bilginin doğrulama durumunu belirtir.
- Doğrulanmamış teknoloji, port veya bağımlılık bilgileri kesin kabul edilmemelidir.
- OpenAPI belgesi Postman koleksiyonunda bulunan isteklerden üretilmiştir.
- Postman koleksiyonunda bulunmayan endpoint'ler bu belgede varsayılmamıştır.
- API response şemaları koleksiyonda yeterli bilgi yoksa oluşturulmamıştır.
- Servis envanteri ile gerçek çalışma ortamı ayrıca karşılaştırılmalıdır.

## 6. Sonraki Çalışmalar

1. Servislerin gerçek teknoloji ve port bilgilerinin doğrulanması.
2. Servisler arası bağımlılıkların kontrol edilmesi.
3. API endpoint'lerinin servislerle ilişkilendirilmesi.
4. Erişilebilirlik ve saldırı grafı analizinde bu envanterin kullanılması.
