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
