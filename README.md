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
