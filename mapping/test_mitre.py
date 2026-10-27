from mitreattack.stix20 import MitreAttackData
import urllib.request
import os

def main():
    file_path = "enterprise-attack.json"
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    
    print("1. MITRE ATT&CK Enterprise veri seti indiriliyor (Canlı)...")
    # Kütüphanenin downloader'ını bypass edip dosyayı doğrudan MITRE'den çekiyoruz
    urllib.request.urlretrieve(url, file_path)
    
    print("2. Veri seti belleğe yükleniyor (Bu birkaç saniye sürebilir)...")
    mitre_attack_data = MitreAttackData(file_path)
    
    print("3. crAPI için örnek bir teknik (T1190) sorgulanıyor...\n")
    
    # Zafiyet sömürüsü tekniğini (T1190) ID'ye göre getir
    technique = mitre_attack_data.get_object_by_attack_id("T1190", "attack-pattern")
    
    if technique:
        print("--- BAŞARILI: Entegrasyon Testi Sonucu ---")
        print(f"Teknik ID : T1190")
        print(f"Teknik Adı: {technique.name}")
        print(f"Açıklama  : {technique.description[:180]}...")
        print("------------------------------------------")
    else:
        print("Teknik bulunamadı, bağlantıyı kontrol edin.")

    # Temizlik (Gereksiz yer kaplamaması için inen dosyayı siler)
    if os.path.exists(file_path):
        os.remove(file_path)

if __name__ == "__main__":
    main()