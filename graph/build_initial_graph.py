import csv
import networkx as nx
import matplotlib.pyplot as plt
from pathlib import Path

# Dosya yolları
CSV_PATH = Path("findings/challenges.csv")
OUTPUT_PATH = Path("graph/initial_attack_graph.png")

def main():
    print("Saldırı grafiği (Attack Graph) düğümleri oluşturuluyor...")
    
    # 1. Yönlü (Directed) bir grafik oluştur
    G = nx.DiGraph()
    
    # 2. Kök düğümü (Hedef Sistem) ekle
    G.add_node("crAPI System")

    # 3. CSV'den verileri oku ve düğümleri/kenarları (nodes/edges) bağla
    if not CSV_PATH.exists():
        print(f"Hata: {CSV_PATH} bulunamadı!")
        return

    with open(CSV_PATH, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            chal_no = f"Challenge {row.get('challenge_no', '?')}"
            category = row.get("kategori", "Bilinmeyen Kategori")
            
            # İlişkiler: crAPI Sistemi -> Zafiyet Kategorisi -> Challenge ID
            G.add_edge("crAPI System", category)
            G.add_edge(category, chal_no)
            
    # 4. Grafiği görselleştir ve çiz
    plt.figure(figsize=(14, 9))
    
    # Düğümlerin ekrandaki yerleşim algoritması
    pos = nx.spring_layout(G, k=0.8, seed=42) 
    
    # Çizim ayarları (Renkler, boyutlar, oklar)
    nx.draw(G, pos, with_labels=True, 
            node_size=2500, 
            node_color="#287D8E", 
            font_size=9, 
            font_color="white", 
            font_weight="bold", 
            edge_color="#9AA7AD", 
            arrows=True,
            arrowsize=15)
    
    # Başlık ekle
    plt.title("crAPI İlk Saldırı Grafiği (Attack Graph PoC)", fontsize=14, fontweight="bold")
    
    # 5. PNG olarak kaydet
    OUTPUT_PATH.parent.mkdir(exist_ok=True)
    plt.savefig(OUTPUT_PATH, dpi=300, bbox_inches="tight")
    print(f"Başarılı! İlk saldırı grafiğiniz şu konuma kaydedildi: {OUTPUT_PATH}")

if __name__ == "__main__":
    main()
    