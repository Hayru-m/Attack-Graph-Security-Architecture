import pandas as pd

GECERLI = {"doğrulandı", "kısmen", "doğrulanamadı"}

df = pd.read_csv("findings/challenges.csv", encoding="utf-8")
print("Satır sayısı:", len(df), "(9 olmalı)")

# Eksik challenge numaraları
eksik = set(range(1, 10)) - set(df["challenge_no"])
print("Eksik numaralar:", sorted(eksik) if eksik else "yok")

# Durum kontrolü
for _, satir in df.iterrows():
    d = str(satir["durum"]).strip()
    if d == "nan" or d == "":
        print(f"Challenge {satir['challenge_no']}: durum BOŞ")
    elif d not in GECERLI:
        print(f"Challenge {satir['challenge_no']}: geçersiz durum -> '{d}'")