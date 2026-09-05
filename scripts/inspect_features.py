import pandas as pd

file = "data/packet_features.csv"

df = pd.read_csv(file)

print("\n========== DATASET INFO ==========\n")

print("Rows:", len(df))
print("Columns:", len(df.columns))

print("\nColumns:")
print(df.columns.tolist())

print("\nMissing values:")
print(df.isnull().sum())

print("\nProtocol distribution:")
print(df["protocol"].value_counts())

print("\nIP version distribution:")
print(df["ip_version"].value_counts())

print("\nTop source IPs:")
print(df["src_ip"].value_counts().head(10))

print("\nTop destination IPs:")
print(df["dst_ip"].value_counts().head(10))

print("\nPacket length statistics:")
print(df["packet_length"].describe())