import os
from extract_features import extract_udp_features
from udp_severity import add_udp_detection_and_scoring

def main():
    pcap_path = os.path.join("data", "samples", "sample.pcap")
    print("PCAP:", os.path.abspath(pcap_path))
    print("Exists:", os.path.exists(pcap_path))

    out_csv = os.path.join("outputs", "tables", "udp_severity_table.csv")
    os.makedirs(os.path.dirname(out_csv), exist_ok=True)

    feat = extract_udp_features(pcap_path, window_sec=1.0)
    print("Feature windows:", len(feat))

    if feat.empty:
        print("No UDP packets found in this PCAP (unexpected).")
        return

    final = add_udp_detection_and_scoring(feat)
    final.to_csv(out_csv, index=False)

    print("✅ Saved:", out_csv)

    top10 = final.sort_values("score_udp", ascending=False).head(10)
    print("\nTop 10 windows by UDP severity score:")
    print(top10[["window_index","udp_pkt_count","udp_pkt_rate","burst_100ms_max","score_udp","severity_udp"]].to_string(index=False))

if __name__ == "__main__":
    main()
