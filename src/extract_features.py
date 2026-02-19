from scapy.all import rdpcap, UDP, IP
import pandas as pd
from collections import Counter
import math

def shannon_entropy(values):
    if not values:
        return 0.0
    counts = Counter(values)
    total = sum(counts.values())
    ent = 0.0
    for c in counts.values():
        p = c / total
        ent -= p * math.log2(p)
    return ent

def extract_udp_features(pcap_path: str, window_sec: float = 1.0) -> pd.DataFrame:
    pkts = rdpcap(pcap_path)

    rows = []
    for p in pkts:
        if p.haslayer(IP) and p.haslayer(UDP):
            t = float(p.time)
            rows.append({
                "time": t,
                "src_ip": p[IP].src,
                "dst_ip": p[IP].dst,
                "dst_port": int(p[UDP].dport),
                "pkt_len": int(len(p))
            })

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)
    t0 = df["time"].min()
    df["win"] = ((df["time"] - t0) // window_sec).astype(int)

    feat_rows = []
    for w, g in df.groupby("win"):
        count_udp = int(len(g))
        rate = count_udp / window_sec

        # Burstiness: max packets in 100ms bins within each window
        g2 = g.copy()
        g2["subbin"] = ((g2["time"] - (t0 + w * window_sec)) // 0.1).astype(int)
        burst_100ms = int(g2.groupby("subbin").size().max()) if len(g2) else 0

        feat_rows.append({
            "window_index": int(w),
            "udp_pkt_count": count_udp,
            "udp_pkt_rate": float(rate),
            "avg_pkt_len": float(g["pkt_len"].mean()),
            "std_pkt_len": float(g["pkt_len"].std(ddof=0)),
            "unique_src_ips": int(g["src_ip"].nunique()),
            "unique_dst_ports": int(g["dst_port"].nunique()),
            "entropy_src_ip": float(shannon_entropy(g["src_ip"].tolist())),
            "burst_100ms_max": burst_100ms
        })

    feat = pd.DataFrame(feat_rows)
    feat["pps_change"] = feat["udp_pkt_rate"].diff().fillna(0.0)
    return feat
