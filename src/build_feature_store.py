import os, glob, math
from collections import defaultdict, Counter
from scapy.all import PcapReader, IP, UDP, TCP, ICMP
import polars as pl

WINDOW_SEC = 1.0
SUBBIN_SEC = 0.1  # for burstiness 100ms
print("✅ build_feature_store.py started")

def entropy(values):
    if not values:
        return 0.0
    c = Counter(values)
    n = sum(c.values())
    e = 0.0
    for k in c.values():
        p = k / n
        e -= p * math.log2(p)
    return e

class WindowAgg:
    """Aggregates packets into time windows and returns feature rows."""
    def __init__(self, kind: str):
        self.kind = kind
        self.reset()

    def reset(self):
        self.count = 0
        self.lens_sum = 0
        self.lens_sq = 0
        self.src_ips = []
        self.dst_ports = []
        self.subbin_counts = defaultdict(int)  # 100ms bins
        self.syn_only = 0
        self.icmp_types = []
        self.frag_count = 0

    def add(self, pkt, t_in_window: float, pkt_len: int, src_ip=None, dst_port=None,
            is_syn_only=False, icmp_type=None, is_frag=False):
        self.count += 1
        self.lens_sum += pkt_len
        self.lens_sq += pkt_len * pkt_len

        if src_ip: self.src_ips.append(src_ip)
        if dst_port is not None: self.dst_ports.append(dst_port)

        subbin = int(t_in_window // SUBBIN_SEC)
        self.subbin_counts[subbin] += 1

        if is_syn_only:
            self.syn_only += 1
        if icmp_type is not None:
            self.icmp_types.append(icmp_type)
        if is_frag:
            self.frag_count += 1

    def finalize_row(self, window_index: int, window_start_ts: float):
        if self.count == 0:
            return None

        mean_len = self.lens_sum / self.count
        var_len = max((self.lens_sq / self.count) - (mean_len * mean_len), 0.0)
        std_len = math.sqrt(var_len)
        burst_100ms = max(self.subbin_counts.values()) if self.subbin_counts else 0

        row = {
            "window_index": window_index,
            "window_start_ts": window_start_ts,
            "pkt_count": self.count,
            "pkt_rate": self.count / WINDOW_SEC,
            "avg_pkt_len": float(mean_len),
            "std_pkt_len": float(std_len),
            "unique_src_ips": int(len(set(self.src_ips))),
            "entropy_src_ip": float(entropy(self.src_ips)),
            "burst_100ms_max": int(burst_100ms),
        }

        # protocol-specific extras
        if self.kind == "udp":
            row["unique_dst_ports"] = int(len(set(self.dst_ports)))
        elif self.kind == "syn":
            row["syn_only_count"] = int(self.syn_only)
            row["unique_dst_ports"] = int(len(set(self.dst_ports)))
        elif self.kind == "icmp":
            row["icmp_type_entropy"] = float(entropy(self.icmp_types))
        elif self.kind == "frag":
            row["frag_pkt_count"] = int(self.frag_count)

        return row

def write_parquet(rows, out_path):
    if not rows:
        return
    df = pl.DataFrame(rows)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    # append safely by writing per-batch files
    df.write_parquet(out_path)

def build_feature_store(pcap_glob: str, out_dir: str):
    pcaps = sorted(glob.glob(pcap_glob))
    if not pcaps:
        print("No PCAPs found:", pcap_glob)
        return

    # output batch files (we merge later)
    udp_parts, syn_parts, icmp_parts, frag_parts = [], [], [], []

    batch_id = 0
    for pcap in pcaps:
        print("Reading:", os.path.basename(pcap))
        t0 = None
        current_win = None

        udp = WindowAgg("udp")
        syn = WindowAgg("syn")
        icmp = WindowAgg("icmp")
        frag = WindowAgg("frag")

        udp_rows, syn_rows, icmp_rows, frag_rows = [], [], [], []

        with PcapReader(pcap) as reader:
            for pkt in reader:
                if not pkt.haslayer(IP):
                    continue

                ts = float(pkt.time)
                if t0 is None:
                    t0 = ts
                    current_win = 0

                win = int((ts - t0) // WINDOW_SEC)

                # when window changes -> flush previous window rows
                while win > current_win:
                    win_start = t0 + current_win * WINDOW_SEC
                    r = udp.finalize_row(current_win, win_start)
                    if r: udp_rows.append(r)
                    r = syn.finalize_row(current_win, win_start)
                    if r: syn_rows.append(r)
                    r = icmp.finalize_row(current_win, win_start)
                    if r: icmp_rows.append(r)
                    r = frag.finalize_row(current_win, win_start)
                    if r: frag_rows.append(r)

                    udp.reset(); syn.reset(); icmp.reset(); frag.reset()
                    current_win += 1

                # in-window offset
                t_in_window = ts - (t0 + current_win * WINDOW_SEC)

                ip = pkt[IP]
                pkt_len = len(pkt)

                # FRAGMENT check
                is_frag = (int(ip.flags.MF) == 1) or (int(ip.frag) > 0)
                if is_frag:
                    frag.add(pkt, t_in_window, pkt_len, src_ip=ip.src, is_frag=True)

                # UDP
                if pkt.haslayer(UDP):
                    dport = int(pkt[UDP].dport)
                    udp.add(pkt, t_in_window, pkt_len, src_ip=ip.src, dst_port=dport)

                # ICMP
                if pkt.haslayer(ICMP):
                    icmp_type = int(pkt[ICMP].type)
                    icmp.add(pkt, t_in_window, pkt_len, src_ip=ip.src, icmp_type=icmp_type)

                # SYN-only TCP
                if pkt.haslayer(TCP):
                    tcp = pkt[TCP]
                    is_syn_only = (tcp.flags & 0x02) != 0 and (tcp.flags & 0x10) == 0  # SYN=1, ACK=0
                    if is_syn_only:
                        dport = int(tcp.dport)
                        syn.add(pkt, t_in_window, pkt_len, src_ip=ip.src, dst_port=dport, is_syn_only=True)

        # flush last window
        if current_win is not None and t0 is not None:
            win_start = t0 + current_win * WINDOW_SEC
            r = udp.finalize_row(current_win, win_start);  udp_rows.append(r)  if r else None
            r = syn.finalize_row(current_win, win_start);  syn_rows.append(r)  if r else None
            r = icmp.finalize_row(current_win, win_start); icmp_rows.append(r) if r else None
            r = frag.finalize_row(current_win, win_start); frag_rows.append(r) if r else None

        # write batch parquet parts (safe + scalable)
        os.makedirs(out_dir, exist_ok=True)
        udp_path  = os.path.join(out_dir, f"udp_features_part_{batch_id:04d}.parquet")
        syn_path  = os.path.join(out_dir, f"syn_features_part_{batch_id:04d}.parquet")
        icmp_path = os.path.join(out_dir, f"icmp_features_part_{batch_id:04d}.parquet")
        frag_path = os.path.join(out_dir, f"frag_features_part_{batch_id:04d}.parquet")

        write_parquet([r for r in udp_rows if r], udp_path)
        write_parquet([r for r in syn_rows if r], syn_path)
        write_parquet([r for r in icmp_rows if r], icmp_path)
        write_parquet([r for r in frag_rows if r], frag_path)

        udp_parts.append(udp_path); syn_parts.append(syn_path); icmp_parts.append(icmp_path); frag_parts.append(frag_path)
        batch_id += 1

    print("\n✅ Feature store created in:", out_dir)
    print("Next: merge parts into single parquet per protocol (optional).")

if __name__ == "__main__":
    print("✅ main() running...")

    PCAP_GLOB = r"R:\udp\data\samples\*.pcap"
    OUT_DIR   = r"R:\udp\outputs\feature_store"

    print("PCAP_GLOB =", PCAP_GLOB)
    print("OUT_DIR   =", OUT_DIR)

    build_feature_store(PCAP_GLOB, OUT_DIR)
    print("✅ Done.")
