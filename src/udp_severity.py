import pandas as pd

WEIGHT_UDP = 2.5  # from your research topic document

def compute_dynamic_thresholds(series: pd.Series):
    # Adaptive thresholds using percentiles (research-friendly)
    p50 = float(series.quantile(0.50))
    p80 = float(series.quantile(0.80))
    p95 = float(series.quantile(0.95))
    return p50, p80, p95

def severity_from_score(score: float, t50: float, t80: float, t95: float) -> str:
    if score <= 0:
        return "Normal"
    if score < t50:
        return "Low"
    if score < t80:
        return "Medium"
    if score < t95:
        return "High"
    return "Critical"

def add_udp_detection_and_scoring(feat: pd.DataFrame) -> pd.DataFrame:
    df = feat.copy()

    # Detection baseline (adaptive):
    # Mark flood if rate or burstiness is above 95th percentile
    rate_t50, rate_t80, rate_t95 = compute_dynamic_thresholds(df["udp_pkt_rate"])
    burst_t50, burst_t80, burst_t95 = compute_dynamic_thresholds(df["burst_100ms_max"])

    df["is_udp_flood"] = (df["udp_pkt_rate"] >= rate_t95) | (df["burst_100ms_max"] >= burst_t95)

    # Severity score only if detected as flood
    df["score_udp"] = df["udp_pkt_count"].where(df["is_udp_flood"], 0) * WEIGHT_UDP

    # Severity levels based on score distribution
    s_t50, s_t80, s_t95 = compute_dynamic_thresholds(df["score_udp"])

    df["severity_udp"] = df["score_udp"].apply(lambda s: severity_from_score(s, s_t50, s_t80, s_t95))

    # SOC-style ranking
    df["rank_by_score"] = df["score_udp"].rank(method="dense", ascending=False).astype(int)

    return df
