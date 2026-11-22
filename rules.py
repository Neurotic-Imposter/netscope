"""Simple, explainable, rule-based indicators.

Every rule has a plain-English threshold (see THRESHOLDS) and every alert
carries its evidence. These are POTENTIAL INDICATORS ONLY — not confirmed
attacks. NetScope is not an intrusion detection system.
"""

import pandas as pd

# How aggressive each rule is — change these numbers to adjust sensitivity.
THRESHOLDS = {
    "window_s": 10,            # sliding time window for connection rules (seconds)
    "conn_attempts": 20,       # SYN packets from one source to one dst:port in a window
    "syn_flood": 100,          # SYN packets from one source to one destination in a window
    "port_scan_ports": 15,     # distinct destination ports probed on one host
    "dominant_share_pct": 50,  # share of all packet bytes from one source (%)
    "dns_repeat": 10,          # identical DNS queries (same name + same type)
}

CAVEAT = (
    "Potential indicator only. This can have normal explanations; "
    "it is not proof of an attack."
)


class Alert:
    """One security indicator fired by a rule."""

    def __init__(self, rule, severity, title, evidence, explanation):
        self.rule = rule
        self.severity = severity   # "Info", "Low", or "Medium"
        self.title = title
        self.evidence = evidence   # dict of key/value pairs shown in the UI
        self.explanation = explanation
        self.caveat = CAVEAT


# ── Helper functions ──────────────────────────────────────────────────────────

def _syn_only(df):
    """Return TCP packets that open a connection: SYN set, ACK not set."""
    flags = df["tcp_flags"].fillna("")
    return df[
        (df["transport"] == "TCP")
        & flags.str.contains("SYN")
        & ~flags.str.contains("ACK")
    ]


def _max_in_window(times, window):
    """Return the largest number of timestamps that fall inside any window-second span."""
    t = times.sort_values().to_numpy()
    best, lo = 0, 0
    for hi in range(len(t)):
        while t[hi] - t[lo] > window:
            lo += 1
        best = max(best, hi - lo + 1)
    return best


def likely_capture_hosts(df):
    """Return IP addresses that are likely the computer that captured this traffic.

    Assumption: the capturing computer appears in >= 90% of IPv4 or IPv6 packets
    (a laptop with both IPv4 and IPv6 may return one address for each).
    """
    hosts = []
    for family in ("IPv4", "IPv6"):
        packets_in_family = df[df["network"] == family]
        if packets_in_family.empty:
            continue
        seen = pd.concat([packets_in_family["src"], packets_in_family["dst"]]).value_counts()
        if seen.iloc[0] / len(packets_in_family) >= 0.9:
            hosts.append(seen.index[0])
    return hosts


# ── Rules ─────────────────────────────────────────────────────────────────────

def connection_rules(df):
    """Check for frequent connection attempts, SYN floods, and port scans."""
    th = THRESHOLDS
    alerts = []
    syn = _syn_only(df)
    if syn.empty:
        return alerts

    synack = df[
        (df["transport"] == "TCP")
        & df["tcp_flags"].str.contains("SYN")
        & df["tcp_flags"].str.contains("ACK")
    ]

    # Rule 1: Frequent connection attempts (one source → one destination:port)
    for (src, dst, port), group in syn.groupby(["src", "dst", "dport"]):
        count = _max_in_window(group["time"], th["window_s"])
        if th["conn_attempts"] <= count < th["syn_flood"]:
            alerts.append(Alert(
                rule="Frequent connection attempts",
                severity="Low",
                title="Potential frequent connection attempts",
                evidence={
                    "source": src,
                    "destination": dst,
                    "port": int(port),
                    "SYN packets in window": count,
                    "window (s)": th["window_s"],
                },
                explanation=(
                    f"{src} sent {count} connection requests (SYN) to {dst}:{port} "
                    f"within {th['window_s']} seconds (threshold {th['conn_attempts']})."
                ),
            ))

    # Rule 2: SYN flood pattern (many SYNs to one host, few replies)
    for (src, dst), group in syn.groupby(["src", "dst"]):
        count = _max_in_window(group["time"], th["window_s"])
        if count >= th["syn_flood"]:
            replies = len(synack[(synack["src"] == dst) & (synack["dst"] == src)])
            alerts.append(Alert(
                rule="SYN flood pattern",
                severity="Medium",
                title="Potential SYN flood pattern",
                evidence={
                    "source": src,
                    "destination": dst,
                    "SYN packets in window": count,
                    "SYN-ACK replies seen": replies,
                    "window (s)": th["window_s"],
                },
                explanation=(
                    f"{src} sent {count} SYN packets to {dst} within "
                    f"{th['window_s']} seconds (threshold {th['syn_flood']}); "
                    f"{replies} SYN-ACK replies were seen."
                ),
            ))

    # Rule 3: Port scanning (one source probing many ports on one host)
    for (src, dst), group in syn.groupby(["src", "dst"]):
        distinct_ports = group["dport"].dropna().nunique()
        if distinct_ports >= th["port_scan_ports"]:
            sample = sorted(group["dport"].dropna().astype(int).unique())[:10]
            alerts.append(Alert(
                rule="Port scanning pattern",
                severity="Medium",
                title="Potential port scanning pattern",
                evidence={
                    "source": src,
                    "destination": dst,
                    "distinct ports probed": distinct_ports,
                    "first ports": ", ".join(map(str, sample)),
                },
                explanation=(
                    f"{src} sent SYN packets to {distinct_ports} different ports on {dst} "
                    f"(threshold {th['port_scan_ports']})."
                ),
            ))

    return alerts


def dominant_source_rule(df):
    """Check if one non-local IP is sending an unusually large share of all bytes."""
    th = THRESHOLDS
    ip_packets = df[df["network"].isin(["IPv4", "IPv6"])]
    capture_hosts = likely_capture_hosts(df)
    if ip_packets.empty:
        return []

    bytes_by_source = ip_packets.groupby("src")["length"].sum().sort_values(ascending=False)
    total_bytes = bytes_by_source.sum()

    for src, byte_count in bytes_by_source.items():
        if src in capture_hosts:
            continue  # the capturing computer naturally sends a lot; skip it
        share = byte_count / total_bytes * 100
        if share >= th["dominant_share_pct"]:
            return [Alert(
                rule="High traffic from one source",
                severity="Info",
                title="Potential high traffic from one source",
                evidence={
                    "source": src,
                    "share of bytes": f"{share:.1f}%",
                    "bytes": int(byte_count),
                },
                explanation=(
                    f"{src} accounts for {share:.1f}% of all bytes "
                    f"(threshold {th['dominant_share_pct']}%). "
                    f"Excluding the likely capturing computer "
                    f"({', '.join(capture_hosts) or 'none found'})."
                ),
            )]
        break  # only check the top source

    return []


def dns_rule(dns):
    """Check for the same DNS query being repeated many times."""
    if dns.empty:
        return []
    th = THRESHOLDS
    alerts = []
    queries = dns[~dns["is_response"]]
    for (name, qtype), group in queries.groupby(["qname", "qtype"]):
        if len(group) >= th["dns_repeat"]:
            span = group["time"].max() - group["time"].min()
            alerts.append(Alert(
                rule="Repeated DNS queries",
                severity="Info",
                title="Potential repeated DNS query pattern",
                evidence={
                    "domain": name,
                    "type": qtype,
                    "queries": len(group),
                    "over (s)": round(span, 1),
                    "DNS servers": ", ".join(sorted(set(group["dst"]))),
                },
                explanation=(
                    f"'{name}' ({qtype}) was queried {len(group)} times "
                    f"(threshold {th['dns_repeat']}). "
                    "Often caused by retries or short DNS caching — not necessarily a problem."
                ),
            ))
    return alerts


def run_all(df, dns):
    """Run all rules and return alerts sorted by severity (Medium first)."""
    severity_order = {"Medium": 0, "Low": 1, "Info": 2}
    alerts = connection_rules(df) + dominant_source_rule(df) + dns_rule(dns)
    return sorted(alerts, key=lambda a: severity_order[a.severity])


def rules_table():
    """Return a summary table of all rules and their trigger conditions."""
    th = THRESHOLDS
    return pd.DataFrame([
        ("Frequent connection attempts",
         f"≥{th['conn_attempts']} SYN to one dst:port in {th['window_s']}s"),
        ("SYN flood pattern",
         f"≥{th['syn_flood']} SYN to one host in {th['window_s']}s"),
        ("Port scanning pattern",
         f"SYN to ≥{th['port_scan_ports']} different ports on one host"),
        ("High traffic from one source",
         f"one source ≥{th['dominant_share_pct']}% of bytes (capturing PC excluded)"),
        ("Repeated DNS queries",
         f"same name+type ≥{th['dns_repeat']} times"),
    ], columns=["Rule", "Fires when"])
