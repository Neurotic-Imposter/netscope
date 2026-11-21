"""Simple, explainable, rule-based indicators.

Every rule has a plain-English threshold (see THRESHOLDS) and every alert carries
its evidence. These are POTENTIAL INDICATORS ONLY. They are not confirmed attacks
and NetScope is not an intrusion detection system.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

THRESHOLDS = {
    "window_s": 10,              # sliding window for connection-attempt rules
    "conn_attempts": 20,         # SYN packets from one source to one dst:port in a window
    "syn_flood": 100,            # SYN packets from one source to one destination in a window
    "port_scan_ports": 15,       # distinct destination ports probed on one host
    "dominant_share_pct": 50,    # share of all packet bytes from one source
    "dns_repeat": 10,            # identical DNS queries (name + type)
}

CAVEAT = "Potential indicator only. This can have normal explanations; it is not proof of an attack."


@dataclass
class Alert:
    rule: str
    severity: str          # "Info" | "Low" | "Medium"
    title: str
    evidence: dict
    explanation: str
    caveat: str = CAVEAT


def _syn_only(df: pd.DataFrame) -> pd.DataFrame:
    """TCP packets that open a connection: SYN set, ACK not set."""
    f = df["tcp_flags"].fillna("")
    return df[(df["transport"] == "TCP") & f.str.contains("SYN") & ~f.str.contains("ACK")]


def _max_in_window(times: pd.Series, window: float) -> int:
    """Largest number of timestamps that fall inside any `window`-second span."""
    t = times.sort_values().to_numpy()
    best, lo = 0, 0
    for hi in range(len(t)):
        while t[hi] - t[lo] > window:
            lo += 1
        best = max(best, hi - lo + 1)
    return best


def likely_capture_hosts(df: pd.DataFrame) -> list[str]:
    """Assumption: the capturing computer is the address present in >= 90% of the
    IPv4 packets and/or >= 90% of the IPv6 packets (a dual-stack PC has one of each)."""
    hosts = []
    for family in ("IPv4", "IPv6"):
        fam = df[df["network"] == family]
        if fam.empty:
            continue
        seen = pd.concat([fam["src"], fam["dst"]]).value_counts()
        if seen.iloc[0] / len(fam) >= 0.9:
            hosts.append(seen.index[0])
    return hosts


def connection_rules(df: pd.DataFrame) -> list[Alert]:
    th, alerts = THRESHOLDS, []
    syn = _syn_only(df)
    if syn.empty:
        return alerts
    synack = df[(df["transport"] == "TCP") & df["tcp_flags"].str.contains("SYN") &
                df["tcp_flags"].str.contains("ACK")]

    # Frequent connection attempts: one source -> one destination:port.
    for (src, dst, port), g in syn.groupby(["src", "dst", "dport"]):
        n = _max_in_window(g["time"], th["window_s"])
        if n >= th["conn_attempts"] and n < th["syn_flood"]:
            alerts.append(Alert(
                "Frequent connection attempts", "Low",
                "Potential frequent connection attempts",
                {"source": src, "destination": dst, "port": int(port),
                 "SYN packets in window": n, "window (s)": th["window_s"]},
                f"{src} sent {n} connection requests (SYN) to {dst}:{port} within "
                f"{th['window_s']} seconds (threshold {th['conn_attempts']})."))

    # SYN flood pattern: many SYNs to one destination, few SYN-ACK replies seen.
    for (src, dst), g in syn.groupby(["src", "dst"]):
        n = _max_in_window(g["time"], th["window_s"])
        if n >= th["syn_flood"]:
            replies = len(synack[(synack["src"] == dst) & (synack["dst"] == src)])
            alerts.append(Alert(
                "SYN flood pattern", "Medium", "Potential SYN flood pattern",
                {"source": src, "destination": dst, "SYN packets in window": n,
                 "SYN-ACK replies seen": replies, "window (s)": th["window_s"]},
                f"{src} sent {n} SYN packets to {dst} within {th['window_s']} seconds "
                f"(threshold {th['syn_flood']}); {replies} SYN-ACK replies were seen."))

    # Port scanning pattern: one source probing many ports on one host.
    for (src, dst), g in syn.groupby(["src", "dst"]):
        ports = g["dport"].dropna().nunique()
        if ports >= th["port_scan_ports"]:
            sample = sorted(g["dport"].dropna().astype(int).unique())[:10]
            alerts.append(Alert(
                "Port scanning pattern", "Medium", "Potential port scanning pattern",
                {"source": src, "destination": dst, "distinct ports probed": ports,
                 "first ports": ", ".join(map(str, sample))},
                f"{src} sent SYN packets to {ports} different ports on {dst} "
                f"(threshold {th['port_scan_ports']})."))
    return alerts


def dominant_source_rule(df: pd.DataFrame) -> list[Alert]:
    th = THRESHOLDS
    ip = df[df["network"].isin(["IPv4", "IPv6"])]
    hosts = likely_capture_hosts(df)
    if ip.empty:
        return []
    by = ip.groupby("src")["length"].sum().sort_values(ascending=False)
    total = by.sum()
    for src, b in by.items():
        if src in hosts:
            continue  # the capturing computer naturally dominates; skip it
        share = b / total * 100
        if share >= th["dominant_share_pct"]:
            return [Alert(
                "High traffic from one source", "Info", "Potential high traffic from one source",
                {"source": src, "share of bytes": f"{share:.1f}%", "bytes": int(b)},
                f"{src} accounts for {share:.1f}% of all bytes (threshold "
                f"{th['dominant_share_pct']}%). Excluding the likely capturing computer ({', '.join(hosts) or 'none found'}).")]
        break
    return []


def dns_rule(dns: pd.DataFrame) -> list[Alert]:
    if dns.empty:
        return []
    th, alerts = THRESHOLDS, []
    q = dns[~dns["is_response"]]
    for (name, qtype), g in q.groupby(["qname", "qtype"]):
        if len(g) >= th["dns_repeat"]:
            span = g["time"].max() - g["time"].min()
            alerts.append(Alert(
                "Repeated DNS queries", "Info", "Potential repeated DNS query pattern",
                {"domain": name, "type": qtype, "queries": len(g),
                 "over (s)": round(span, 1), "DNS servers": ", ".join(sorted(set(g["dst"])))},
                f"'{name}' ({qtype}) was queried {len(g)} times (threshold {th['dns_repeat']}). "
                "Often caused by retries or short caching, not necessarily a problem."))
    return alerts


def run_all(df: pd.DataFrame, dns: pd.DataFrame) -> list[Alert]:
    order = {"Medium": 0, "Low": 1, "Info": 2}
    alerts = connection_rules(df) + dominant_source_rule(df) + dns_rule(dns)
    return sorted(alerts, key=lambda a: order[a.severity])


def rules_table() -> pd.DataFrame:
    th = THRESHOLDS
    return pd.DataFrame([
        ("Frequent connection attempts", f"≥{th['conn_attempts']} SYN to one dst:port in {th['window_s']}s"),
        ("SYN flood pattern", f"≥{th['syn_flood']} SYN to one host in {th['window_s']}s"),
        ("Port scanning pattern", f"SYN to ≥{th['port_scan_ports']} different ports on one host"),
        ("High traffic from one source", f"one source ≥{th['dominant_share_pct']}% of bytes (capturing PC excluded)"),
        ("Repeated DNS queries", f"same name+type ≥{th['dns_repeat']} times"),
    ], columns=["Rule", "Fires when"])
