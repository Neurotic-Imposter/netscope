"""Tests for the plain-English labels, directed communication map, packet details."""
import pandas as pd

import analysis as A
import charts


# ---- plain-English protocol names ----
def test_friendly_names_keep_the_technical_name():
    assert A.friendly_name("TCP") == "Reliable Data Communication"
    assert A.protocol_label("TCP") == "Reliable Data Communication (TCP)"
    assert A.protocol_label("UDP") == "Faster Data Communication (UDP)"
    assert A.protocol_label("DNS") == "Website Address Lookup (DNS)"
    assert A.protocol_label("ARP") == "Finding Devices on a Local Network (ARP)"
    assert A.protocol_label("ICMP") == "Network Connectivity Messages (ICMP)"

def test_unknown_protocol_is_shown_unchanged():
    assert A.protocol_label("SomethingNew") == "SomethingNew"
    assert A.protocol_description("SomethingNew") == ""

def test_every_protocol_seen_has_a_description(cap):
    seen = set(cap.packets["protocol"]) | set(cap.packets["network"])
    for name in seen:
        assert A.protocol_description(name), f"missing description for {name}"

def test_narrative_uses_plain_english(cap):
    lines = " ".join(A.narrative(cap.packets, cap.dns, A.overview(cap.packets)))
    assert "Reliable Data Communication (TCP)" in lines
    assert "website address lookups" in lines


# ---- directed communication ----
def _row(flows, src, dst):
    return flows[(flows["src"] == src) & (flows["dst"] == dst)].iloc[0]

def test_directions_are_kept_separate(cap):
    flows = A.directed_flows(cap.packets)
    forward = _row(flows, "10.0.0.5", "10.0.0.9")    # 20 on port 443 + 2 HTTP
    back = _row(flows, "10.0.0.9", "10.0.0.5")       # 10 replies
    assert forward["packets"] == 22 and back["packets"] == 10

def test_flow_bytes_match_packets(cap):
    df = cap.packets
    flows = A.directed_flows(df)
    expected = df[(df["src"] == "10.0.0.5") & (df["dst"] == "10.0.0.9")]["length"].sum()
    assert _row(flows, "10.0.0.5", "10.0.0.9")["bytes"] == expected

def test_flow_protocols_are_only_those_seen(cap):
    flows = A.directed_flows(cap.packets)
    assert set(_row(flows, "10.0.0.5", "10.0.0.9")["protocols"].split(", ")) == {"TLS", "HTTP", "TCP"}
    assert set(_row(flows, "10.0.0.5", "10.0.0.1")["protocols"].split(", ")) == {"DNS", "ICMP"}

def test_flows_exclude_arp_and_sorted_by_bytes(cap):
    flows = A.directed_flows(cap.packets)
    assert flows["packets"].sum() == len(cap.packets) - 2          # the 2 ARP packets are left out
    assert flows["bytes"].is_monotonic_decreasing

def test_flows_ignore_packets_to_self():
    df = pd.DataFrame({"no": [1], "src": ["1.1.1.1"], "dst": ["1.1.1.1"], "network": ["IPv4"],
                       "length": [60], "protocol": ["TCP"]})
    assert A.directed_flows(df).empty

def test_comm_map_has_one_arrow_per_connection(cap):
    flows = A.directed_flows(cap.packets)
    fig = charts.comm_map(flows, top_n=4)
    assert len(fig.layout.annotations) == 4
    assert len(fig.data) <= 4            # hover trace + at most 2 dot traces

def test_comm_map_top_n_limits_connections(cap):
    flows = A.directed_flows(cap.packets)
    assert len(charts.comm_map(flows, top_n=3).layout.annotations) == 3
    assert len(charts.comm_map(flows, top_n=30).layout.annotations) == len(flows)

def test_comm_map_marks_capture_device_and_hover_has_direction(cap):
    fig = charts.comm_map(A.directed_flows(cap.packets), 10, highlight_nodes={"10.0.0.5"})
    names = [t.name for t in fig.data]
    assert "Likely your device (estimate)" in names
    hover = " ".join(fig.data[0].text)
    assert "10.0.0.5 → 10.0.0.9" in hover and "Protocols seen" in hover

def test_comm_map_nothing_to_draw():
    assert charts.comm_map(A.directed_flows(pd.DataFrame(
        {"no": [], "src": [], "dst": [], "network": [], "length": [], "protocol": []})), 10) is None


# ---- packet detail panel ----
def test_packet_detail_tcp(cap):
    row = cap.packets[(cap.packets["tcp_flags"] == "SYN")].iloc[0]
    d = A.packet_detail(row)
    assert d["Sender IP Address"] == "10.0.0.5" and d["Receiver IP Address"] == "10.0.0.9"
    assert d["Sender port"] == "50000" and d["Receiver port"] == "443"
    assert d["TCP flags"] == "SYN"
    assert d["Type of traffic"] == "Reliable Data Communication (TCP)"
    assert d["Packet size"].endswith("bytes")

def test_packet_detail_without_ports_has_no_port_or_flags(cap):
    row = cap.packets[cap.packets["transport"] == "ICMP"].iloc[0]
    d = A.packet_detail(row)
    assert "Sender port" not in d and "TCP flags" not in d


# ---- helpers added for the dashboard redesign ----
def test_protocol_counts_match_the_known_synthetic_capture(cap):
    counts = {name: n for name, n, _ in A.protocol_counts(cap.packets)}
    assert counts == {"TCP": 36, "UDP": 12, "DNS": 12, "ARP": 2, "ICMP": 5, "HTTP": 2, "HTTPS": 29}
    # they overlap on purpose: DNS is inside UDP, so the sum is more than the 55 packets
    assert sum(counts.values()) > len(cap.packets)

def test_ip_activity_counts_each_direction(cap):
    row = A.ip_activity(cap.packets).set_index("ip").loc["10.0.0.5"]
    assert row["packets_sent"] == 22 + 6 + 5 and row["packets_received"] == 10 + 6

def test_no_handshake_means_an_empty_table_not_zero_milliseconds(cap):
    # the synthetic capture has a SYN but never a SYN-ACK
    assert A.tcp_handshakes(cap.packets).empty
    assert A.tcp_indicators(cap.packets)["answered"] == 0

def test_handshake_time_comes_from_the_timestamps():
    df = pd.DataFrame({
        "no": [1, 2], "time": [10.0, 10.05], "transport": ["TCP", "TCP"],
        "tcp_flags": ["SYN", "SYN,ACK"], "src": ["a", "b"], "dst": ["b", "a"],
        "sport": [5000, 443], "dport": [443, 5000]})
    h = A.tcp_handshakes(df)
    assert len(h) == 1 and round(h["ms"].iloc[0]) == 50

def test_reset_rule_needs_enough_resets():
    import rules
    base = {"transport": "TCP", "src": "a", "dst": "b", "tcp_flags": "RST"}
    few = pd.DataFrame([base] * 9)
    many = pd.DataFrame([base] * 10)
    assert rules.reset_rule(few) == [] and len(rules.reset_rule(many)) == 1

def test_spike_rule_ignores_short_or_flat_captures(cap):
    import rules
    assert rules.spike_rule(cap.packets) == []       # 55 evenly spaced packets
