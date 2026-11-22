"""Tests for parsing, aggregation, rules and exports.

Most tests use the small synthetic capture from conftest.py, so they run on a fresh
clone. The last group compares NetScope with Wireshark on the real capture; it is
skipped when that private file is not present.
Run:  python -m pytest -q
"""
import os

import pandas as pd
import pytest
from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, wrpcap

import analysis as A
from tests.conftest import EXPECTED
from parser import CaptureError, parse_capture
import rules
from pdf_report import build_pdf


# ---- synthetic capture: exact known answers ----
def test_total_packets(cap):
    assert len(cap.packets) == EXPECTED["total"] and cap.skipped == 0

def test_protocol_counts(cap):
    df = cap.packets
    assert (df["transport"] == "TCP").sum() == EXPECTED["tcp"]
    assert (df["transport"] == "UDP").sum() == EXPECTED["udp"]
    assert (df["transport"] == "ICMP").sum() == EXPECTED["icmp"]
    assert (df["network"] == "ARP").sum() == EXPECTED["arp"]
    assert (df["app"] == "DNS").sum() == EXPECTED["dns"] and len(cap.dns) == EXPECTED["dns"]
    assert (df["app"] == "TLS").sum() == EXPECTED["tls"]
    assert (df["app"] == "HTTP").sum() == EXPECTED["http"]

def test_ipv4_and_ipv6_both_extracted(cap):
    assert {"IPv4", "IPv6", "ARP"} <= set(cap.packets["network"])
    v6 = cap.packets[cap.packets["network"] == "IPv6"]["src"]
    assert v6.str.contains(":").all()

def test_layers_each_sum_to_100(cap):
    for t in A.layer_tables(cap.packets).values():
        assert t["packets"].sum() == EXPECTED["total"]
        assert abs(t["percent"].sum() - 100) < 0.1

def test_dns_summary(cap):
    s = A.dns_summary(cap.dns)
    assert s["queries"] == 6 and s["responses"] == 6
    assert s["failed"] == 2 and s["unanswered"] == 0
    assert set(A.dns_types(cap.dns)["type"]) == {"A"}

def test_quiet_seconds_are_zero_not_missing(cap):
    tbl, _ = A.traffic_over_time(cap.packets)
    assert tbl["packets"].sum() == EXPECTED["total"] and tbl["packets"].notna().all()

def test_overview_numbers(cap):
    ov = A.overview(cap.packets)
    assert ov["packets"] == EXPECTED["total"]
    assert ov["duration"] == pytest.approx(EXPECTED["total"] - 1)
    assert ov["unique_ips"] == 5      # 10.0.0.5, .9, .1 and the two IPv6 addresses

def test_likely_capture_host(cap):
    hosts = rules.likely_capture_hosts(cap.packets)
    assert "10.0.0.5" in hosts          # the IPv4 address present in every IPv4 packet


# ---- synthetic captures ----
def _write(tmp_path, pkts, name="t.pcap"):
    p = tmp_path / name
    wrpcap(str(p), pkts)
    return str(p)

def _syn(src, dst, dport, t):
    p = Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") / IP(src=src, dst=dst) / TCP(sport=40000, dport=dport, flags="S")
    p.time = t
    return p

def test_syn_flood_detected(tmp_path):
    pkts = [_syn("10.0.0.5", "10.0.0.9", 80, 100 + i * 0.01) for i in range(150)]
    cap = parse_capture(_write(tmp_path, pkts))
    titles = [a.title for a in rules.run_all(cap.packets, cap.dns)]
    assert "Potential SYN flood pattern" in titles
    a = next(a for a in rules.run_all(cap.packets, cap.dns) if "SYN flood" in a.title)
    assert a.evidence["SYN packets in window"] == 150

def test_port_scan_detected(tmp_path):
    pkts = [_syn("10.0.0.5", "10.0.0.9", 1000 + i, 100 + i) for i in range(20)]
    cap = parse_capture(_write(tmp_path, pkts))
    alerts = rules.run_all(cap.packets, cap.dns)
    scan = [a for a in alerts if "port scanning" in a.title]
    assert scan and scan[0].evidence["distinct ports probed"] == 20

def test_normal_traffic_raises_no_alert(tmp_path):
    pkts = [_syn("10.0.0.5", "10.0.0.9", 443, 100 + i * 5) for i in range(3)]
    cap = parse_capture(_write(tmp_path, pkts))
    assert rules.run_all(cap.packets, cap.dns) == []

def test_repeated_dns_detected_and_parsed(tmp_path):
    pkts = []
    for i in range(12):
        q = Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") / IP(src="10.0.0.5", dst="10.0.0.1") / UDP(sport=5000 + i, dport=53) / \
            DNS(id=i, qd=DNSQR(qname="example.com", qtype="A"))
        q.time = 100 + i
        r = Ether(src="00:11:22:33:44:66", dst="00:11:22:33:44:55") / IP(src="10.0.0.1", dst="10.0.0.5") / UDP(sport=53, dport=5000 + i) / \
            DNS(id=i, qr=1, rcode=3, qd=DNSQR(qname="example.com", qtype="A"))
        r.time = 100.02 + i
        pkts += [q, r]
    cap = parse_capture(_write(tmp_path, pkts))
    s = A.dns_summary(cap.dns)
    assert s["queries"] == 12 and s["failed"] == 12 and s["unanswered"] == 0
    assert any("repeated DNS" in a.title for a in rules.run_all(cap.packets, cap.dns))


def test_narrative_generates_factual_observations(cap):
    ov = A.overview(cap.packets)
    lines = A.narrative(cap.packets, cap.dns, ov)
    assert len(lines) >= 3
    assert any(f"{EXPECTED['total']} packets" in l for l in lines)
    assert any("TCP" in l for l in lines)
    assert any("DNS" in l for l in lines)


def test_label_port_names_known_ports():
    assert A.label_port("443/tcp") == "443/tcp (HTTPS)"
    assert A.label_port("53/udp") == "53/udp (DNS)"
    assert A.label_port("55555/tcp") == "55555/tcp"


# ---- error handling ----
def test_missing_file():
    with pytest.raises(CaptureError):
        parse_capture("does_not_exist.pcapng")

def test_empty_file(tmp_path):
    p = tmp_path / "e.pcap"; p.write_bytes(b"")
    with pytest.raises(CaptureError):
        parse_capture(str(p))

def test_not_a_capture(tmp_path):
    p = tmp_path / "x.pcap"; p.write_bytes(b"this is plain text, not a capture file" * 20)
    with pytest.raises(CaptureError):
        parse_capture(str(p))

def test_max_packets_flags_truncation(tmp_path):
    pkts = [_syn("10.0.0.5", "10.0.0.9", 80, 100 + i) for i in range(10)]
    cap = parse_capture(_write(tmp_path, pkts), max_packets=4)
    assert len(cap.packets) == 4 and cap.truncated and cap.notes


# ---- exports ----
def test_csv_export_roundtrip(cap, tmp_path):
    p = tmp_path / "o.csv"
    cap.packets.to_csv(p, index=False)
    back = pd.read_csv(p)
    assert len(back) == EXPECTED["total"] and "src" in back.columns

def test_pdf_generates(cap):
    pdf = build_pdf(cap, rules.run_all(cap.packets, cap.dns))
    assert pdf[:4] == b"%PDF" and len(pdf) > 5000


# ---- optional: parity with Wireshark on the private real capture ----
REAL = os.path.join(os.path.dirname(__file__), "..", "captures", "netscope_first_capture.pcapng")
needs_real = pytest.mark.skipif(not os.path.exists(REAL), reason="private reference capture not present")


@needs_real
def test_real_capture_matches_wireshark():
    real = parse_capture(REAL)
    df = real.packets
    assert len(df) == 2794 and real.skipped == 0
    assert (df["transport"] == "TCP").sum() == 2248
    assert (df["transport"] == "ICMP").sum() == 25
    assert (df["app"] == "DNS").sum() == 128 and len(real.dns) == 128
    assert {"IPv4", "IPv6", "ARP"} <= set(df["network"])
    s = A.dns_summary(real.dns)
    assert s["queries"] == 64 and s["responses"] == 64
