"""Tests for parsing, aggregation, detectors, exports.

The first group checks the REAL capture against the numbers Wireshark showed for the
same file. The rest use small synthetic captures so we know the exact right answers.
Run:  python -m pytest -q
"""
import os

import pandas as pd
import pytest
from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, wrpcap

from core import analysis as A
from core.parser import CaptureError, parse_capture
from detectors import rules
from reports.pdf_report import build_pdf

REAL = os.path.join(os.path.dirname(__file__), "..", "captures", "netscope_first_capture.pcapng")


@pytest.fixture(scope="module")
def real():
    return parse_capture(REAL)


# ---- real capture vs Wireshark display filters ----
def test_total_packets_matches_wireshark(real):
    assert len(real.packets) == 2794 and real.skipped == 0

def test_tcp_matches_wireshark(real):
    assert (real.packets["transport"] == "TCP").sum() == 2248

def test_icmp_matches_wireshark(real):
    assert (real.packets["transport"] == "ICMP").sum() == 25

def test_dns_matches_wireshark(real):
    assert (real.packets["app"] == "DNS").sum() == 128
    assert len(real.dns) == 128

def test_ipv4_and_ipv6_both_extracted(real):
    nets = set(real.packets["network"])
    assert {"IPv4", "IPv6", "ARP"} <= nets
    v6 = real.packets[real.packets["network"] == "IPv6"]["src"]
    assert v6.str.contains(":").all()

def test_layers_each_sum_to_100(real):
    for t in A.layer_tables(real.packets).values():
        assert t["packets"].sum() == 2794
        assert abs(t["percent"].sum() - 100) < 0.1

def test_dns_queries_have_types_and_responses(real):
    s = A.dns_summary(real.dns)
    assert s["queries"] == 64 and s["responses"] == 64
    assert set(A.dns_types(real.dns)["type"]) >= {"A", "AAAA"}

def test_quiet_seconds_are_zero_not_missing(real):
    tbl, _ = A.traffic_over_time(real.packets)
    assert tbl["packets"].sum() == 2794 and tbl["packets"].notna().all()


# ---- synthetic captures ----
def _write(tmp_path, pkts, name="t.pcap"):
    p = tmp_path / name
    wrpcap(str(p), pkts)
    return str(p)

def _syn(src, dst, dport, t):
    p = Ether() / IP(src=src, dst=dst) / TCP(sport=40000, dport=dport, flags="S")
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
        q = Ether() / IP(src="10.0.0.5", dst="10.0.0.1") / UDP(sport=5000 + i, dport=53) / \
            DNS(id=i, qd=DNSQR(qname="example.com", qtype="A"))
        q.time = 100 + i
        r = Ether() / IP(src="10.0.0.1", dst="10.0.0.5") / UDP(sport=53, dport=5000 + i) / \
            DNS(id=i, qr=1, rcode=3, qd=DNSQR(qname="example.com", qtype="A"))
        r.time = 100.02 + i
        pkts += [q, r]
    cap = parse_capture(_write(tmp_path, pkts))
    s = A.dns_summary(cap.dns)
    assert s["queries"] == 12 and s["failed"] == 12 and s["unanswered"] == 0
    assert any("repeated DNS" in a.title for a in rules.run_all(cap.packets, cap.dns))


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
def test_csv_export_roundtrip(real, tmp_path):
    p = tmp_path / "o.csv"
    real.packets.to_csv(p, index=False)
    back = pd.read_csv(p)
    assert len(back) == 2794 and "src" in back.columns

def test_pdf_generates(real):
    pdf = build_pdf(real, rules.run_all(real.packets, real.dns))
    assert pdf[:4] == b"%PDF" and len(pdf) > 5000
