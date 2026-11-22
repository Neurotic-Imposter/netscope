"""Shared test data: a small synthetic capture built with Scapy.

It needs no private file, so the tests run after a fresh clone.
Because we build it ourselves, we know the exact right answers.

Packets (55 in total):
  A  10.0.0.5 -> 10.0.0.9  TCP port 443, 20 packets (first one is SYN), TLS data
  B  10.0.0.9 -> 10.0.0.5  TCP port 443, 10 packets (replies)
  C  10.0.0.5 -> 10.0.0.9  HTTP request on port 80, 2 packets
  D  DNS: 6 lookups from 10.0.0.5 to 10.0.0.1, 6 answers (2 of them NXDOMAIN)
  E  ICMP: 5 echo requests 10.0.0.5 -> 10.0.0.1
  F  ARP: 2 packets
  G  IPv6 TCP: 4 packets  fe80::5 -> fe80::9
"""
import pytest
from scapy.all import ARP, DNS, DNSQR, ICMP, IP, IPv6, TCP, UDP, Ether, Raw, wrpcap

MAC1, MAC2 = "00:11:22:33:44:55", "00:11:22:33:44:66"
TLS_BYTES = b"\x17\x03\x03\x00\x20" + b"x" * 20     # looks like a TLS record
EXPECTED = {"total": 55, "tcp": 36, "udp": 12, "icmp": 5, "arp": 2, "dns": 12, "tls": 29, "http": 2}


def _eth(a, b):
    return Ether(src=a, dst=b)


def build_packets():
    pkts = []
    t = 100.0

    def add(p):
        nonlocal t
        p.time = t
        t += 1.0
        pkts.append(p)

    # A: client -> server over port 443 (first is a SYN, the rest carry TLS data)
    for i in range(20):
        flags = "S" if i == 0 else "PA"
        payload = Raw(TLS_BYTES) if i else Raw(b"")
        add(_eth(MAC1, MAC2) / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=50000, dport=443, flags=flags) / payload)
    # B: server -> client
    for i in range(10):
        add(_eth(MAC2, MAC1) / IP(src="10.0.0.9", dst="10.0.0.5") / TCP(sport=443, dport=50000, flags="PA") / Raw(TLS_BYTES))
    # C: plain HTTP
    for i in range(2):
        add(_eth(MAC1, MAC2) / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=50001, dport=80, flags="PA") / Raw(b"GET / HTTP/1.1\r\n\r\n"))
    # D: DNS - 6 questions, 6 answers (every third answer is NXDOMAIN)
    for i in range(6):
        add(_eth(MAC1, MAC2) / IP(src="10.0.0.5", dst="10.0.0.1") / UDP(sport=5000 + i, dport=53)
            / DNS(id=i, qd=DNSQR(qname="example.com", qtype="A")))
        add(_eth(MAC2, MAC1) / IP(src="10.0.0.1", dst="10.0.0.5") / UDP(sport=53, dport=5000 + i)
            / DNS(id=i, qr=1, rcode=3 if i % 3 == 0 else 0, qd=DNSQR(qname="example.com", qtype="A")))
    # E: ping
    for i in range(5):
        add(_eth(MAC1, MAC2) / IP(src="10.0.0.5", dst="10.0.0.1") / ICMP())
    # F: ARP
    add(_eth(MAC1, "ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc="10.0.0.5", pdst="10.0.0.1"))
    add(_eth(MAC2, MAC1) / ARP(op=2, psrc="10.0.0.1", pdst="10.0.0.5", hwsrc=MAC2))
    # G: IPv6 TCP
    for i in range(4):
        add(_eth(MAC1, MAC2) / IPv6(src="fe80::5", dst="fe80::9") / TCP(sport=40000, dport=8080, flags="PA") / Raw(b"abc"))
    return pkts


@pytest.fixture(scope="session")
def pcap_path(tmp_path_factory):
    path = tmp_path_factory.mktemp("cap") / "synthetic.pcap"
    wrpcap(str(path), build_packets())
    return str(path)


@pytest.fixture(scope="session")
def pcap_bytes(pcap_path):
    with open(pcap_path, "rb") as f:
        return f.read()


@pytest.fixture(scope="session")
def second_pcap_bytes(tmp_path_factory):
    """A different, smaller capture - used to test switching between files."""
    path = tmp_path_factory.mktemp("cap2") / "second.pcap"
    wrpcap(str(path), build_packets()[:10])
    with open(path, "rb") as f:
        return f.read()


@pytest.fixture(scope="session")
def cap(pcap_path):
    from parser import parse_capture
    return parse_capture(pcap_path)
