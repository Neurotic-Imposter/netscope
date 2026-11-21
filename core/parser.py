"""PCAP / PCAPNG parsing.

This module turns a capture file into a pandas DataFrame with ONE ROW PER PACKET.
Everything else in NetScope (statistics, charts, alerts, reports) works from that
table, so the dashboard never needs to touch raw packets.

We use Scapy (pure Python) so Wireshark/TShark does not have to be installed or
found on PATH. Wireshark is still what you use to *capture* the traffic.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

import pandas as pd
from scapy.all import ARP, DNS, ICMP, IP, IPv6, TCP, UDP, Ether
from scapy.utils import PcapReader

# Columns of the packet table (documented once, used everywhere).
COLUMNS = [
    "no", "time", "rel_time", "src", "dst", "network", "transport", "app",
    "protocol", "sport", "dport", "length", "tcp_flags", "info",
]

TCP_FLAG_NAMES = {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH", "A": "ACK", "U": "URG"}

ICMP_TYPES = {
    0: "Echo (ping) reply", 3: "Destination unreachable", 8: "Echo (ping) request",
    11: "Time-to-live exceeded", 5: "Redirect",
}
ICMPV6_TYPES = {
    128: "Echo request", 129: "Echo reply", 133: "Router Solicitation",
    134: "Router Advertisement", 135: "Neighbor Solicitation",
    136: "Neighbor Advertisement", 143: "Multicast Listener Report v2",
    130: "Multicast Listener Query",
}
DNS_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}
DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

# Port-based application labels for UDP. These are HEURISTICS (by port number).
UDP_APPS = {53: "DNS", 5353: "mDNS", 5355: "LLMNR", 137: "NBNS", 123: "NTP", 67: "DHCP", 68: "DHCP"}


class CaptureError(Exception):
    """Raised with a friendly message when a capture cannot be read."""


@dataclass
class Capture:
    """Result of parsing one file."""
    packets: pd.DataFrame
    dns: pd.DataFrame                      # one row per DNS (port 53) packet
    file_name: str = ""
    file_size: int = 0
    truncated: bool = False                # True if max_packets stopped parsing early
    skipped: int = 0                       # packets that could not be decoded
    notes: list[str] = field(default_factory=list)


def _tcp_flags(tcp) -> str:
    """Return flags like 'SYN,ACK' from a Scapy TCP layer."""
    return ",".join(TCP_FLAG_NAMES[c] for c in str(tcp.flags) if c in TCP_FLAG_NAMES)


def _is_tls(payload: bytes) -> bool:
    """TLS record header: type 20-23, version major byte 0x03."""
    return len(payload) >= 5 and 20 <= payload[0] <= 23 and payload[1] == 3 and payload[2] <= 4


def _is_http(payload: bytes) -> bool:
    return payload[:5] in (b"GET /", b"POST ", b"HEAD ", b"PUT /") or payload[:5] == b"HTTP/"


def _name(raw) -> str:
    """DNS names come as bytes like b'example.com.' -> 'example.com'."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    return str(raw).rstrip(".")


def _parse_dns(pkt, row: dict) -> dict | None:
    """Pull query/response details from a DNS packet (UDP/TCP port 53)."""
    d = pkt[DNS]
    q = d.qd[0] if d.qdcount and d.qd else None
    qname = _name(q.qname) if q is not None else ""
    qtype = DNS_QTYPES.get(q.qtype, str(q.qtype)) if q is not None else ""
    answers = []
    for i in range(d.ancount or 0):
        try:
            rr = d.an[i]
            data = rr.rdata
            answers.append(_name(data) if isinstance(data, (bytes, str)) else str(data))
        except Exception:  # a malformed answer should not stop the whole analysis
            break
    is_resp = bool(d.qr)
    return {
        "no": row["no"], "time": row["time"], "src": row["src"], "dst": row["dst"],
        "sport": row["sport"], "dport": row["dport"], "dns_id": d.id,
        "is_response": is_resp, "qname": qname, "qtype": qtype,
        "rcode": DNS_RCODES.get(d.rcode, str(d.rcode)) if is_resp else "",
        "answers": "; ".join(answers), "n_answers": len(answers),
    }


def _describe(pkt, row: dict) -> None:
    """Fill network/transport/app/protocol/info for one packet (in place)."""
    network, transport, app, info = "Other", "", "", pkt.summary()

    if pkt.haslayer(ARP):
        a = pkt[ARP]
        network = "ARP"
        row["src"], row["dst"] = a.psrc, a.pdst
        info = (f"Who has {a.pdst}? Tell {a.psrc}" if a.op == 1
                else f"{a.psrc} is at {a.hwsrc}")
    elif pkt.haslayer(IP) or pkt.haslayer(IPv6):
        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        network = "IPv4" if pkt.haslayer(IP) else "IPv6"
        row["src"], row["dst"] = ip.src, ip.dst
        layers = [l.__name__ for l in pkt.layers()]

        if pkt.haslayer(TCP):
            t = pkt[TCP]
            transport, row["sport"], row["dport"] = "TCP", t.sport, t.dport
            row["tcp_flags"] = _tcp_flags(t)
            payload = bytes(t.payload)
            if _is_tls(payload):
                app = "TLS"
            elif _is_http(payload):
                app = "HTTP"
            elif 53 in (t.sport, t.dport) and pkt.haslayer(DNS):
                app = "DNS"
            info = f"{t.sport} → {t.dport} [{row['tcp_flags']}] len={len(payload)}"
        elif pkt.haslayer(UDP):
            u = pkt[UDP]
            transport, row["sport"], row["dport"] = "UDP", u.sport, u.dport
            low = min(u.sport, u.dport)
            app = UDP_APPS.get(low, "")
            if not app and 443 in (u.sport, u.dport):
                app = "QUIC"  # heuristic: UDP port 443 is normally QUIC (HTTP/3)
            info = f"{u.sport} → {u.dport} len={max(len(u.payload), 0)}"
        elif pkt.haslayer(ICMP):
            transport = "ICMP"
            c = pkt[ICMP]
            info = f"{ICMP_TYPES.get(c.type, 'Type ' + str(c.type))} ttl={getattr(ip, 'ttl', '')}"
        elif any(n.startswith("ICMPv6") for n in layers):
            transport = "ICMPv6"
            icmp6 = next(l for l in pkt.layers() if l.__name__.startswith("ICMPv6"))
            t6 = pkt[icmp6].type if hasattr(pkt[icmp6], "type") else None
            info = ICMPV6_TYPES.get(t6, icmp6.__name__)

    row.update(network=network, transport=transport, app=app, info=info)
    # "protocol" is the label a user sees, like Wireshark's Protocol column:
    # the most specific one we identified.
    row["protocol"] = app or transport or network


def parse_capture(path: str, max_packets: int | None = None) -> Capture:
    """Read a .pcap/.pcapng file and return a Capture. Raises CaptureError."""
    if not os.path.isfile(path):
        raise CaptureError(f"File not found: {path}")
    if os.path.getsize(path) == 0:
        raise CaptureError("The capture file is empty.")

    rows, dns_rows = [], []
    skipped, truncated, first_time = 0, False, None
    try:
        reader = PcapReader(path)
    except Exception as exc:
        raise CaptureError(
            "This does not look like a valid .pcap or .pcapng file "
            f"(details: {exc})."
        ) from exc

    with reader:
        try:
            for n, pkt in enumerate(reader, start=1):
                if max_packets and n > max_packets:
                    truncated = True
                    break
                try:
                    t = float(pkt.time)
                    first_time = t if first_time is None else first_time
                    row = {
                        "no": n, "time": t, "rel_time": t - first_time,
                        "src": "", "dst": "", "sport": pd.NA, "dport": pd.NA,
                        "length": getattr(pkt, "wirelen", None) or len(pkt),
                        "tcp_flags": "",
                    }
                    _describe(pkt, row)
                    # DNS analysis uses standard DNS only (UDP/TCP port 53), the same
                    # packets Wireshark's `dns` filter shows. mDNS/LLMNR are separate.
                    if row["app"] == "DNS" and pkt.haslayer(DNS):
                        parsed = _parse_dns(pkt, row)
                        if parsed:
                            dns_rows.append(parsed)
                    rows.append(row)
                except Exception:
                    skipped += 1  # keep going; we report how many were unreadable
        except Exception as exc:
            if not rows:
                raise CaptureError(f"Could not read packets from this file ({exc}).") from exc
            skipped += 1  # file cut off part-way; keep what we already read

    if not rows:
        raise CaptureError("No readable packets were found in this file.")

    df = pd.DataFrame(rows, columns=COLUMNS)
    df["sport"] = df["sport"].astype("Int64")
    df["dport"] = df["dport"].astype("Int64")
    dns_df = pd.DataFrame(dns_rows)
    cap = Capture(df, dns_df, os.path.basename(path), os.path.getsize(path), truncated, skipped)
    if truncated:
        cap.notes.append(f"Only the first {max_packets:,} packets were analysed (size limit).")
    if skipped:
        cap.notes.append(f"{skipped:,} packet(s) could not be decoded and were skipped.")
    return cap
