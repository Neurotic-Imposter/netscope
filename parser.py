"""
parser.py — Reads a .pcap or .pcapng file and turns it into a table of packets.

Each packet becomes one row in a pandas DataFrame. Everything else in NetScope
(charts, statistics, alerts, PDF) works from that table — this file is the only
place that touches raw network packets.

We use Scapy to read the file so Wireshark does not need to be installed.
Wireshark is still used to *capture* traffic; NetScope only reads the saved file.
"""

import os

import pandas as pd
from scapy.all import ARP, DNS, ICMP, IP, IPv6, TCP, UDP, Ether
from scapy.utils import PcapReader


# ── Constants ────────────────────────────────────────────────────────────────

# Human-readable names for TCP control flags
TCP_FLAG_NAMES = {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH", "A": "ACK", "U": "URG"}

# ICMP type numbers → plain English names (IPv4)
ICMP_TYPES = {
    0: "Echo (ping) reply",
    3: "Destination unreachable",
    5: "Redirect",
    8: "Echo (ping) request",
    11: "Time-to-live exceeded",
}

# ICMPv6 type numbers → plain English names
ICMPV6_TYPES = {
    128: "Echo request",   129: "Echo reply",
    130: "Multicast Listener Query",
    133: "Router Solicitation", 134: "Router Advertisement",
    135: "Neighbor Solicitation", 136: "Neighbor Advertisement",
    143: "Multicast Listener Report v2",
}

# DNS query type numbers → short names
DNS_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX",
              16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}

# DNS response code numbers → short names
DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL",
              3: "NXDOMAIN", 4: "NOTIMP",  5: "REFUSED"}

# UDP ports → application name (best guess from port number only)
UDP_APPS = {53: "DNS", 67: "DHCP", 68: "DHCP",
            123: "NTP", 137: "NBNS", 5353: "mDNS", 5355: "LLMNR"}

# Stop parsing after this many packets so the app stays fast on large files
MAX_PACKETS = 200_000


# ── Data structures ───────────────────────────────────────────────────────────

class CaptureError(Exception):
    """Raised when a capture file cannot be read. The message is shown to the user."""


class Capture:
    """Holds everything parsed from one capture file."""

    def __init__(self, packets, dns, file_name="", file_size=0,
                 truncated=False, skipped=0):
        self.packets   = packets    # pandas DataFrame, one row per packet
        self.dns       = dns        # pandas DataFrame, one row per DNS packet
        self.file_name = file_name
        self.file_size = file_size
        self.truncated = truncated  # True if we stopped early due to MAX_PACKETS
        self.skipped   = skipped    # number of packets we could not decode
        self.notes     = []         # warning messages shown at the top of the page


# ── Helper functions ──────────────────────────────────────────────────────────

def _tcp_flags(tcp):
    """Return a string like 'SYN,ACK' from a Scapy TCP layer."""
    return ",".join(TCP_FLAG_NAMES[c] for c in str(tcp.flags) if c in TCP_FLAG_NAMES)


def _is_tls(payload):
    """Check whether a TCP payload looks like a TLS record (from the first 5 bytes)."""
    return len(payload) >= 5 and 20 <= payload[0] <= 23 and payload[1] == 3 and payload[2] <= 4


def _is_http(payload):
    """Check whether a TCP payload starts with an HTTP method or response."""
    return payload[:5] in (b"GET /", b"POST ", b"HEAD ", b"PUT /") or payload[:5] == b"HTTP/"


def _dns_name(raw):
    """Convert a DNS name from bytes (b'example.com.') to a plain string ('example.com')."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    return str(raw).rstrip(".")


def _parse_dns_packet(pkt, row):
    """Extract query/response details from a single DNS packet. Returns a dict or None."""
    d = pkt[DNS]
    q = d.qd[0] if d.qdcount and d.qd else None
    qname = _dns_name(q.qname) if q else ""
    qtype = DNS_QTYPES.get(q.qtype, str(q.qtype)) if q else ""

    # Collect all answer records
    answers = []
    for i in range(d.ancount or 0):
        try:
            rr = d.an[i]
            data = rr.rdata
            answers.append(_dns_name(data) if isinstance(data, (bytes, str)) else str(data))
        except Exception:
            break  # malformed answer — stop here but keep what we have

    is_response = bool(d.qr)
    return {
        "no": row["no"], "time": row["time"],
        "src": row["src"], "dst": row["dst"],
        "sport": row["sport"], "dport": row["dport"],
        "dns_id": d.id,
        "is_response": is_response,
        "qname": qname,
        "qtype": qtype,
        "rcode": DNS_RCODES.get(d.rcode, str(d.rcode)) if is_response else "",
        "answers": "; ".join(answers),
        "n_answers": len(answers),
    }


def _describe_packet(pkt, row):
    """
    Fill in the network/transport/app/protocol/info fields for one packet.
    Writes directly into the `row` dictionary.
    """
    network, transport, app = "Other", "", ""
    info = pkt.summary()   # fallback description from Scapy

    if pkt.haslayer(ARP):
        # ARP — device is asking "who has this IP address?"
        a = pkt[ARP]
        network = "ARP"
        row["src"] = a.psrc
        row["dst"] = a.pdst
        if a.op == 1:
            info = f"Who has {a.pdst}? Tell {a.psrc}"
        else:
            info = f"{a.psrc} is at {a.hwsrc}"

    elif pkt.haslayer(IP) or pkt.haslayer(IPv6):
        # Regular IP packet (IPv4 or IPv6)
        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        network = "IPv4" if pkt.haslayer(IP) else "IPv6"
        row["src"] = ip.src
        row["dst"] = ip.dst
        layer_names = [l.__name__ for l in pkt.layers()]

        if pkt.haslayer(TCP):
            t = pkt[TCP]
            transport = "TCP"
            row["sport"] = t.sport
            row["dport"] = t.dport
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
            transport = "UDP"
            row["sport"] = u.sport
            row["dport"] = u.dport
            low = min(u.sport, u.dport)
            app = UDP_APPS.get(low, "")
            if not app and 443 in (u.sport, u.dport):
                app = "QUIC"   # UDP port 443 is usually QUIC (HTTP/3)
            info = f"{u.sport} → {u.dport} len={max(len(u.payload), 0)}"

        elif pkt.haslayer(ICMP):
            transport = "ICMP"
            c = pkt[ICMP]
            info = f"{ICMP_TYPES.get(c.type, 'Type ' + str(c.type))} ttl={getattr(ip, 'ttl', '')}"

        elif any(n.startswith("ICMPv6") for n in layer_names):
            transport = "ICMPv6"
            icmp6_class = next(l for l in pkt.layers() if l.__name__.startswith("ICMPv6"))
            t6 = pkt[icmp6_class].type if hasattr(pkt[icmp6_class], "type") else None
            info = ICMPV6_TYPES.get(t6, icmp6_class.__name__)

    row["network"]   = network
    row["transport"] = transport
    row["app"]       = app
    row["info"]      = info
    # "protocol" is the most specific label — what a user sees in the Protocol column
    row["protocol"]  = app or transport or network


# ── Main parsing function ─────────────────────────────────────────────────────

def parse_capture(path, max_packets=None):
    """
    Read a .pcap or .pcapng file and return a Capture object.
    Raises CaptureError with a friendly message if something goes wrong.
    """
    if not os.path.isfile(path):
        raise CaptureError(f"File not found: {path}")
    if os.path.getsize(path) == 0:
        raise CaptureError("The capture file is empty.")

    # Try to open the file with Scapy's reader
    try:
        reader = PcapReader(path)
    except Exception as exc:
        raise CaptureError(
            f"This does not look like a valid .pcap or .pcapng file (details: {exc})."
        ) from exc

    rows = []        # one dict per packet → will become the packets DataFrame
    dns_rows = []    # one dict per DNS packet → will become the dns DataFrame
    skipped = 0
    truncated = False
    first_time = None

    with reader:
        try:
            for packet_number, pkt in enumerate(reader, start=1):
                if max_packets and packet_number > max_packets:
                    truncated = True
                    break

                try:
                    t = float(pkt.time)
                    if first_time is None:
                        first_time = t

                    # Start with an empty row; _describe_packet fills in the rest
                    row = {
                        "no":        packet_number,
                        "time":      t,
                        "rel_time":  t - first_time,   # seconds since capture started
                        "src":       "",
                        "dst":       "",
                        "sport":     pd.NA,
                        "dport":     pd.NA,
                        "length":    getattr(pkt, "wirelen", None) or len(pkt),
                        "tcp_flags": "",
                    }
                    _describe_packet(pkt, row)

                    # Only parse DNS on standard port 53 (same as Wireshark's dns filter)
                    if row["app"] == "DNS" and pkt.haslayer(DNS):
                        dns_row = _parse_dns_packet(pkt, row)
                        if dns_row:
                            dns_rows.append(dns_row)

                    rows.append(row)

                except Exception:
                    skipped += 1   # skip this packet, keep going

        except Exception as exc:
            if not rows:
                raise CaptureError(f"Could not read packets from this file ({exc}).") from exc
            skipped += 1   # file was cut off; keep the packets we already read

    if not rows:
        raise CaptureError("No readable packets were found in this file.")

    # Build the DataFrames
    columns = ["no", "time", "rel_time", "src", "dst", "network", "transport",
               "app", "protocol", "sport", "dport", "length", "tcp_flags", "info"]
    df = pd.DataFrame(rows, columns=columns)
    df["sport"] = df["sport"].astype("Int64")
    df["dport"] = df["dport"].astype("Int64")
    dns_df = pd.DataFrame(dns_rows)

    cap = Capture(df, dns_df,
                  file_name=os.path.basename(path),
                  file_size=os.path.getsize(path),
                  truncated=truncated,
                  skipped=skipped)

    if truncated:
        cap.notes.append(f"Only the first {max_packets:,} packets were analysed (file size limit).")
    if skipped:
        cap.notes.append(f"{skipped:,} packet(s) could not be decoded and were skipped.")

    return cap
