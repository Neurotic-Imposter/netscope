"""Aggregations over the packet table. Every number comes from the capture.

No Streamlit / Plotly code lives here, so these functions are easy to test.
"""
from __future__ import annotations

import math

import pandas as pd


def overview(df: pd.DataFrame) -> dict:
    """Headline KPIs."""
    ip = df[df["network"].isin(["IPv4", "IPv6"])]
    return {
        "packets": len(df),
        "bytes": int(df["length"].sum()),
        "duration": float(df["time"].max() - df["time"].min()),
        "unique_src": ip["src"].nunique(),
        "unique_dst": ip["dst"].nunique(),
        "start": float(df["time"].min()),
        "end": float(df["time"].max()),
    }


def _share(counts: pd.Series, total: int, label: str) -> pd.DataFrame:
    out = counts.rename("packets").reset_index()
    out.columns = [label, "packets"]
    out["percent"] = (out["packets"] / total * 100).round(2)
    return out


def layer_tables(df: pd.DataFrame) -> dict[str, pd.DataFrame]:
    """Protocol counts PER LAYER.

    A TLS packet is also a TCP packet and an IPv6 packet, so the three layers
    overlap. Each table's percentages are out of ALL packets and each table adds
    up to 100% on its own - tables must never be added to each other.
    """
    total = len(df)
    net = df["network"].value_counts()
    trans = df["transport"].replace("", "No transport layer").value_counts()
    app = df["app"].replace("", "None identified").value_counts()
    return {
        "Network layer": _share(net, total, "protocol"),
        "Transport layer": _share(trans, total, "protocol"),
        "Application layer": _share(app, total, "protocol"),
    }


def top_ports(df: pd.DataFrame, column: str, n: int = 10) -> pd.DataFrame:
    """Most frequent source or destination ports (TCP/UDP only)."""
    sub = df[df[column].notna()]
    out = sub.groupby([column, "transport"]).size().rename("packets").reset_index()
    out = out.sort_values("packets", ascending=False).head(n)
    out[column] = out[column].astype(int).astype(str) + "/" + out["transport"].str.lower()
    return out[[column, "packets"]].rename(columns={column: "port"})


def top_talkers(df: pd.DataFrame, column: str, n: int = 10) -> pd.DataFrame:
    """Top source ('src') or destination ('dst') IPs by packets, with bytes."""
    ip = df[df["network"].isin(["IPv4", "IPv6"])]
    g = ip.groupby(column).agg(packets=("no", "count"), bytes=("length", "sum"))
    return g.sort_values("packets", ascending=False).head(n).reset_index()


def conversations(df: pd.DataFrame) -> pd.DataFrame:
    """Endpoint pairs, direction ignored (A<->B), like Wireshark's Conversations."""
    ip = df[df["network"].isin(["IPv4", "IPv6"])].copy()
    pair = ip[["src", "dst"]].apply(lambda r: tuple(sorted(r)), axis=1)
    ip["a"], ip["b"] = pair.str[0], pair.str[1]
    g = ip.groupby(["a", "b"]).agg(packets=("no", "count"), bytes=("length", "sum"))
    return g.sort_values("bytes", ascending=False).reset_index()


def traffic_over_time(df: pd.DataFrame, buckets: int = 60) -> tuple[pd.DataFrame, int]:
    """Packets and bytes per time bucket. Returns (table, bucket_seconds)."""
    duration = df["rel_time"].max()
    width = max(1, math.ceil(duration / buckets)) if duration > 0 else 1
    b = (df["rel_time"] // width * width).astype(int)
    out = df.groupby(b).agg(packets=("no", "count"), bytes=("length", "sum"))
    full = pd.RangeIndex(0, int(b.max()) + width, width)
    out = out.reindex(full, fill_value=0)  # quiet seconds really are zero packets
    out.index.name = "seconds"
    return out.reset_index(), width


def length_histogram(df: pd.DataFrame, bin_size: int = 100) -> pd.DataFrame:
    b = (df["length"] // bin_size * bin_size).astype(int)
    out = b.value_counts().sort_index().rename("packets").reset_index()
    out.columns = ["start", "packets"]
    out["range"] = out["start"].astype(str) + "–" + (out["start"] + bin_size - 1).astype(str)
    return out


# ---------- DNS ----------

def dns_summary(dns: pd.DataFrame) -> dict:
    """Queries, responses, failures and matched response times."""
    if dns.empty:
        return {"available": False}
    q = dns[~dns["is_response"]]
    r = dns[dns["is_response"]]

    # Match each query to its response: same client, server and DNS id.
    qq = q.assign(client=q["src"], server=q["dst"], cport=q["sport"])
    rr = r.assign(client=r["dst"], server=r["src"], cport=r["dport"])
    m = qq.merge(rr, on=["client", "server", "cport", "dns_id", "qname", "qtype"],
                 suffixes=("_q", "_r"))
    m["rtt_ms"] = (m["time_r"] - m["time_q"]) * 1000
    m = m[m["rtt_ms"] >= 0].drop_duplicates(subset=["no_q"])

    return {
        "available": True,
        "queries": len(q), "responses": len(r),
        "unanswered": len(q) - len(m),          # query with no response SEEN in the capture
        "failed": int((r["rcode"] != "NOERROR").sum()),
        "servers": sorted(set(q["dst"])),
        "rtt_median_ms": float(m["rtt_ms"].median()) if len(m) else None,
        "rtt_max_ms": float(m["rtt_ms"].max()) if len(m) else None,
        "matched": len(m),
    }


def dns_domains(dns: pd.DataFrame, n: int = 15) -> pd.DataFrame:
    q = dns[~dns["is_response"]]
    g = q.groupby(["qname", "qtype"]).size().rename("queries").reset_index()
    return g.sort_values("queries", ascending=False).head(n)


def dns_types(dns: pd.DataFrame) -> pd.DataFrame:
    q = dns[~dns["is_response"]]
    return q["qtype"].value_counts().rename("queries").rename_axis("type").reset_index()


def dns_answers(dns: pd.DataFrame, n: int = 50) -> pd.DataFrame:
    r = dns[dns["is_response"]]
    out = r[["no", "qname", "qtype", "rcode", "src", "answers"]].rename(columns={"src": "server"})
    return out.head(n)


def format_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.2f} {unit}"
        n /= 1024
    return f"{n:.2f} GB"
