"""Plotly chart builders (presentation only; they receive ready-made tables)."""
from __future__ import annotations

import math

import networkx as nx
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# Dark-surface categorical palette (validated set, fixed order). Text uses text tokens.
SERIES = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#0ca30c", "#9085e9", "#e66767"]
INK, MUTED, GRID = "#f0efec", "#c3c2b7", "rgba(255,255,255,0.08)"


def _style(fig: go.Figure, height: int = 340, legend: bool = False) -> go.Figure:
    fig.update_layout(
        template="plotly_dark", height=height, showlegend=legend,
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=MUTED, size=12), margin=dict(l=10, r=50, t=30, b=10),
        hoverlabel=dict(bgcolor="#1a1a19", font_color=INK),
    )
    fig.update_xaxes(gridcolor=GRID, zerolinecolor=GRID)
    fig.update_yaxes(gridcolor=GRID, zerolinecolor=GRID)
    return fig


def bar_h(df: pd.DataFrame, label: str, value: str, title: str = "", color: str = SERIES[0]) -> go.Figure:
    """Horizontal bar chart, largest at the top."""
    d = df.iloc[::-1]
    fig = go.Figure(go.Bar(
        x=d[value], y=d[label].astype(str), orientation="h", marker_color=color,
        text=d[value].map("{:,}".format), textposition="outside", cliponaxis=False,
        hovertemplate="%{y}: %{x:,}<extra></extra>"))
    fig.update_layout(title=dict(text=title, font=dict(color=INK, size=14)))
    fig.update_yaxes(automargin=True)
    return _style(fig, height=max(260, 34 * len(d) + 80))


def protocol_donut(df: pd.DataFrame, title: str) -> go.Figure:
    """Share chart for ONE layer (never mix layers in one donut)."""
    fig = go.Figure(go.Pie(
        labels=df["protocol"], values=df["packets"], hole=0.55, sort=False,
        marker=dict(colors=SERIES[: len(df)], line=dict(color="#1a1a19", width=2)),
        textinfo="label+percent", textfont=dict(color=INK),
        hovertemplate="%{label}: %{value:,} packets (%{percent})<extra></extra>"))
    fig.update_layout(title=dict(text=title, font=dict(color=INK, size=14)))
    return _style(fig, height=320)


def time_series(tbl: pd.DataFrame, y: str, width: int) -> go.Figure:
    label = "Bytes" if y == "bytes" else "Packets"
    fig = go.Figure(go.Scatter(
        x=tbl["seconds"], y=tbl[y], mode="lines", line=dict(color=SERIES[0], width=2),
        fill="tozeroy", fillcolor="rgba(57,135,229,0.15)",
        hovertemplate="t=%{x}s: %{y:,}<extra></extra>"))
    fig.update_layout(xaxis_title=f"Seconds since capture start ({width}s buckets)", yaxis_title=label)
    return _style(fig)


def histogram(tbl: pd.DataFrame) -> go.Figure:
    fig = go.Figure(go.Bar(x=tbl["range"], y=tbl["packets"], marker_color=SERIES[2],
                           hovertemplate="%{x} bytes: %{y:,} packets<extra></extra>"))
    fig.update_layout(xaxis_title="Frame length (bytes)", yaxis_title="Packets")
    return _style(fig)


def comm_map(conv: pd.DataFrame, max_nodes: int = 25) -> go.Figure | None:
    """IPs as nodes, conversations as edges, edge width = bytes. Top endpoints only."""
    if conv.empty:
        return None
    vol: dict[str, int] = {}
    for r in conv.itertuples():
        vol[r.a] = vol.get(r.a, 0) + r.bytes
        vol[r.b] = vol.get(r.b, 0) + r.bytes
    keep = set(sorted(vol, key=vol.get, reverse=True)[:max_nodes])
    sub = conv[conv["a"].isin(keep) & conv["b"].isin(keep)]
    g = nx.Graph()
    for r in sub.itertuples():
        g.add_edge(r.a, r.b, weight=r.bytes)
    if g.number_of_nodes() == 0:
        return None
    # Lay out each connected group separately; otherwise spring_layout flings small
    # groups far away and squashes the main hub. The biggest group sits in the centre,
    # the others on a ring around it.
    comps = sorted(nx.connected_components(g), key=len, reverse=True)
    pos = {}
    for i, comp in enumerate(comps):
        sub = g.subgraph(comp)
        local = nx.spring_layout(sub, seed=7, k=1.0 / math.sqrt(max(len(comp), 1))) if len(comp) > 1 else {next(iter(comp)): (0.0, 0.0)}
        scale = 1.0 if i == 0 else 0.25
        cx, cy = (0.0, 0.0) if i == 0 else (
            2.0 * math.cos(2 * math.pi * i / max(len(comps) - 1, 1)),
            2.0 * math.sin(2 * math.pi * i / max(len(comps) - 1, 1)))
        for n, (x, y) in local.items():
            pos[n] = (cx + scale * x, cy + scale * y)
    wmax = max(d["weight"] for *_, d in g.edges(data=True))
    fig = go.Figure()
    for a, b, d in g.edges(data=True):  # one trace per edge so widths can differ
        fig.add_trace(go.Scatter(
            x=[pos[a][0], pos[b][0]], y=[pos[a][1], pos[b][1]], mode="lines",
            line=dict(width=1 + 7 * d["weight"] / wmax, color="rgba(144,133,233,0.55)"),
            hoverinfo="text", text=f"{a} ↔ {b}<br>{d['weight']:,} bytes"))
    nodes = list(g.nodes)
    vmax = max(vol[n] for n in nodes)
    fig.add_trace(go.Scatter(
        x=[pos[n][0] for n in nodes], y=[pos[n][1] for n in nodes], mode="markers",
        marker=dict(size=[10 + 26 * vol[n] / vmax for n in nodes], color=SERIES[0],
                    line=dict(color="#1a1a19", width=2)),
        text=[f"{n}<br>{vol[n]:,} bytes" for n in nodes], hoverinfo="text"))
    # Label only the single busiest endpoint; others show on hover (labels would collide).
    top = sorted(nodes, key=vol.get, reverse=True)[:1]
    fig.add_trace(go.Scatter(
        x=[pos[n][0] for n in top], y=[pos[n][1] for n in top], mode="text",
        text=[n if len(n) < 22 else n[:10] + "…" + n[-8:] for n in top],
        textposition="bottom center", textfont=dict(color=INK, size=11), hoverinfo="skip"))
    fig.update_xaxes(visible=False)
    fig.update_yaxes(visible=False)
    return _style(fig, height=520)
