"""Plotly chart builders — receive ready-made data tables, return figures."""

import math

import networkx as nx
import pandas as pd
import plotly.graph_objects as go

# Dark-surface categorical colour palette (fixed order so the same protocol
# always gets the same colour across charts).
SERIES = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#0ca30c", "#9085e9", "#e66767"]
INK = "#f0efec"       # bright text
MUTED = "#c3c2b7"     # dimmed text / axis labels
GRID = "rgba(255,255,255,0.08)"

# Applied to every chart — no toolbar clutter for beginners.
CHART_CONFIG = {
    "displayModeBar": False,
    "responsive": True,
}


def _style(fig, height=340, legend=False):
    """Apply a consistent dark theme to any Plotly figure."""
    fig.update_layout(
        template="plotly_dark",
        height=height,
        showlegend=legend,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=MUTED, size=12),
        margin=dict(l=10, r=50, t=30, b=10),
        hoverlabel=dict(bgcolor="#1a1a19", font_color=INK),
    )
    fig.update_xaxes(gridcolor=GRID, zerolinecolor=GRID)
    fig.update_yaxes(gridcolor=GRID, zerolinecolor=GRID)
    return fig


def bar_h(df, label, value, title="", color=SERIES[0]):
    """Horizontal bar chart with the largest bar at the top."""
    d = df.iloc[::-1]  # flip so biggest is on top
    fig = go.Figure(go.Bar(
        x=d[value],
        y=d[label].astype(str),
        orientation="h",
        marker_color=color,
        text=d[value].map("{:,}".format),
        textposition="outside",
        cliponaxis=False,
        hovertemplate="%{y}: %{x:,}<extra></extra>",
    ))
    fig.update_layout(title=dict(text=title, font=dict(color=INK, size=14)))
    fig.update_yaxes(automargin=True)
    return _style(fig, height=max(260, 34 * len(d) + 80))


def protocol_donut(df, title):
    """Donut chart showing the share of packets for one protocol layer."""
    fig = go.Figure(go.Pie(
        labels=df["protocol"],
        values=df["packets"],
        hole=0.55,
        sort=False,
        marker=dict(colors=SERIES[: len(df)], line=dict(color="#1a1a19", width=2)),
        textinfo="label+percent",
        textfont=dict(color=INK),
        hovertemplate="%{label}: %{value:,} packets (%{percent})<extra></extra>",
    ))
    fig.update_layout(title=dict(text=title, font=dict(color=INK, size=14)))
    return _style(fig, height=320)


def time_series(tbl, y, width):
    """Line chart of packets or bytes over time."""
    label = "Bytes" if y == "bytes" else "Packets"
    fig = go.Figure(go.Scatter(
        x=tbl["seconds"],
        y=tbl[y],
        mode="lines",
        line=dict(color=SERIES[0], width=2),
        fill="tozeroy",
        fillcolor="rgba(57,135,229,0.15)",
        hovertemplate="t=%{x}s: %{y:,}<extra></extra>",
    ))
    fig.update_layout(
        xaxis_title=f"Seconds since capture start ({width}s buckets)",
        yaxis_title=label,
    )
    return _style(fig)


def histogram(tbl):
    """Bar chart showing how many packets fall into each packet-size range."""
    fig = go.Figure(go.Bar(
        x=tbl["range"],
        y=tbl["packets"],
        marker_color=SERIES[2],
        hovertemplate="%{x} bytes: %{y:,} packets<extra></extra>",
    ))
    fig.update_layout(xaxis_title="Frame length (bytes)", yaxis_title="Packets")
    return _style(fig)


def comm_map(conv, max_nodes=25, highlight_nodes=None):
    """Network graph — IPs as nodes, conversations as edges, edge width = bytes.

    highlight_nodes: set of IP strings to show in green (used for the local device).
    Returns None if there is nothing to draw.
    """
    if conv.empty:
        return None

    highlight_nodes = highlight_nodes or set()

    # Count total bytes per IP address (across all conversations).
    vol = {}
    for row in conv.itertuples():
        vol[row.a] = vol.get(row.a, 0) + row.bytes
        vol[row.b] = vol.get(row.b, 0) + row.bytes

    # Keep only the top max_nodes endpoints to avoid a cluttered graph.
    keep = set(sorted(vol, key=vol.get, reverse=True)[:max_nodes])
    sub = conv[conv["a"].isin(keep) & conv["b"].isin(keep)]

    g = nx.Graph()
    for row in sub.itertuples():
        g.add_edge(row.a, row.b, weight=row.bytes)

    if g.number_of_nodes() == 0:
        return None

    # Layout each connected group of nodes separately so isolated clusters
    # don't overlap the main group.
    comps = sorted(nx.connected_components(g), key=len, reverse=True)
    pos = {}
    for i, comp in enumerate(comps):
        sg = g.subgraph(comp)
        if len(comp) > 1:
            local_pos = nx.spring_layout(sg, seed=7, k=1.0 / math.sqrt(max(len(comp), 1)))
        else:
            local_pos = {next(iter(comp)): (0.0, 0.0)}

        scale = 1.0 if i == 0 else 0.25
        cx = 0.0 if i == 0 else 2.0 * math.cos(2 * math.pi * i / max(len(comps) - 1, 1))
        cy = 0.0 if i == 0 else 2.0 * math.sin(2 * math.pi * i / max(len(comps) - 1, 1))

        for node, (x, y) in local_pos.items():
            pos[node] = (cx + scale * x, cy + scale * y)

    max_weight = max(d["weight"] for *_, d in g.edges(data=True))
    fig = go.Figure()

    # Draw edges (one trace per edge so hover shows the pair and byte count).
    for a, b, d in g.edges(data=True):
        fig.add_trace(go.Scatter(
            x=[pos[a][0], pos[b][0]],
            y=[pos[a][1], pos[b][1]],
            mode="lines",
            line=dict(width=1 + 7 * d["weight"] / max_weight, color="rgba(144,133,233,0.55)"),
            hoverinfo="text",
            text=f"{a} ↔ {b}<br>{d['weight']:,} bytes",
        ))

    nodes = list(g.nodes)
    max_vol = max(vol[n] for n in nodes)

    # Remote nodes (blue circles)
    other_nodes = [n for n in nodes if n not in highlight_nodes]
    if other_nodes:
        fig.add_trace(go.Scatter(
            x=[pos[n][0] for n in other_nodes],
            y=[pos[n][1] for n in other_nodes],
            mode="markers",
            marker=dict(
                size=[10 + 26 * vol[n] / max_vol for n in other_nodes],
                color=SERIES[0],
                line=dict(color="#1a1a19", width=2),
            ),
            text=[f"{n}<br>{vol[n]:,} bytes" for n in other_nodes],
            hoverinfo="text",
            name="Remote device",
        ))

    # Highlighted nodes — the user's local device (green star)
    local_nodes = [n for n in nodes if n in highlight_nodes]
    if local_nodes:
        fig.add_trace(go.Scatter(
            x=[pos[n][0] for n in local_nodes],
            y=[pos[n][1] for n in local_nodes],
            mode="markers",
            marker=dict(
                size=[14 + 26 * vol[n] / max_vol for n in local_nodes],
                color="#199e70",
                symbol="star",
                line=dict(color="#1a1a19", width=2),
            ),
            text=[f"★ YOUR DEVICE — {n}<br>{vol[n]:,} bytes" for n in local_nodes],
            hoverinfo="text",
            name="Your device",
        ))

    # Label the single busiest endpoint.
    top = sorted(nodes, key=vol.get, reverse=True)[:1]
    fig.add_trace(go.Scatter(
        x=[pos[n][0] for n in top],
        y=[pos[n][1] for n in top],
        mode="text",
        text=[n if len(n) < 22 else n[:10] + "…" + n[-8:] for n in top],
        textposition="bottom center",
        textfont=dict(color=INK, size=11),
        hoverinfo="skip",
    ))

    fig.update_xaxes(visible=False)
    fig.update_yaxes(visible=False)
    return _style(fig, height=520, legend=True)
