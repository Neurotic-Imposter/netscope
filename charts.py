"""Plotly chart builders — receive ready-made data tables, return figures.

The charts match the dark dashboard theme: transparent background (the page supplies
the surface), muted grey text, hairline grid, and blue as the main series colour.
"""

import math

import networkx as nx
import pandas as pd
import plotly.graph_objects as go

# Blue leads; the rest are muted so no single hue shouts. Same order every time.
SERIES = ["#4693FF", "#9085E9", "#2BB5A0", "#D19A66", "#D55181", "#7C8AA5", "#82B6FF", "#B8A1F0"]
BLUE = SERIES[0]
GRID = "#262626"
TEXT = "#A1A1A1"
NO_COLOUR = "rgba(0,0,0,0)"
FONT = "Inter, system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif"

# One protocol keeps one colour on the communication map.
PROTOCOL_COLOURS = {"TLS": "#4693FF", "TCP": "#82B6FF", "UDP": "#9085E9", "DNS": "#2BB5A0",
                    "QUIC": "#D19A66", "HTTP": "#D55181", "ICMP": "#7C8AA5"}
OTHER_COLOUR = "#7C8AA5"

# Applied to every chart — no toolbar clutter for beginners.
CHART_CONFIG = {
    "displayModeBar": False,
    "responsive": True,
}


def _rgba(hex_colour, alpha):
    h = hex_colour.lstrip("#")
    return f"rgba({int(h[0:2], 16)},{int(h[2:4], 16)},{int(h[4:6], 16)},{alpha})"


def _style(fig, height=340, legend=False):
    """Apply the same dark, flat look to every Plotly figure."""
    fig.update_layout(
        height=height,
        showlegend=legend,
        paper_bgcolor=NO_COLOUR,
        plot_bgcolor=NO_COLOUR,
        font=dict(family=FONT, color=TEXT, size=12),
        margin=dict(l=10, r=50, t=40, b=10),
        hoverlabel=dict(bgcolor="#171717", bordercolor=GRID, font=dict(color="#EEEEEE", family=FONT)),
        legend=dict(font=dict(color=TEXT)),
    )
    axis = dict(gridcolor=GRID, zerolinecolor=GRID, linecolor=GRID, tickfont=dict(color=TEXT),
                title_font=dict(color=TEXT, size=12))
    fig.update_xaxes(**axis)
    fig.update_yaxes(**axis)
    return fig


def _title(text):
    return dict(text=text, font=dict(size=14, color="#EEEEEE"), x=0, xanchor="left")


def bar_h(df, label, value, title="", color=BLUE, x_title="Packets"):
    """Horizontal bar chart with the largest bar at the top."""
    d = df.iloc[::-1]  # flip so biggest is on top
    fig = go.Figure(go.Bar(
        x=d[value],
        y=d[label].astype(str),
        orientation="h",
        marker_color=color,
        text=d[value].map("{:,}".format),
        textposition="outside",
        textfont=dict(color=TEXT),
        cliponaxis=False,
        hovertemplate=f"%{{y}}: %{{x:,}} {x_title.lower()}<extra></extra>",
    ))
    fig.update_layout(title=_title(title))
    fig.update_xaxes(title_text=x_title)
    fig.update_yaxes(automargin=True)
    return _style(fig, height=max(260, 34 * len(d) + 80))


def protocol_donut(df, title):
    """
    Donut chart showing the share of packets for one protocol layer.
    The labels go in a legend under the chart so long names stay readable.
    """
    fig = go.Figure(go.Pie(
        labels=df["protocol"],
        values=df["packets"],
        hole=0.6,
        sort=False,
        marker=dict(colors=[SERIES[i % len(SERIES)] for i in range(len(df))],
                    line=dict(color="#0A0A0A", width=2)),
        textinfo="percent",
        hovertemplate="%{label}<br>%{value:,} packets (%{percent})<extra></extra>",
    ))
    fig.update_layout(title=_title(title), legend=dict(orientation="h", y=-0.05, yanchor="top"))
    return _style(fig, height=380, legend=True)


def time_series(tbl, y, width):
    """Line chart of packets or bytes over time."""
    label = "Bytes" if y == "bytes" else "Packets"
    fig = go.Figure(go.Scatter(
        x=tbl["seconds"],
        y=tbl[y],
        mode="lines",
        line=dict(color=BLUE, width=2),
        fill="tozeroy",
        fillcolor=_rgba(BLUE, 0.12),
        hovertemplate=f"{label} in the {width}s starting at t=%{{x}}s: %{{y:,}}<extra></extra>",
    ))
    fig.update_layout(
        xaxis_title="Seconds since capture start",
        yaxis_title=f"{label} per {width}-second period",
    )
    return _style(fig)


def histogram(tbl):
    """Bar chart showing how many packets fall into each packet-size range."""
    fig = go.Figure(go.Bar(
        x=tbl["range"],
        y=tbl["packets"],
        marker_color=BLUE,
        hovertemplate="%{x} bytes: %{y:,} packets<extra></extra>",
    ))
    fig.update_layout(xaxis_title="Packet size (bytes)", yaxis_title="Packets")
    return _style(fig)


def _short(ip):
    """Shorten very long IPv6 addresses for on-screen labels (hover shows the full address)."""
    return ip if len(ip) < 22 else ip[:10] + "…" + ip[-8:]


def comm_map(flows, top_n=12, highlight_nodes=None):
    """
    Directed communication map.

    flows: table from analysis.directed_flows (src, dst, packets, bytes, protocols, main_protocol).
    Draws the busiest `top_n` sender -> receiver connections:
      - dots are IP addresses (size = bytes sent + received in the connections shown)
      - arrows go from sender to receiver (thickness = bytes, colour = most common protocol)
    Returns None if there is nothing to draw.
    """
    if flows.empty:
        return None
    highlight_nodes = highlight_nodes or set()
    shown = flows.head(top_n)

    # Bytes per IP address, counting only the connections that are drawn.
    volume = {}
    for row in shown.itertuples():
        volume[row.src] = volume.get(row.src, 0) + row.bytes
        volume[row.dst] = volume.get(row.dst, 0) + row.bytes

    g = nx.Graph()
    g.add_nodes_from(volume)
    g.add_edges_from(zip(shown["src"], shown["dst"]))
    pos = nx.spring_layout(g, seed=7, k=1.5 / math.sqrt(len(g)))

    fig = go.Figure()
    most_bytes = shown["bytes"].max()
    pairs = set(zip(shown["src"], shown["dst"]))

    # Arrows: one annotation per connection (annotations are not chart traces).
    mid_x, mid_y, mid_text = [], [], []
    for row in shown.itertuples():
        x0, y0 = pos[row.src]
        x1, y1 = pos[row.dst]
        dx, dy = x1 - x0, y1 - y0
        length = math.hypot(dx, dy) or 1
        ux, uy = dx / length, dy / length
        # Stop the arrow just before the dots; shift it sideways if the
        # reverse direction is also drawn so the two arrows do not overlap.
        side = 0.02 if (row.dst, row.src) in pairs else 0
        sx = x0 + ux * 0.06 - uy * side
        sy = y0 + uy * 0.06 + ux * side
        ex = x1 - ux * 0.08 - uy * side
        ey = y1 - uy * 0.08 + ux * side
        colour = PROTOCOL_COLOURS.get(row.main_protocol, OTHER_COLOUR)
        width = 1 + 4 * row.bytes / most_bytes
        fig.add_annotation(
            x=ex, y=ey, ax=sx, ay=sy, xref="x", yref="y", axref="x", ayref="y",
            showarrow=True, arrowhead=2, arrowsize=min(3.0, 3.0 / width),   # head stays ~9 px at any thickness
            arrowwidth=width,
            arrowcolor=_rgba(colour, 0.85),
        )
        mid_x.append((sx + ex) / 2)
        mid_y.append((sy + ey) / 2)
        protocols = row.protocols.split(", ")
        shown_protocols = ", ".join(protocols[:4]) + (f" +{len(protocols) - 4} more" if len(protocols) > 4 else "")
        mid_text.append(
            f"{row.src} → {row.dst}<br>{row.packets:,} packets · {row.bytes:,} bytes"
            f"<br>Protocols seen: {shown_protocols}"
        )

    # One invisible trace so hovering over an arrow shows its details.
    fig.add_trace(go.Scatter(
        x=mid_x, y=mid_y, mode="markers",
        marker=dict(size=16, color=NO_COLOUR),
        text=mid_text, hoverinfo="text", showlegend=False,
    ))

    # IP address dots: one trace for the likely capture device, one for the rest.
    biggest = max(volume.values())
    labelled = set(sorted(volume, key=volume.get, reverse=True)[:12])   # keep the map readable
    for is_device, name, colour in [(False, "Other IP address", "#EEEEEE"),
                                    (True, "Likely your device (estimate)", "#00A63E")]:
        ips = [ip for ip in volume if (ip in highlight_nodes) == is_device]
        if not ips:
            continue
        fig.add_trace(go.Scatter(
            x=[pos[ip][0] for ip in ips], y=[pos[ip][1] for ip in ips],
            mode="markers+text",
            marker=dict(size=[12 + 26 * volume[ip] / biggest for ip in ips],
                        color=colour, line=dict(color="#0A0A0A", width=2)),
            text=[_short(ip) if ip in labelled else "" for ip in ips],
            textposition="top center",
            textfont=dict(color=TEXT, size=11),
            customdata=[f"{ip}<br>{volume[ip]:,} bytes in the connections shown" for ip in ips],
            hovertemplate="%{customdata}<extra></extra>",
            name=name,
        ))

    # Legend entries for the arrow colours (annotations have no legend of their own).
    for proto in dict.fromkeys(shown["main_protocol"]):
        fig.add_trace(go.Scatter(
            x=[None], y=[None], mode="lines",
            line=dict(color=PROTOCOL_COLOURS.get(proto, OTHER_COLOUR), width=3),
            name=f"Arrow: mostly {proto}",
        ))

    fig.update_xaxes(visible=False, range=[-1.4, 1.4])
    fig.update_yaxes(visible=False, range=[-1.4, 1.4], scaleanchor="x")
    fig.update_layout(legend=dict(orientation="h", y=-0.02, yanchor="top", font=dict(color=TEXT)))
    return _style(fig, height=560, legend=True)
