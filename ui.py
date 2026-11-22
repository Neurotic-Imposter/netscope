"""Design system: theme CSS and the few reusable components every page shares.

Tokens (dark-first, flat surfaces, thin borders, blue as the one interactive colour):
  canvas #0A0A0A · surface #111111 · raised #171717 · elevated #222222 · border #262626
  ink #EEEEEE · muted #A1A1A1 · blue #4693FF (text) / #056DFF (buttons)
  green #00A63E = normal · amber #D19A66 = review · red #FF6467 = concerning

Only fixed strings are ever placed into HTML here. Anything that comes from a capture
(IP addresses, domain names, descriptions) goes through Streamlit's own widgets instead.
"""

import re

import streamlit as st

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Fira+Code:wght@400&display=swap');
:root {
  --canvas:#0A0A0A; --surface:#111111; --raised:#171717; --elevated:#222222; --border:#262626;
  --ink:#EEEEEE; --muted:#A1A1A1; --blue:#4693FF; --action:#056DFF;
  --ok:#00A63E; --warn:#D19A66; --bad:#FF6467; --radius:8px;
}
html, body, .stApp, button, input, textarea, select {
  font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
code, pre, [data-testid="stCode"] * { font-family: "Fira Code", ui-monospace, Consolas, monospace !important; }

/* Page frame */
.stApp { background: var(--canvas); }
[data-testid="stHeader"] { background: transparent; }
footer, #MainMenu, [data-testid="stToolbar"], [data-testid="stDecoration"] { visibility: hidden; height: 0; }
.block-container { max-width: 1200px; padding: 2.25rem 2rem 4rem; }

/* Type scale: compact, hierarchy from size and colour */
h1, h2, h3, h4 { letter-spacing: -0.02em; }
[data-testid="stHeading"] h1 { font-size: 2rem; font-weight: 700; }
[data-testid="stHeading"] h2 { font-size: 1.5rem; font-weight: 600; }
[data-testid="stHeading"] h3 { font-size: 1.125rem; font-weight: 600; margin-top: .25rem; }
[data-testid="stCaptionContainer"], .stCaption { color: var(--muted); }

/* Sidebar = left navigation */
[data-testid="stSidebar"] { background: var(--surface); border-right: 1px solid var(--border); }
[data-testid="stSidebar"] [role="radiogroup"] { gap: 2px; }
[data-testid="stSidebar"] [role="radiogroup"] label {
  padding: .5rem .75rem; border-radius: var(--radius); width: 100%; margin: 0; cursor: pointer;
}
[data-testid="stSidebar"] [data-testid="stRadioOption"] > div > div:first-child { display: none; }  /* hide the radio dot */
[data-testid="stSidebar"] [role="radiogroup"] label p { font-size: .875rem; font-weight: 500; color: var(--muted); }
[data-testid="stSidebar"] [role="radiogroup"] label:hover { background: var(--elevated); }
[data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) {
  background: var(--elevated); box-shadow: inset 2px 0 0 var(--blue);
}
[data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) p { color: var(--ink); }
.ns-brand { margin-bottom: 1.25rem; font-weight: 600; font-size: .95rem; line-height: 1.3; color: var(--ink); }
.ns-brand small { display: block; font-weight: 500; font-size: .75rem; color: var(--muted); margin-top: 2px; }

/* Cards: flat, hairline border, small radius */
[data-testid="stMetric"] { padding: .15rem 0; }
[data-testid="stMetricLabel"] p { font-size: .8125rem; font-weight: 500; color: var(--muted); }
[data-testid="stMetricValue"] { font-size: 1.5rem; font-weight: 600; letter-spacing: -0.02em; }

/* Controls */
.stButton > button, .stDownloadButton > button {
  border-radius: var(--radius); font-weight: 500; font-size: .875rem; padding: .5rem 1rem;
  background: var(--elevated); border: 1px solid var(--border); color: var(--ink);
}
.stButton > button:hover, .stDownloadButton > button:hover { border-color: var(--blue); color: var(--ink); }
.stButton > button[kind="primary"], .stDownloadButton > button[kind="primary"] {
  background: var(--action); border-color: var(--action); color: #fff;
}
.stButton > button[kind="primary"]:hover { background: #086FFF; }
:focus-visible { outline: 2px solid var(--blue) !important; outline-offset: 2px; }
[data-testid="stTextInput"] input, [data-testid="stSelectbox"] div[data-baseweb="select"] > div {
  background: var(--elevated); border-radius: var(--radius);
}
[data-testid="stTabs"] [role="tab"] { font-size: .875rem; font-weight: 500; }
[data-testid="stExpander"] { border-radius: var(--radius); border-color: var(--border); }
[data-testid="stAlert"] { border-radius: var(--radius); border: 1px solid var(--border); background: var(--surface); }
[data-testid="stFileUploaderDropzone"] {
  background: var(--surface); border: 1.5px dashed #3a3a3a; border-radius: var(--radius); padding: 1.5rem;
}
[data-testid="stFileUploaderDropzone"]:hover { border-color: var(--blue); }

/* Landing page */
.ns-eyebrow { display: inline-block; font-size: .75rem; font-weight: 600; letter-spacing: .06em; text-transform: uppercase;
  color: var(--blue); border: 1px solid var(--border); background: var(--surface); border-radius: 999px; padding: .2rem .7rem; }
.ns-hero h1 { font-size: 2.25rem; line-height: 1.11; letter-spacing: -0.04em; margin: .6rem 0 .5rem; font-weight: 700; }
.ns-lead { font-size: 1.05rem; color: #cfcfcf; max-width: 46rem; line-height: 1.55; }
.ns-card { border: 1px solid var(--border); background: var(--surface); border-radius: var(--radius); padding: 1.1rem 1.25rem; height: 100%; }
.ns-card h4 { margin: 0 0 .4rem; font-size: 1rem; font-weight: 600; }
.ns-card p, .ns-card li { font-size: .875rem; color: var(--muted); line-height: 1.5; }
.ns-card ul { padding-left: 1.1rem; margin: .25rem 0 0; }
.ns-card.accent { border-color: #1d4f99; }
.ns-step { display: flex; gap: .75rem; align-items: flex-start; margin: .6rem 0; font-size: .95rem; color: #cfcfcf; }
.ns-step .ns-num { flex: 0 0 1.6rem; height: 1.6rem; border-radius: 999px; background: var(--elevated); border: 1px solid var(--border);
  display: inline-flex; align-items: center; justify-content: center; font-size: .75rem; color: var(--blue); }

/* Educational simulation */
.ns-flow { display: flex; align-items: center; justify-content: space-between; gap: .5rem; margin: .5rem 0 1rem; }
.ns-node { flex: 1 1 0; text-align: center; border: 1px solid var(--border); background: var(--surface); border-radius: var(--radius);
  padding: .8rem .4rem; font-size: .85rem; font-weight: 600; }
.ns-node span { display: block; font-weight: 400; font-size: .75rem; color: var(--muted); margin-top: 2px; font-family: "Fira Code", monospace; }
.ns-hop { flex: 0 0 auto; text-align: center; font-size: 1.25rem; color: #3a3a3a; min-width: 3.5rem; }
.ns-hop.on { color: var(--blue); }
.ns-hop small { display: block; font-size: .65rem; color: var(--muted); font-family: Inter, sans-serif; }
.ns-sim-tag { display: inline-block; font-size: .7rem; font-weight: 600; letter-spacing: .06em; text-transform: uppercase;
  color: var(--warn); border: 1px solid #4a3a28; border-radius: 999px; padding: .15rem .6rem; }

/* Status chips */
.ns-chip { display: inline-block; font-size: .7rem; font-weight: 600; border-radius: 999px; padding: .12rem .55rem;
  border: 1px solid var(--border); background: var(--elevated); color: var(--muted); vertical-align: middle; }
.ns-chip.ok { color: #3ddc84; border-color: #14532d; background: #0b2415; }
.ns-chip.warn { color: var(--warn); border-color: #4a3a28; background: #241b10; }
.ns-chip.bad { color: var(--bad); border-color: #5a1d1f; background: #2a1112; }
.ns-chip.blue { color: var(--blue); border-color: #1d4f99; background: #0c1b33; }
.ns-muted { color: var(--muted); font-size: .85rem; }

@media (max-width: 640px) {
  .block-container { padding: 1.25rem 1rem 3rem; }
  .ns-hero h1 { font-size: 1.75rem; }
  .ns-flow { flex-direction: column; }
  .ns-hop { transform: rotate(90deg); min-width: 0; }
}
@media (prefers-reduced-motion: reduce) { * { transition: none !important; animation: none !important; } }
</style>
"""

# The big drop zone is only for the upload area in the main page (the sidebar keeps the compact one).
BIG_DROPZONE = """
<style>
[data-testid="stMain"] [data-testid="stFileUploaderDropzone"] {
  min-height: 11rem; flex-direction: column; align-items: center; justify-content: center; text-align: center; gap: .75rem;
  border-color: #1d4f99; background: #0b1220;
}
[data-testid="stMain"] [data-testid="stFileUploaderDropzone"] button { background: var(--action); border-color: var(--action); color: #fff; }
</style>
"""


def inject_theme():
    st.markdown(CSS + BIG_DROPZONE, unsafe_allow_html=True)


def md_escape(text):
    """Make text from a capture (such as a file name) safe to place inside Markdown."""
    return re.sub(r"([\\`*_{}\[\]()#+\-.!|<>~$&])", r"\\\1", str(text))


def chip(text, kind=""):
    """A small status label. `text` must be a fixed string, never capture data."""
    return f'<span class="ns-chip {kind}">{text}</span>'


def page_header(title, description, technical=None):
    """Page title, a one-sentence explanation and (optionally) the technical name."""
    st.header(title)
    text = description if technical is None else f"{description}  \nTechnical name: *{technical}*"
    st.caption(text)


def metric_card(column, label, value, help_text):
    """A KPI in a bordered card. The (?) tooltip explains it in plain language."""
    with column:
        with st.container(border=True):
            st.metric(label, value, help=help_text)


def sim_flow(direction, reaches_server):
    """The Laptop → Router / Network → Website server picture for the landing-page simulation.

    DNS steps only travel as far as the router / DNS server, so the second hop stays dim for them.
    """
    right = direction == "right"
    arrow_a, arrow_b = ("→", "→") if right else ("←", "←")
    label = "request" if right else "response"
    return (
        '<div class="ns-flow">'
        '<div class="ns-node">Laptop<span>192.168.1.23</span></div>'
        f'<div class="ns-hop on">{arrow_a}<small>{label}</small></div>'
        '<div class="ns-node">Router / Network<span>192.168.1.1</span></div>'
        f'<div class="ns-hop{" on" if reaches_server else ""}">{arrow_b}<small>{label if reaches_server else ""}</small></div>'
        '<div class="ns-node">Website server<span>203.0.113.10</span></div>'
        '</div>'
    )
