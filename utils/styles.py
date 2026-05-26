"""
utils/styles.py
Global CSS injection and reusable HTML component helpers for APK Triage.

Usage in any page:
    from utils.styles import inject_css, section_header, status_pill, ioc_badge

Call inject_css() once at the top of each page, after st.set_page_config().
"""
import streamlit as st


# ─── Colour tokens ─────────────────────────────────────────────────────────────
RISK_COLOURS = {
    "CRITICAL": "#e74c3c",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f39c12",
    "LOW":      "#2ecc71",
    "CLEAN":    "#2ecc71",
    "UNKNOWN":  "#95a5a6",
}

C2_COLOURS = {
    "telegram": "#2980b9",
    "ip":       "#8e44ad",
    "url":      "#16a085",
}


# ─── Global CSS ────────────────────────────────────────────────────────────────

_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');

:root {
  --apk-bg:          #0d1117;
  --apk-surface:     #161b22;
  --apk-surface2:    #1c2330;
  --apk-border:      #30363d;
  --apk-border2:     #21262d;
  --apk-text:        #e6edf3;
  --apk-muted:       #7d8590;
  --apk-accent:      #58a6ff;

  --risk-critical:   #e74c3c;
  --risk-high:       #e67e22;
  --risk-medium:     #f39c12;
  --risk-low:        #2ecc71;
  --risk-clean:      #2ecc71;
  --risk-unknown:    #95a5a6;

  --c2-telegram:     #2980b9;
  --c2-ip:           #8e44ad;
  --c2-url:          #16a085;

  --radius-sm:       4px;
  --radius-md:       8px;
  --radius-lg:       12px;
}

html, body, [class*="css"] {
  font-family: 'IBM Plex Sans', sans-serif !important;
  color: var(--apk-text) !important;
}

.stApp {
  background-color: var(--apk-bg) !important;
}

.block-container {
  padding-top: 1.5rem !important;
  max-width: 1200px !important;
}

/* ── Sidebar ─────────────────────────────────────────────────────────── */
[data-testid="stSidebar"] {
  background-color: var(--apk-surface) !important;
  border-right: 1px solid var(--apk-border) !important;
}
[data-testid="stSidebar"] * {
  color: var(--apk-text) !important;
}

/* ── Headings ────────────────────────────────────────────────────────── */
h1 {
  font-family: 'IBM Plex Sans', sans-serif !important;
  font-weight: 600 !important;
  font-size: 1.6rem !important;
  letter-spacing: -0.02em !important;
  color: var(--apk-text) !important;
}
h2 {
  font-family: 'IBM Plex Sans', sans-serif !important;
  font-weight: 500 !important;
  font-size: 1.1rem !important;
  color: var(--apk-text) !important;
}
h3 {
  font-family: 'IBM Plex Sans', sans-serif !important;
  font-weight: 500 !important;
  font-size: 0.95rem !important;
  color: var(--apk-muted) !important;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

/* ── Buttons ─────────────────────────────────────────────────────────── */
.stButton > button {
  background-color: var(--apk-surface2) !important;
  border: 1px solid var(--apk-border) !important;
  color: var(--apk-text) !important;
  border-radius: var(--radius-md) !important;
  font-family: 'IBM Plex Sans', sans-serif !important;
  font-size: 13px !important;
  font-weight: 500 !important;
  transition: border-color 0.15s, background-color 0.15s !important;
}
.stButton > button:hover {
  border-color: var(--apk-accent) !important;
  background-color: rgba(88,166,255,0.08) !important;
}

/* ── Download buttons ────────────────────────────────────────────────── */
.stDownloadButton > button {
  background-color: var(--apk-surface2) !important;
  border: 1px solid var(--apk-border) !important;
  color: var(--apk-text) !important;
  border-radius: var(--radius-md) !important;
  font-family: 'IBM Plex Sans', sans-serif !important;
  font-size: 13px !important;
  font-weight: 500 !important;
  width: 100% !important;
  transition: border-color 0.15s !important;
}
.stDownloadButton > button:hover {
  border-color: var(--apk-accent) !important;
  background-color: rgba(88,166,255,0.08) !important;
}

/* ── Text inputs & selects ───────────────────────────────────────────── */
.stTextInput > div > div > input,
.stSelectbox > div > div {
  background-color: var(--apk-surface2) !important;
  border: 1px solid var(--apk-border) !important;
  border-radius: var(--radius-md) !important;
  color: var(--apk-text) !important;
  font-family: 'IBM Plex Mono', monospace !important;
  font-size: 13px !important;
}
.stTextInput > div > div > input:focus {
  border-color: var(--apk-accent) !important;
  box-shadow: 0 0 0 3px rgba(88,166,255,0.12) !important;
}

/* ── File uploader ───────────────────────────────────────────────────── */
[data-testid="stFileUploader"] {
  background-color: var(--apk-surface) !important;
  border: 1.5px dashed var(--apk-border) !important;
  border-radius: var(--radius-lg) !important;
  transition: border-color 0.2s !important;
}
[data-testid="stFileUploader"]:hover {
  border-color: var(--apk-accent) !important;
}

/* ── Metrics ─────────────────────────────────────────────────────────── */
[data-testid="stMetric"] {
  background-color: var(--apk-surface) !important;
  border: 1px solid var(--apk-border) !important;
  border-radius: var(--radius-lg) !important;
  padding: 14px 18px !important;
}
[data-testid="stMetricLabel"] {
  font-size: 11px !important;
  font-weight: 500 !important;
  text-transform: uppercase !important;
  letter-spacing: 0.06em !important;
  color: var(--apk-muted) !important;
}
[data-testid="stMetricValue"] {
  font-family: 'IBM Plex Mono', monospace !important;
  font-size: 1.6rem !important;
  font-weight: 600 !important;
  color: var(--apk-text) !important;
}

/* ── Expanders ───────────────────────────────────────────────────────── */
[data-testid="stExpander"] {
  background-color: var(--apk-surface) !important;
  border: 1px solid var(--apk-border) !important;
  border-radius: var(--radius-lg) !important;
}
[data-testid="stExpander"] summary {
  font-family: 'IBM Plex Sans', sans-serif !important;
  font-weight: 500 !important;
  font-size: 14px !important;
  color: var(--apk-text) !important;
}

/* ── Tabs ────────────────────────────────────────────────────────────── */
.stTabs [data-baseweb="tab-list"] {
  background-color: var(--apk-surface) !important;
  border-radius: var(--radius-lg) var(--radius-lg) 0 0 !important;
  border-bottom: 1px solid var(--apk-border) !important;
  gap: 0 !important;
}
.stTabs [data-baseweb="tab"] {
  font-family: 'IBM Plex Sans', sans-serif !important;
  font-size: 13px !important;
  font-weight: 500 !important;
  color: var(--apk-muted) !important;
  padding: 10px 20px !important;
  border-bottom: 2px solid transparent !important;
}
.stTabs [aria-selected="true"] {
  color: var(--apk-accent) !important;
  border-bottom-color: var(--apk-accent) !important;
  background-color: transparent !important;
}

/* ── Dataframes ──────────────────────────────────────────────────────── */
[data-testid="stDataFrame"] {
  border: 1px solid var(--apk-border) !important;
  border-radius: var(--radius-lg) !important;
  overflow: hidden !important;
}

/* ── Alerts ──────────────────────────────────────────────────────────── */
.stAlert {
  border-radius: var(--radius-md) !important;
  border-left-width: 3px !important;
}

/* ── Code blocks ─────────────────────────────────────────────────────── */
code, .stCode {
  font-family: 'IBM Plex Mono', monospace !important;
  font-size: 12px !important;
  background-color: var(--apk-surface2) !important;
  border: 1px solid var(--apk-border) !important;
  border-radius: var(--radius-sm) !important;
}

/* ── Progress bar ────────────────────────────────────────────────────── */
.stProgress > div > div > div {
  background-color: var(--apk-accent) !important;
  border-radius: var(--radius-sm) !important;
}

/* ── Dividers ────────────────────────────────────────────────────────── */
hr {
  border-color: var(--apk-border) !important;
  margin: 1.5rem 0 !important;
}

/* ── Spinner ─────────────────────────────────────────────────────────── */
.stSpinner > div {
  border-top-color: var(--apk-accent) !important;
}

/* ── Caption ─────────────────────────────────────────────────────────── */
.stCaption, small {
  color: var(--apk-muted) !important;
  font-size: 12px !important;
}
</style>
"""


def inject_css():
    """
    Call once per page, right after st.set_page_config().
    Injects the global dark theme, IBM Plex typography, and component overrides.
    """
    st.markdown(_CSS, unsafe_allow_html=True)


# ─── Reusable HTML components ──────────────────────────────────────────────────

def section_header(title: str, subtitle: str = ""):
    """
    Styled section heading with optional subtitle.
    Replaces st.subheader() + st.caption() pairs.

    Usage:
        section_header("Permissions", "Dangerous capabilities detected in this APK")
    """
    sub_html = (
        f"<p style='color:#7d8590;font-size:13px;margin:2px 0 0;font-family:IBM Plex Sans,sans-serif'>"
        f"{subtitle}</p>"
    ) if subtitle else ""
    st.markdown(f"""
    <div style='margin:1.5rem 0 0.75rem'>
      <h2 style='font-family:IBM Plex Sans,sans-serif;font-weight:600;font-size:1rem;
                 letter-spacing:0.01em;margin:0;color:#e6edf3'>{title}</h2>
      {sub_html}
    </div>
    """, unsafe_allow_html=True)


def status_pill(label: str, state: str = "ok"):
    """
    Coloured pill badge for sidebar status indicators.
    state: "ok" | "warn" | "off"

    Usage:
        status_pill("GTI key loaded", "ok")
        status_pill("AI not configured", "off")
    """
    colours = {
        "ok":   ("rgba(46,204,113,0.12)",  "#2ecc71", "✓"),
        "warn": ("rgba(243,156,18,0.12)",  "#f39c12", "⚠"),
        "off":  ("rgba(149,165,166,0.12)", "#95a5a6", "○"),
    }
    bg, fg, icon = colours.get(state, colours["off"])
    st.markdown(f"""
    <div style='display:inline-flex;align-items:center;gap:6px;
                padding:4px 10px;border-radius:20px;
                background:{bg};border:1px solid {fg}44;
                font-size:12px;font-weight:500;color:{fg};
                font-family:IBM Plex Sans,sans-serif;margin:4px 0'>
      <span>{icon}</span><span>{label}</span>
    </div>
    """, unsafe_allow_html=True)


def risk_badge(risk_level: str):
    """
    Inline risk level badge.

    Usage:
        risk_badge("CRITICAL")
    """
    colour = RISK_COLOURS.get(risk_level, "#95a5a6")
    st.markdown(f"""
    <span style='display:inline-block;padding:3px 10px;border-radius:20px;
                 background:{colour}22;border:1px solid {colour}55;
                 color:{colour};font-size:11px;font-weight:600;
                 font-family:IBM Plex Mono,monospace;letter-spacing:0.05em'>
      {risk_level}
    </span>
    """, unsafe_allow_html=True)


def ioc_badge(value: str, ioc_type: str = ""):
    """
    Styled IoC row with a copy-to-clipboard button.
    ioc_type: "telegram" | "ip" | "url" | ""

    Usage:
        ioc_badge("t.me/somebot", "telegram")
        ioc_badge("103.44.120.5", "ip")
    """
    colour    = C2_COLOURS.get(ioc_type, "#58a6ff")
    label     = {"telegram": "TG", "ip": "IP", "url": "URL"}.get(ioc_type, "IOC")
    safe_val  = value.replace("'", "\\'").replace('"', '&quot;')
    st.markdown(f"""
    <div style='display:flex;align-items:center;gap:8px;
                padding:7px 12px;margin:4px 0;
                background:#161b22;border:1px solid #30363d;
                border-left:3px solid {colour};border-radius:6px'>
      <span style='color:{colour};font-size:10px;font-weight:600;
                   background:{colour}22;padding:1px 6px;border-radius:3px;
                   font-family:IBM Plex Mono,monospace;white-space:nowrap'>{label}</span>
      <span style='color:#e6edf3;flex:1;word-break:break-all;
                   font-family:IBM Plex Mono,monospace;font-size:12px'>{value}</span>
      <button onclick="navigator.clipboard.writeText('{safe_val}').then(()=>{{
                  this.textContent='✓';setTimeout(()=>this.textContent='⎘',1200)}})"
              style='background:none;border:1px solid #30363d;border-radius:4px;
                     color:#7d8590;cursor:pointer;padding:2px 7px;font-size:12px;
                     transition:color 0.15s;flex-shrink:0'
              title='Copy to clipboard'>⎘</button>
    </div>
    """, unsafe_allow_html=True)


def permission_card(perm_name: str, description: str, score: int):
    """
    Compact permission card replacing st.error() blocks.
    Shows severity-coloured left border and score badge.

    Usage:
        permission_card("RECEIVE_SMS", "Intercepts incoming SMS — steals TAC/OTP", 50)
    """
    if score >= 30:
        colour, severity = "#e74c3c", "HIGH"
    elif score >= 20:
        colour, severity = "#e67e22", "MEDIUM"
    else:
        colour, severity = "#f39c12", "LOW"

    st.markdown(f"""
    <div style='display:flex;align-items:flex-start;gap:12px;
                padding:10px 14px;margin:5px 0;
                background:#161b22;border:1px solid #30363d;
                border-left:3px solid {colour};border-radius:6px'>
      <div style='flex:1;min-width:0'>
        <div style='font-family:IBM Plex Mono,monospace;font-size:12px;
                    font-weight:500;color:#e6edf3;margin-bottom:3px'>{perm_name}</div>
        <div style='font-size:12px;color:#7d8590;line-height:1.5;
                    font-family:IBM Plex Sans,sans-serif'>{description}</div>
      </div>
      <span style='font-size:10px;font-weight:600;white-space:nowrap;flex-shrink:0;
                   padding:2px 7px;border-radius:3px;margin-top:1px;
                   background:{colour}22;color:{colour};
                   font-family:IBM Plex Mono,monospace'>{severity} +{score}</span>
    </div>
    """, unsafe_allow_html=True)


def divider_with_label(label: str):
    """
    Labelled section divider, replaces st.divider().

    Usage:
        divider_with_label("Evidence Integrity")
    """
    st.markdown(f"""
    <div style='display:flex;align-items:center;gap:12px;margin:1.5rem 0 1rem'>
      <div style='flex:1;height:1px;background:#30363d'></div>
      <span style='font-size:10px;font-weight:600;color:#7d8590;
                   letter-spacing:0.1em;text-transform:uppercase;
                   font-family:IBM Plex Sans,sans-serif;white-space:nowrap'>{label}</span>
      <div style='flex:1;height:1px;background:#30363d'></div>
    </div>
    """, unsafe_allow_html=True)


def ai_verdict_box(summary: str):
    """
    Renders the AI analyst verdict in a clearly-labelled amber callout box.

    Usage:
        ai_verdict_box(ai_summary_text)
    """
    paragraphs = [p.strip() for p in summary.strip().split("\n\n") if p.strip()]
    paras_html = "".join(
        f"<p style='margin:0 0 10px;line-height:1.7;font-size:13px;"
        f"color:#c9d1d9;font-family:IBM Plex Sans,sans-serif'>{p}</p>"
        for p in paragraphs
    )
    st.markdown(f"""
    <div style='background:#161b22;border:1px solid #30363d;
                border-left:3px solid #f39c12;border-radius:8px;
                padding:16px 18px;margin:8px 0'>
      <div style='display:flex;align-items:center;gap:8px;margin-bottom:12px'>
        <span style='font-size:15px'>🤖</span>
        <span style='font-family:IBM Plex Sans,sans-serif;font-size:11px;
                     font-weight:600;color:#f39c12;text-transform:uppercase;
                     letter-spacing:0.08em'>AI Analyst Verdict</span>
        <span style='font-size:11px;color:#7d8590;margin-left:4px'>
          · AI-generated, not a definitive forensic finding</span>
      </div>
      {paras_html}
    </div>
    """, unsafe_allow_html=True)


def analysis_stepper(steps: list):
    """
    Horizontal step progress indicator.
    steps: list of (label, state) — state is "done" | "active" | "pending"

    Usage:
        analysis_stepper([
            ("Static Analysis", "done"),
            ("GTI Enrichment",  "done"),
            ("AI Verdict",      "active"),
            ("Saved",           "pending"),
        ])
    """
    parts = []
    for i, (label, state) in enumerate(steps):
        if state == "done":
            dot_bg, dot_fg, text_colour, dot_content = "#2ecc71", "#0d1117", "#2ecc71", "✓"
        elif state == "active":
            dot_bg, dot_fg, text_colour, dot_content = "#58a6ff", "#0d1117", "#58a6ff", str(i + 1)
        else:
            dot_bg, dot_fg, text_colour, dot_content = "#21262d", "#7d8590", "#7d8590", str(i + 1)

        connector = (
            "<div style='flex:1;height:1px;background:#30363d;margin:0 4px;margin-bottom:16px'></div>"
            if i < len(steps) - 1 else ""
        )
        parts.append(f"""
        <div style='display:flex;align-items:center;flex:1'>
          <div style='display:flex;flex-direction:column;align-items:center;gap:5px'>
            <div style='width:26px;height:26px;border-radius:50%;
                        background:{dot_bg};color:{dot_fg};
                        display:flex;align-items:center;justify-content:center;
                        font-size:11px;font-weight:600;
                        font-family:IBM Plex Mono,monospace'>{dot_content}</div>
            <span style='font-size:10px;font-weight:500;color:{text_colour};
                         white-space:nowrap;font-family:IBM Plex Sans,sans-serif;
                         letter-spacing:0.03em'>{label}</span>
          </div>
          {connector}
        </div>
        """)

    st.markdown(f"""
    <div style='display:flex;align-items:flex-start;padding:14px 0;margin:8px 0'>
      {''.join(parts)}
    </div>
    """, unsafe_allow_html=True)