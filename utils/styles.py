"""
utils/styles.py
Global CSS injection and reusable HTML component helpers for APK Triage.

Uses st.html() (Streamlit 1.31+) which is the supported way to inject
raw HTML/CSS on Streamlit Cloud without being blocked.

Icon system: uses Phosphor Icons (via CDN) for a clean, consistent icon set.
All emojis have been replaced with <i class="ph-bold ph-*"> icons.

Usage in any page:
    from utils.styles import inject_css, section_header, status_pill, ioc_badge

Call inject_css() once at the top of each page, after st.set_page_config().

FIX: Phosphor Icons CDN <link> is now embedded inside _CSS and injected once
via inject_css(). Each st.html() call runs in its own sandboxed iframe, so
repeating the <link> inside every helper was unreliable. The solution is to
load the font once at page level using a <style>@import</style> trick via a
<link> tag placed in the main CSS block, which Streamlit hoists to the page
<head> rather than keeping it scoped to an iframe.
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

# ─── Icon map (Phosphor icon class names) ──────────────────────────────────────
ICONS = {
    "critical":     "ph-warning-octagon",
    "high":         "ph-warning",
    "medium":       "ph-warning-circle",
    "low":          "ph-check-circle",
    "clean":        "ph-check-circle",
    "unknown":      "ph-question",
    "telegram":     "ph-paper-plane-tilt",
    "ip":           "ph-globe",
    "url":          "ph-link",
    "ok":           "ph-check-circle",
    "warn":         "ph-warning",
    "off":          "ph-minus-circle",
    "copy":         "ph-copy",
    "save":         "ph-floppy-disk",
    "delete":       "ph-trash",
    "download":     "ph-download-simple",
    "export":       "ph-export",
    "report":       "ph-file-text",
    "signed":       "ph-seal-check",
    "package":      "ph-package",
    "database":     "ph-database",
    "scan":         "ph-magnifying-glass",
    "ai":           "ph-robot",
    "lock":         "ph-lock",
    "gear":         "ph-gear",
    "graph":        "ph-graph",
    "clock":        "ph-clock",
    "badge":        "ph-identification-badge",
    "folder":       "ph-folder",
    "shield":       "ph-shield-check",
    "virus":        "ph-bug",
    "hash":         "ph-hash",
    "tag":          "ph-tag",
    "analyst":      "ph-user",
    "case":         "ph-briefcase",
    "network":      "ph-share-network",
    "filter":       "ph-funnel",
    "expand":       "ph-caret-down",
    "refresh":      "ph-arrow-clockwise",
    "info":         "ph-info",
    "key":          "ph-key",
}

# ─── Phosphor Icons CDN URL ────────────────────────────────────────────────────
_PHOSPHOR_CDN = "https://cdn.jsdelivr.net/npm/@phosphor-icons/web@2.1.1/src/bold/style.css"

# ─── Global CSS ────────────────────────────────────────────────────────────────
# The Phosphor Icons <link> is included HERE so inject_css() loads it once at
# page level. Streamlit hoists <link> tags found in st.markdown(unsafe_allow_html)
# to the page <head>, making the icon font available globally — not scoped to a
# single iframe the way st.html() content is.

_CSS = f"""
<link rel="stylesheet" href="{_PHOSPHOR_CDN}"/>

<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');

:root {{
  --apk-bg:          #0b0f19;
  --apk-surface:     #131b2e;
  --apk-surface2:    #1e2942;
  --apk-border:      #243656;
  --apk-border2:     #1c2c47;
  --apk-text:        #f1f5f9;
  --apk-muted:       #94a3b8;
  --apk-accent:      #4ea2ff;

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
}}

/* Phosphor icon sizing harmonisation */
.ph-bold {{
  font-size: 14px;
  vertical-align: -2px;
}}
.ph-bold.ph-lg  {{ font-size: 18px; vertical-align: -3px; }}
.ph-bold.ph-xl  {{ font-size: 22px; vertical-align: -4px; }}
.ph-bold.ph-2xl {{ font-size: 28px; vertical-align: -5px; }}

html, body, [class*="css"] {{
  font-family: 'IBM Plex Sans', sans-serif !important;
  color: var(--apk-text) !important;
}}

.stApp {{
  background-color: var(--apk-bg) !important;
}}

.block-container {{
  padding-top: 5rem !important;
  max-width: 1200px !important;
}}

/* ── Sidebar ─────────────────────────────────────────────────────────── */
[data-testid="stSidebar"] {{
  background-color: var(--apk-surface) !important;
  border-right: 1px solid var(--apk-border) !important;
}}
[data-testid="stSidebar"] * {{
  color: var(--apk-text) !important;
}}

/* ── Headings ────────────────────────────────────────────────────────── */
h1 {{
  font-family: 'IBM Plex Sans', sans-serif !important;
  font-weight: 600 !important;
  font-size: 1.6rem !important;
  letter-spacing: -0.02em !important;
  color: var(--apk-text) !important;
}}
h2 {{
  font-family: 'IBM Plex Sans', sans-serif !important;
  font-weight: 500 !important;
  font-size: 1.1rem !important;
  color: var(--apk-text) !important;
  text-transform: none !important;
  letter-spacing: normal !important;
}}
h3 {{
  font-family: 'IBM Plex Sans', sans-serif !important;
  font-weight: 500 !important;
  font-size: 0.95rem !important;
  color: var(--apk-muted) !important;
  text-transform: none !important;
  letter-spacing: normal !important;
}}

/* ── Buttons ─────────────────────────────────────────────────────────── */
.stButton > button {{
  background-color: var(--apk-surface2) !important;
  border: 1px solid var(--apk-border) !important;
  color: var(--apk-text) !important;
  border-radius: var(--radius-md) !important;
  font-family: 'IBM Plex Sans', sans-serif !important;
  font-size: 13px !important;
  font-weight: 500 !important;
  transition: border-color 0.15s, background-color 0.15s !important;
}}
.stButton > button:hover {{
  border-color: var(--apk-accent) !important;
  background-color: rgba(88,166,255,0.08) !important;
}}

/* ── Download buttons ────────────────────────────────────────────────── */
.stDownloadButton > button {{
  background-color: var(--apk-surface2) !important;
  border: 1px solid var(--apk-border) !important;
  color: var(--apk-text) !important;
  border-radius: var(--radius-md) !important;
  font-family: 'IBM Plex Sans', sans-serif !important;
  font-size: 13px !important;
  font-weight: 500 !important;
  width: 100% !important;
  transition: border-color 0.15s !important;
}}
.stDownloadButton > button:hover {{
  border-color: var(--apk-accent) !important;
  background-color: rgba(88,166,255,0.08) !important;
}}

/* ── Text inputs & selects ───────────────────────────────────────────── */
.stTextInput > div > div > input,
.stSelectbox > div > div {{
  background-color: var(--apk-surface2) !important;
  border: 1px solid var(--apk-border) !important;
  border-radius: var(--radius-md) !important;
  color: var(--apk-text) !important;
  font-family: 'IBM Plex Mono', monospace !important;
  font-size: 13px !important;
}}
.stTextInput > div > div > input:focus {{
  border-color: var(--apk-accent) !important;
  box-shadow: 0 0 0 3px rgba(88,166,255,0.12) !important;
}}

/* ── File uploader ───────────────────────────────────────────────────── */
[data-testid="stFileUploader"] {{
  background-color: var(--apk-surface) !important;
  border: 1.5px dashed var(--apk-border) !important;
  border-radius: var(--radius-lg) !important;
  transition: border-color 0.2s !important;
}}
[data-testid="stFileUploader"]:hover {{
  border-color: var(--apk-accent) !important;
}}

/* ── Metrics ─────────────────────────────────────────────────────────── */
[data-testid="stMetric"] {{
  background-color: var(--apk-surface) !important;
  border: 1px solid var(--apk-border) !important;
  border-radius: var(--radius-lg) !important;
  padding: 14px 18px !important;
}}
[data-testid="stMetricLabel"] {{
  font-size: 11px !important;
  font-weight: 500 !important;
  text-transform: uppercase !important;
  letter-spacing: 0.06em !important;
  color: var(--apk-muted) !important;
}}
[data-testid="stMetricValue"] {{
  font-family: 'IBM Plex Mono', monospace !important;
  font-size: 1.2rem !important;
  font-weight: 600 !important;
  color: var(--apk-text) !important;
}}
[data-testid="stMetricValue"] > div {{
  white-space: normal !important;
  word-break: break-all !important;
  line-height: 1.3 !important;
}}

/* ── Bordered Containers ──────────────────────────────────────────────── */
[data-testid="stVerticalBlockBorderWrapper"] {{
  background-color: var(--apk-surface) !important;
  border: 1px solid var(--apk-border) !important;
  border-radius: var(--radius-lg) !important;
}}

/* ── Expanders ───────────────────────────────────────────────────────── */
[data-testid="stExpander"] {{
  background-color: var(--apk-surface) !important;
  border: 1px solid var(--apk-border) !important;
  border-radius: var(--radius-lg) !important;
}}
[data-testid="stExpander"] summary {{
  font-family: 'IBM Plex Sans', sans-serif !important;
  font-weight: 500 !important;
  font-size: 14px !important;
  color: var(--apk-text) !important;
}}

/* ── Tabs ────────────────────────────────────────────────────────────── */
.stTabs [data-baseweb="tab-list"] {{
  background-color: var(--apk-surface) !important;
  border-radius: var(--radius-lg) var(--radius-lg) 0 0 !important;
  border-bottom: 1px solid var(--apk-border) !important;
  gap: 0 !important;
}}
.stTabs [data-baseweb="tab"] {{
  font-family: 'IBM Plex Sans', sans-serif !important;
  font-size: 13px !important;
  font-weight: 500 !important;
  color: var(--apk-muted) !important;
  padding: 10px 20px !important;
  border-bottom: 2px solid transparent !important;
}}
.stTabs [aria-selected="true"] {{
  color: var(--apk-accent) !important;
  border-bottom-color: var(--apk-accent) !important;
  background-color: transparent !important;
}}

/* ── Dataframes ──────────────────────────────────────────────────────── */
[data-testid="stDataFrame"] {{
  border: 1px solid var(--apk-border) !important;
  border-radius: var(--radius-lg) !important;
  overflow: hidden !important;
}}

/* ── Alerts ──────────────────────────────────────────────────────────── */
.stAlert {{
  border-radius: var(--radius-md) !important;
  border-left-width: 3px !important;
}}

/* ── Code blocks ─────────────────────────────────────────────────────── */
code, .stCode {{
  font-family: 'IBM Plex Mono', monospace !important;
  font-size: 12px !important;
  background-color: var(--apk-surface2) !important;
  border: 1px solid var(--apk-border) !important;
  border-radius: var(--radius-sm) !important;
}}

/* ── Progress bar ────────────────────────────────────────────────────── */
.stProgress > div > div > div {{
  background-color: var(--apk-accent) !important;
  border-radius: var(--radius-sm) !important;
}}

/* ── Dividers ────────────────────────────────────────────────────────── */
hr {{
  border-color: var(--apk-border) !important;
  margin: 1.5rem 0 !important;
}}

/* ── Spinner ─────────────────────────────────────────────────────────── */
.stSpinner > div {{
  border-top-color: var(--apk-accent) !important;
}}

/* ── Caption ─────────────────────────────────────────────────────────── */
.stCaption, small {{
  color: var(--apk-muted) !important;
  font-size: 12px !important;
}}

/* ── Page links ──────────────────────────────────────────────────────── */
[data-testid="stPageLink"] a {{
  background-color: var(--apk-surface2) !important;
  border: 1px solid var(--apk-border) !important;
  border-radius: var(--radius-md) !important;
  color: var(--apk-accent) !important;
  font-family: 'IBM Plex Sans', sans-serif !important;
  font-size: 13px !important;
  font-weight: 500 !important;
  padding: 8px 16px !important;
  transition: border-color 0.15s !important;
  text-decoration: none !important;
}}
[data-testid="stPageLink"] a:hover {{
  border-color: var(--apk-accent) !important;
  background-color: rgba(88,166,255,0.08) !important;
}}
</style>
"""


def inject_css():
    """
    Injects global dark theme CSS + Phosphor Icons CDN.
    Uses st.markdown(unsafe_allow_html=True) so Streamlit hoists the <link>
    tag into the page <head> — making the icon font available to ALL subsequent
    st.html() calls on the page, not just the iframe it was injected into.

    Call once per page, right after st.set_page_config().
    """
    st.markdown(_CSS, unsafe_allow_html=True)


# ─── Reusable HTML components ──────────────────────────────────────────────────
# NOTE: All <link rel="stylesheet"> tags have been REMOVED from the individual
# helper functions below. The Phosphor font is loaded once by inject_css() and
# is available globally for the rest of the page.

def brand_header(title: str, subtitle: str = "", badge: str = ""):
    """
    Renders a premium branding header combining a glowing custom SVG shield logo,
    an optional uppercase tracking badge, the primary page title, and a high-contrast subtitle.
    """
    import base64
    
    # Shared, mathematically symmetrical premium SVG logo (avoiding fractional coordinates/fine lines)
    svg_logo = """<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M24 4L8 11V22C8 33.2 14.8 40.5 24 44C33.2 40.5 40 33.2 40 22V11L24 4Z" fill="#3b82f6"/>
      <path d="M24 7L11 13V22C11 31 16.5 37.2 24 41C31.5 37.2 37 31 37 22V13L24 7Z" fill="#131b2e" opacity="0.95"/>
      <path d="M24 13L16 28H19.5L24 19.5L28.5 28H32L24 13Z" fill="#60a5fa"/>
    </svg>"""
    
    encoded_logo = base64.b64encode(svg_logo.encode('utf-8')).decode('utf-8')
    logo_uri = f"data:image/svg+xml;base64,{encoded_logo}"
    
    badge_html = f"<div style='font-family:IBM Plex Sans,sans-serif;font-size:10px;font-weight:600;color:#4ea2ff;letter-spacing:0.12em;text-transform:uppercase;margin-bottom:6px'>{badge}</div>" if badge else ""
    sub_html = f"<p style='color:#94a3b8;font-size:13.5px;margin:4px 0 0;font-family:IBM Plex Sans,sans-serif;line-height:1.4'>{subtitle}</p>" if subtitle else ""
    
    st.markdown(f"""
    <div style='display:flex;align-items:center;gap:18px;margin:1rem 0 1.5rem'>
      <!-- Glowing SVG Logo -->
      <div style='flex-shrink:0'>
        <img src="{logo_uri}" width="52" height="52" style="display:block; filter: drop-shadow(0 0 6px rgba(59, 130, 246, 0.65))" />
      </div>
      <div>
        {badge_html}
        <h1 style='font-family:IBM Plex Sans,sans-serif;font-weight:600;font-size:1.7rem;
                   letter-spacing:-0.02em;margin:0;color:#f1f5f9;line-height:1.2'>{title}</h1>
        {sub_html}
      </div>
    </div>
    """, unsafe_allow_html=True)


def sidebar_branding():
    """
    Renders a mini brand-badge at the top of the sidebar.
    """
    import base64
    
    svg_logo_mini = """<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M24 4L8 11V22C8 33.2 14.8 40.5 24 44C33.2 40.5 40 33.2 40 22V11L24 4Z" fill="#3b82f6"/>
      <path d="M24 7L11 13V22C11 31 16.5 37.2 24 41C31.5 37.2 37 31 37 22V13L24 7Z" fill="#131b2e" opacity="0.95"/>
      <path d="M24 13L16 28H19.5L24 19.5L28.5 28H32L24 13Z" fill="#60a5fa"/>
    </svg>"""
    
    encoded_mini = base64.b64encode(svg_logo_mini.encode('utf-8')).decode('utf-8')
    mini_uri = f"data:image/svg+xml;base64,{encoded_mini}"
    
    st.markdown(f"""
    <div style='display:flex;align-items:center;gap:10px;margin-bottom:1.5rem;padding-bottom:1rem;border-bottom:1px solid #243656'>
      <img src="{mini_uri}" width="28" height="28" style="display:block; filter: drop-shadow(0 0 4px rgba(59, 130, 246, 0.5))" />
      <span style='font-family:IBM Plex Sans,sans-serif;font-weight:600;font-size:13.5px;letter-spacing:0.06em;color:#f1f5f9'>A-ANALYZER</span>
    </div>
    """, unsafe_allow_html=True)


def section_header(title: str, subtitle: str = ""):
    sub_html = (
        f"<p style='color:#94a3b8;font-size:13px;margin:2px 0 0;"
        f"font-family:IBM Plex Sans,sans-serif'>{subtitle}</p>"
    ) if subtitle else ""
    st.html(f"""
    <div style='margin:1.5rem 0 0.75rem'>
      <h2 style='font-family:IBM Plex Sans,sans-serif;font-weight:600;font-size:1rem;
                 letter-spacing:0.01em;margin:0;color:#f1f5f9'>{title}</h2>
      {sub_html}
    </div>
    """)


def status_pill(label: str, state: str = "ok"):
    icon_map = {
        "ok":   ("rgba(46,204,113,0.12)",  "#2ecc71", "ph-check-circle"),
        "warn": ("rgba(243,156,18,0.12)",  "#f39c12", "ph-warning"),
        "off":  ("rgba(149,165,166,0.12)", "#95a5a6", "ph-minus-circle"),
    }
    bg, fg, icon_class = icon_map.get(state, icon_map["off"])
    st.html(f"""
    <div style='display:inline-flex;align-items:center;gap:6px;
                padding:4px 10px;border-radius:20px;
                background:{bg};border:1px solid {fg}44;
                font-size:12px;font-weight:500;color:{fg};
                font-family:IBM Plex Sans,sans-serif;margin:4px 0'>
      <i class="ph-bold {icon_class}" style="font-size:13px"></i>
      <span>{label}</span>
    </div>
    """)


def risk_badge(risk_level: str):
    colour = RISK_COLOURS.get(risk_level, "#95a5a6")
    icon_class = ICONS.get(risk_level.lower(), "ph-question")
    st.html(f"""
    <span style='display:inline-flex;align-items:center;gap:5px;padding:3px 10px;
                 border-radius:20px;background:{colour}22;border:1px solid {colour}55;
                 color:{colour};font-size:11px;font-weight:600;
                 font-family:IBM Plex Mono,monospace;letter-spacing:0.05em'>
      <i class="ph-bold {icon_class}" style="font-size:12px"></i>
      {risk_level}
    </span>
    """)


def ioc_badge(value: str, ioc_type: str = ""):
    colour     = C2_COLOURS.get(ioc_type, "#4ea2ff")
    label      = {"telegram": "TG", "ip": "IP", "url": "URL"}.get(ioc_type, "IOC")
    icon_class = ICONS.get(ioc_type, "ph-link")
    safe_val   = value.replace("'", "\\'").replace('"', '&quot;')
    st.html(f"""
    <div style='display:flex;align-items:center;gap:8px;
                padding:7px 12px;margin:4px 0;
                background:#131b2e;border:1px solid #243656;
                border-left:3px solid {colour};border-radius:6px'>
      <span style='color:{colour};font-size:10px;font-weight:600;
                   background:{colour}22;padding:2px 7px;border-radius:3px;
                   font-family:IBM Plex Mono,monospace;white-space:nowrap;
                   display:flex;align-items:center;gap:4px'>
        <i class="ph-bold {icon_class}" style="font-size:11px"></i>{label}
      </span>
      <span style='color:#f1f5f9;flex:1;word-break:break-all;
                   font-family:IBM Plex Mono,monospace;font-size:12px'>{value}</span>
      <button onclick="navigator.clipboard.writeText('{safe_val}').then(()=>{{
                  this.innerHTML='<i class=\\'ph-bold ph-check\\' style=\\'font-size:12px\\'></i>';
                  setTimeout(()=>this.innerHTML='<i class=\\'ph-bold ph-copy\\' style=\\'font-size:12px\\'></i>',1200)}})"
              style='background:none;border:1px solid #243656;border-radius:4px;
                     color:#94a3b8;cursor:pointer;padding:3px 7px;font-size:12px;
                     transition:color 0.15s;flex-shrink:0;line-height:1'
              title='Copy to clipboard'>
        <i class="ph-bold ph-copy" style="font-size:12px"></i>
      </button>
    </div>
    """)


def permission_card(perm_name: str, description: str, score: int):
    if score >= 30:
        colour, severity = "#e74c3c", "HIGH"
    elif score >= 20:
        colour, severity = "#e67e22", "MEDIUM"
    else:
        colour, severity = "#f39c12", "LOW"

    st.html(f"""
    <div style='display:flex;align-items:flex-start;gap:12px;
                padding:10px 14px;margin:5px 0;
                background:#131b2e;border:1px solid #243656;
                border-left:3px solid {colour};border-radius:6px'>
      <div style='flex:1;min-width:0'>
        <div style='font-family:IBM Plex Mono,monospace;font-size:12px;
                    font-weight:500;color:#f1f5f9;margin-bottom:3px'>{perm_name}</div>
        <div style='font-size:12px;color:#94a3b8;line-height:1.5;
                    font-family:IBM Plex Sans,sans-serif'>{description}</div>
      </div>
      <span style='font-size:10px;font-weight:600;white-space:nowrap;flex-shrink:0;
                   padding:2px 7px;border-radius:3px;margin-top:1px;
                   background:{colour}22;color:{colour};
                   font-family:IBM Plex Mono,monospace'>{severity} +{score}</span>
    </div>
    """)


def divider_with_label(label: str):
    st.html(f"""
    <div style='display:flex;align-items:center;gap:12px;margin:1.5rem 0 1rem'>
      <div style='flex:1;height:1px;background:#243656'></div>
      <span style='font-size:10px;font-weight:600;color:#94a3b8;
                   letter-spacing:0.1em;text-transform:uppercase;
                   font-family:IBM Plex Sans,sans-serif;white-space:nowrap'>{label}</span>
      <div style='flex:1;height:1px;background:#243656'></div>
    </div>
    """)


def ai_verdict_box(summary: str):
    paragraphs = [p.strip() for p in summary.strip().split("\n\n") if p.strip()]
    paras_html = "".join(
        f"<p style='margin:0 0 10px;line-height:1.7;font-size:13px;"
        f"color:#e2e8f0;font-family:IBM Plex Sans,sans-serif'>{p}</p>"
        for p in paragraphs
    )
    st.html(f"""
    <div style='background:#131b2e;border:1px solid #243656;
                border-left:3px solid #f39c12;border-radius:8px;
                padding:16px 18px;margin:8px 0'>
      <div style='display:flex;align-items:center;gap:8px;margin-bottom:12px'>
        <i class="ph-bold ph-robot" style="font-size:16px;color:#f39c12"></i>
        <span style='font-family:IBM Plex Sans,sans-serif;font-size:11px;
                     font-weight:600;color:#f39c12;text-transform:uppercase;
                     letter-spacing:0.08em'>AI Analyst Verdict</span>
        <span style='font-size:11px;color:#94a3b8;margin-left:4px'>
          · AI-generated, not a definitive forensic finding</span>
      </div>
      {paras_html}
    </div>
    """)


def analysis_stepper(steps: list):
    parts = []
    for i, (label, state) in enumerate(steps):
        if state == "done":
            dot_bg, dot_fg, text_colour = "#2ecc71", "#0b0f19", "#2ecc71"
            dot_content = "<i class='ph-bold ph-check' style='font-size:11px'></i>"
        elif state == "active":
            dot_bg, dot_fg, text_colour = "#4ea2ff", "#0b0f19", "#4ea2ff"
            dot_content = str(i + 1)
        else:
            dot_bg, dot_fg, text_colour = "#1e2942", "#94a3b8", "#94a3b8"
            dot_content = str(i + 1)

        connector = (
            "<div style='flex:1;height:1px;background:#243656;margin:0 4px;margin-bottom:16px'></div>"
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

    st.html(f"""
    <div style='display:flex;align-items:flex-start;padding:14px 0;margin:8px 0'>
      {''.join(parts)}
    </div>
    """)


def apply_plotly_theme(fig):
    """
    Applies the custom midnight dark-blue cyber-intelligence styling to any Plotly figure.
    This replaces standard white Plotly charts with a beautiful dark-blue aesthetic.
    """
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",  # Transparent background so it fits containers
        plot_bgcolor="rgba(0,0,0,0)",   # Transparent plot area
        font=dict(family="IBM Plex Sans, sans-serif", size=12, color="#cbd5e1"), # Light-slate labels
        margin=dict(l=10, r=10, t=35, b=10), # Snug margins to save space
        showlegend=True,
        # Style the legend to be subtle
        legend=dict(
            bgcolor="rgba(19, 27, 46, 0.7)", # Subtle dark-blue slate background
            bordercolor="#243656",            # Blue-slate border
            borderwidth=1,
            font=dict(color="#94a3b8")        # Muted text for legend labels
        ),
        # X and Y Axis styling
        xaxis=dict(
            gridcolor="#1c2c47",  # Very dark blue-grey gridlines
            linecolor="#243656",  # Slate border
            tickfont=dict(color="#94a3b8"),
            zerolinecolor="#243656"
        ),
        yaxis=dict(
            gridcolor="#1c2c47",
            linecolor="#243656",
            tickfont=dict(color="#94a3b8"),
            zerolinecolor="#243656"
        ),
        # Style hover tooltips to look high-end
        hoverlabel=dict(
            bgcolor="#1e2942",
            bordercolor="#4ea2ff",
            font=dict(family="IBM Plex Mono, monospace", size=12, color="#f1f5f9")
        )
    )
    return fig
