"""Aegis dashboard — Streamlit UI (PDF FR-11, sections 7/11).

A thin, read-only observability surface over the Aegis SDK: it renders the decisions the SDK and
eval harness produce and never makes a security decision itself. All data comes from
:mod:`dashboard.data`, which drives the real SDK / ``run_suite`` in-process — so the dashboard runs
fully offline with zero artifacts required.

Layout: a persistent header (product name + policy-mode selector), a left nav rail selecting one of
five views, and a dark "security console" theme. Launch with ``scripts/run_dashboard.py`` or
``streamlit run dashboard/app.py``.
"""

from __future__ import annotations

import html

import streamlit as st

import dashboard.data as data
from aegis.policy import Mode

# ---------------------------------------------------------------------------------------------
# Theme — dark "security console" palette (matches the approved Figma mocks). The Streamlit
# config.toml sets the base theme; this CSS styles the bespoke pieces (badges, cards, bars).
# ---------------------------------------------------------------------------------------------
BG, SURFACE, SURFACE2 = "#0E1117", "#161B22", "#1C222B"
BORDER, TEXT, MUTED, BLUE = "#2A2F37", "#E6EDF3", "#8B949E", "#58A6FF"

CSS = f"""
<style>
  .stApp {{ background:{BG}; color:{TEXT}; }}
  section[data-testid="stSidebar"] {{ background:{SURFACE}; border-right:1px solid {BORDER}; }}
  .aegis-badge {{ display:inline-block; padding:2px 10px; border-radius:6px;
      font-weight:700; font-size:0.74rem; letter-spacing:0.04em; }}
  .aegis-chip {{ display:inline-block; padding:1px 8px; margin:2px 4px 2px 0; border-radius:10px;
      background:{SURFACE2}; border:1px solid {BORDER}; color:{MUTED}; font-size:0.72rem; }}
  .aegis-phase {{ display:inline-block; min-width:42px; text-align:center; padding:1px 6px;
      border-radius:4px; background:{SURFACE2}; border:1px solid {BORDER}; color:{BLUE};
      font-size:0.66rem; font-weight:700; }}
  .aegis-card {{ background:{SURFACE}; border:1px solid {BORDER}; border-radius:10px;
      padding:12px 16px; margin-bottom:10px; }}
  .aegis-mono {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; color:{TEXT};
      font-size:0.82rem; }}
  .aegis-muted {{ color:{MUTED}; }}
  .aegis-bar-track {{ background:{SURFACE2}; border-radius:5px; height:9px; width:100%;
      overflow:hidden; border:1px solid {BORDER}; }}
  .aegis-bar-fill {{ height:100%; border-radius:5px; }}
  .aegis-banner {{ background:{SURFACE2}; border:1px solid {BORDER}; border-left:3px solid {BLUE};
      border-radius:6px; padding:8px 12px; color:{MUTED}; font-size:0.8rem; }}
  .aegis-metric {{ background:{SURFACE}; border:1px solid {BORDER}; border-radius:10px;
      padding:10px 14px; text-align:center; }}
  .aegis-metric .v {{ font-size:1.5rem; font-weight:700; color:{TEXT}; }}
  .aegis-metric .l {{ font-size:0.72rem; color:{MUTED}; letter-spacing:0.03em; }}
</style>
"""


def badge(action: str) -> str:
    """A colored action badge (HTML span) using the shared :data:`dashboard.data.ACTION_META`."""
    meta = data.ACTION_META[action]
    return (f'<span class="aegis-badge" style="background:{meta["bg"]};color:{meta["fg"]}">'
            f'{meta["label"]}</span>')


def chips(items: list[str]) -> str:
    """Render a list of detector/label strings as inline chips."""
    return "".join(f'<span class="aegis-chip">{html.escape(str(i))}</span>' for i in items) or \
        '<span class="aegis-muted">—</span>'


def risk_bar(score: float, color: str = BLUE) -> str:
    """A thin 0..1 risk bar as inline HTML (used in the feed and comparison rows)."""
    pct = max(0.0, min(1.0, score)) * 100
    return (f'<div class="aegis-bar-track"><div class="aegis-bar-fill" '
            f'style="width:{pct:.0f}%;background:{color}"></div></div>')


def metric_card(value: str, label: str) -> str:
    return f'<div class="aegis-metric"><div class="v">{value}</div><div class="l">{label}</div></div>'


# ---------------------------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------------------------
def view_feed(mode: Mode) -> None:
    """V1 — Live Decision Feed: reverse-chronological stream of guarded turns."""
    st.subheader("Live Decision Feed")
    view = data.run_view(mode)

    if not view.rows:
        st.markdown('<div class="aegis-banner">No events yet. Run '
                    '<span class="aegis-mono">scripts/run_demo.py</span> or drive the gateway '
                    'to populate the feed.</div>', unsafe_allow_html=True)
        return

    c = st.columns(4)
    c[0].markdown(metric_card(str(view.total), "TOTAL TURNS"), unsafe_allow_html=True)
    c[1].markdown(metric_card(str(view.blocked), "BLOCKED"), unsafe_allow_html=True)
    c[2].markdown(metric_card(str(view.escalated), "ESCALATED"), unsafe_allow_html=True)
    c[3].markdown(metric_card(str(view.warnings), "WARNINGS"), unsafe_allow_html=True)
    st.write("")

    actions = ["(all)"] + list(data.ACTION_META)
    phases = ["(all)", "request", "tool_call", "response"]
    f = st.columns([1, 1, 2])
    pick_action = f[0].selectbox("Action", actions, key="feed_action")
    pick_phase = f[1].selectbox("Phase", phases, key="feed_phase")
    query = f[2].text_input("Filter scenario / category", key="feed_query").strip().lower()

    rows = [
        r for r in view.rows
        if (pick_action == "(all)" or r.action == pick_action)
        and (pick_phase == "(all)" or r.phase == pick_phase)
        and (not query or query in r.scenario_id.lower() or query in r.category.lower())
    ]
    if not rows:
        st.markdown('<div class="aegis-banner">No turns match the current filter.</div>',
                    unsafe_allow_html=True)
        return

    for r in rows:
        cols = st.columns([1.1, 3.1, 2.4, 1.4, 1.0])
        cols[0].markdown(f'<span class="aegis-phase">{r.phase_icon}</span> {badge(r.action)}',
                         unsafe_allow_html=True)
        label = html.escape(r.scenario_id)
        sub = html.escape(r.category if r.is_attack else f"{r.category} (benign)")
        cols[1].markdown(
            f'<div class="aegis-mono">{label}</div>'
            f'<div class="aegis-muted" style="font-size:0.74rem">{sub}</div>'
            f'<div class="aegis-muted" style="font-size:0.72rem">{html.escape(r.input_summary)}</div>',
            unsafe_allow_html=True)
        cols[2].markdown(chips(r.detectors), unsafe_allow_html=True)
        cols[3].markdown(f'{risk_bar(r.risk_score)}<div class="aegis-muted" '
                         f'style="font-size:0.7rem">risk {r.risk_score:.2f}</div>',
                         unsafe_allow_html=True)
        cols[4].markdown(f'<div class="aegis-muted" style="font-size:0.74rem">'
                         f'{r.latency_ms:.2f} ms</div>', unsafe_allow_html=True)
        if cols[4].button("Detail", key=f"detail_{r.scenario_id}"):
            st.session_state["selected_scenario"] = r.scenario_id
            st.session_state["nav"] = "V2 · Decision Detail"
            st.rerun()
        st.markdown(f'<hr style="border-color:{BORDER};margin:6px 0">', unsafe_allow_html=True)


def view_detail(mode: Mode) -> None:
    """V2 — Decision Detail: full per-detector evidence for one guarded turn."""
    st.subheader("Decision Detail")
    scenarios = data.get_scenarios()
    ids = [s.id for s in scenarios]
    selected = st.session_state.get("selected_scenario", ids[0] if ids else None)
    if selected not in ids:
        selected = ids[0] if ids else None
    if selected is None:
        st.markdown('<div class="aegis-banner">No scenarios available.</div>',
                    unsafe_allow_html=True)
        return
    selected = st.selectbox("Scenario", ids, index=ids.index(selected), key="detail_select")
    st.session_state["selected_scenario"] = selected

    det = data.decision_detail(selected, mode)
    if det is None:
        st.markdown('<div class="aegis-banner">Could not resolve that scenario.</div>',
                    unsafe_allow_html=True)
        return

    st.markdown(
        f'<div class="aegis-card">{badge(det.action)} &nbsp; '
        f'<span class="aegis-phase">{data.PHASE_ICON.get(det.phase, det.phase)}</span> &nbsp;'
        f'<span class="aegis-mono">{html.escape(det.scenario_id)}</span> &nbsp;'
        f'<span class="aegis-muted">· {html.escape(det.category)} · mode {det.mode} · risk '
        f'{det.risk_score:.2f}</span><br>'
        f'<span class="aegis-muted" style="font-size:0.78rem">trace_id '
        f'{html.escape(det.trace_id)}</span><br>'
        f'<span class="aegis-muted" style="font-size:0.8rem">{html.escape(det.description)}</span>'
        f'</div>', unsafe_allow_html=True)

    st.markdown("**Per-detector evidence**")
    for h in det.detector_hits:
        cols = st.columns([1.4, 1, 1, 1.2, 1.2, 0.9])
        cols[0].markdown(f'<span class="aegis-mono">{html.escape(h.detector_name)}</span>',
                         unsafe_allow_html=True)
        cols[1].markdown(f'score {h.score:.2f}')
        cols[2].markdown(f'conf {h.confidence:.2f}')
        cols[3].markdown(f'<span class="aegis-muted">{h.verdict}</span>', unsafe_allow_html=True)
        cols[4].markdown(badge(h.recommended_action), unsafe_allow_html=True)
        cols[5].markdown(f'<span class="aegis-muted" style="font-size:0.74rem">{h.latency_ms:.2f} '
                         f'ms</span>', unsafe_allow_html=True)
        if h.evidence:
            with st.expander(f"evidence · {h.detector_name}"):
                st.json(h.evidence)

    st.markdown("**Policy reasons**")
    if det.reasons:
        for reason in det.reasons:
            st.markdown(f'- <span class="aegis-mono">{html.escape(reason)}</span>',
                        unsafe_allow_html=True)
    else:
        st.markdown('<span class="aegis-muted">Clean ALLOW — no rules fired.</span>',
                    unsafe_allow_html=True)

    st.markdown("**Inbound vs returned**")
    left, right = st.columns(2)
    left.markdown(f'<div class="aegis-card"><div class="aegis-muted" '
                  f'style="font-size:0.72rem">INBOUND (redacted)</div>'
                  f'<div class="aegis-mono">{html.escape(det.input_summary)}</div></div>',
                  unsafe_allow_html=True)
    if det.sanitized_payload is not None:
        right.markdown('<div class="aegis-card"><div class="aegis-muted" '
                       'style="font-size:0.72rem">RETURNED (sanitized — least disclosure)</div>'
                       '</div>', unsafe_allow_html=True)
        right.code(str(det.sanitized_payload))
    elif det.refusal is not None:
        right.markdown(f'<div class="aegis-card"><div class="aegis-muted" '
                       f'style="font-size:0.72rem">RETURNED (refusal)</div>'
                       f'<div class="aegis-mono">{html.escape(det.refusal)}</div></div>',
                       unsafe_allow_html=True)
    else:
        right.markdown('<div class="aegis-card"><div class="aegis-muted" '
                       'style="font-size:0.72rem">RETURNED</div>'
                       '<div class="aegis-mono">Forwarded unchanged (ALLOW / WARN).</div></div>',
                       unsafe_allow_html=True)


def view_comparison(mode: Mode) -> None:
    """V3 — Baseline vs Protected: the demo headline, observe vs protected per scenario."""
    st.subheader("Baseline vs Protected")
    st.markdown('<div class="aegis-banner">Same scenarios run by the vulnerable agent '
                '(<b>observe</b> — records, never blocks) next to the protected agent. '
                'Highlighted rows are where Aegis stops what the baseline leaked.</div>',
                unsafe_allow_html=True)
    st.write("")
    rows = data.baseline_vs_protected(mode)

    head = st.columns([2.6, 1.3, 1.3, 3.0])
    for col, name in zip(head, ["SCENARIO", "BASELINE", "PROTECTED", "EVIDENCE"]):
        col.markdown(f'<span class="aegis-muted" style="font-size:0.72rem">{name}</span>',
                     unsafe_allow_html=True)

    for r in rows:
        cols = st.columns([2.6, 1.3, 1.3, 3.0])
        accent = f'border-left:3px solid {BLUE};padding-left:8px' if r.protected_stops_more else ''
        cols[0].markdown(
            f'<div style="{accent}"><span class="aegis-mono">{html.escape(r.scenario_id)}</span>'
            f'<br><span class="aegis-muted" style="font-size:0.72rem">{html.escape(r.category)}'
            f'</span></div>', unsafe_allow_html=True)
        cols[1].markdown(badge(r.baseline_action), unsafe_allow_html=True)
        cols[2].markdown(badge(r.protected_action), unsafe_allow_html=True)
        reason = r.protected_reasons[0] if r.protected_reasons else \
            ("benign — allowed clean" if not r.is_attack else "—")
        cols[3].markdown(f'<span class="aegis-muted" style="font-size:0.76rem">'
                         f'{html.escape(reason)}</span>', unsafe_allow_html=True)
        st.markdown(f'<hr style="border-color:{BORDER};margin:5px 0">', unsafe_allow_html=True)


def view_metrics(mode: Mode) -> None:
    """V4 — Metrics & Eval Summary: the scored eval-harness output for the active posture."""
    st.subheader("Metrics & Eval Summary")
    st.markdown('<div class="aegis-banner"><b>Demo-grade.</b> These numbers describe this small, '
                'hand-authored deterministic suite — not a statistical bound on real-world '
                'performance. The leakage budget is a learned cumulative signal, not a formal '
                'information-flow bound.</div>', unsafe_allow_html=True)
    st.write("")
    m = data.run_view(mode).metrics

    c = st.columns(4)
    c[0].markdown(metric_card(str(m.total_cases), "CASES"), unsafe_allow_html=True)
    c[1].markdown(metric_card(str(m.false_block_count), "FALSE BLOCKS (benign)"),
                  unsafe_allow_html=True)
    target = "OK" if m.avg_latency_ms < 50 else "OVER"
    c[2].markdown(metric_card(f"{m.avg_latency_ms:.2f} ms", f"AVG LATENCY (<50ms {target})"),
                  unsafe_allow_html=True)
    c[3].markdown(metric_card(f"{m.evidence_completeness * 100:.0f}%", "EVIDENCE COMPLETE"),
                  unsafe_allow_html=True)
    st.write("")

    st.markdown("**Detection rate by category**")
    for cat, rate in m.detection_rate_by_category.items():
        is_benign = cat in {"benign_normal", "benign_secret_handle", "false_positive_benign_text"}
        color = data.ACTION_META["ALLOW"]["bg"] if is_benign else BLUE
        cols = st.columns([2, 4, 0.7])
        cols[0].markdown(f'<span class="aegis-mono" style="font-size:0.8rem">'
                         f'{html.escape(cat)}</span>', unsafe_allow_html=True)
        cols[1].markdown(risk_bar(rate, color), unsafe_allow_html=True)
        cols[2].markdown(f'{rate * 100:.0f}%')

    st.write("")
    left, right = st.columns(2)
    left.markdown("**Detector-hit distribution**")
    if m.detector_hit_distribution:
        peak = max(m.detector_hit_distribution.values())
        for det, n in sorted(m.detector_hit_distribution.items(), key=lambda x: -x[1]):
            cols = left.columns([2, 3, 0.6])
            cols[0].markdown(f'<span class="aegis-mono" style="font-size:0.78rem">'
                             f'{html.escape(det)}</span>', unsafe_allow_html=True)
            cols[1].markdown(risk_bar(n / peak if peak else 0), unsafe_allow_html=True)
            cols[2].markdown(str(n))
    right.markdown("**Trust metric**")
    right.markdown(f'<div class="aegis-card"><span class="aegis-muted">Warnings on this run</span>'
                   f'<div class="v" style="font-size:1.3rem">{m.warning_count}</div>'
                   f'<span class="aegis-muted">False blocks on benign traffic</span>'
                   f'<div class="v" style="font-size:1.3rem">{m.false_block_count}</div></div>',
                   unsafe_allow_html=True)


def view_policy(mode: Mode) -> None:
    """V5 — Policy & Detectors: read-only reference of rules, detectors, and registries."""
    st.subheader("Policy & Detectors")
    pv = data.load_policy_rules()
    st.markdown(f'Active mode: {badge(mode.name)}'
                f' &nbsp;<span class="aegis-muted">(policy file ships as '
                f'<span class="aegis-mono">{html.escape(pv.mode)}</span>; the header selector '
                f'overrides it live)</span>', unsafe_allow_html=True)
    st.write("")

    st.markdown("**Loaded rules** (independent; most-severe action wins)")
    for r in pv.rules:
        st.markdown(
            f'<div class="aegis-card"><span class="aegis-chip">{html.escape(r["type"])}</span> '
            f'<span class="aegis-mono">{html.escape(r["summary"])}</span> &rarr; '
            f'{badge(r["action"])}</div>', unsafe_allow_html=True)

    with st.expander("Raw policy YAML"):
        st.code(pv.raw_yaml, language="yaml")

    st.write("")
    left, right = st.columns(2)
    left.markdown("**Registered detectors**")
    for d in data.detector_roster():
        left.markdown(f'<div class="aegis-card"><span class="aegis-mono">{html.escape(d.name)}'
                      f'</span><br>{chips(d.phases)}</div>', unsafe_allow_html=True)

    reg = data.honeytoken_and_broker_registry()
    right.markdown("**Honeytoken registry** (provenance only — never the token value)")
    if reg.honeytokens:
        for h in reg.honeytokens:
            right.markdown(
                f'<div class="aegis-card"><span class="aegis-mono">{html.escape(h["canary_id"])}'
                f'</span><br><span class="aegis-muted" style="font-size:0.76rem">'
                f'{html.escape(h["service"])} · {html.escape(h["fmt"])} · '
                f'{html.escape(h["location"])}</span></div>', unsafe_allow_html=True)
    else:
        right.markdown('<span class="aegis-muted">No canaries planted.</span>',
                       unsafe_allow_html=True)

    right.markdown("**Credential broker handles** (opaque — never secret values)")
    if reg.broker_handles:
        for b in reg.broker_handles:
            right.markdown(f'<span class="aegis-chip">{html.escape(b["handle"])}</span>',
                           unsafe_allow_html=True)
    else:
        right.markdown('<span class="aegis-muted">No handles in play.</span>',
                       unsafe_allow_html=True)


# ---------------------------------------------------------------------------------------------
# Shell
# ---------------------------------------------------------------------------------------------
VIEWS = {
    "V1 · Live Decision Feed": view_feed,
    "V2 · Decision Detail": view_detail,
    "V3 · Baseline vs Protected": view_comparison,
    "V4 · Metrics & Eval Summary": view_metrics,
    "V5 · Policy & Detectors": view_policy,
}

MODE_OPTIONS = {
    "observe": Mode.OBSERVE,
    "balanced": Mode.BALANCED,
    "strict": Mode.STRICT,
}


def main() -> None:
    """Render the Aegis dashboard shell: header (title + mode selector) + nav rail + active view."""
    st.set_page_config(page_title="Aegis", page_icon="🛡", layout="wide")
    st.markdown(CSS, unsafe_allow_html=True)

    header = st.columns([3, 1])
    header[0].markdown(
        '<h2 style="margin-bottom:0">🛡 Aegis</h2>'
        '<span class="aegis-muted">Runtime credential-defense — read-only decision console</span>',
        unsafe_allow_html=True)
    mode_key = header[1].selectbox("Policy mode", list(MODE_OPTIONS), index=1, key="mode")
    mode = MODE_OPTIONS[mode_key]
    st.markdown(f'<hr style="border-color:{BORDER};margin:8px 0 16px 0">', unsafe_allow_html=True)

    with st.sidebar:
        st.markdown("### Views")
        names = list(VIEWS)
        default = st.session_state.get("nav", names[0])
        if default not in names:
            default = names[0]
        choice = st.radio("Navigate", names, index=names.index(default),
                          label_visibility="collapsed", key="nav")
        st.markdown(f'<hr style="border-color:{BORDER}">', unsafe_allow_html=True)
        st.markdown(f'<span class="aegis-muted" style="font-size:0.76rem">Active posture: '
                    f'<b>{data.MODE_LABELS[mode]}</b><br>Driving the SDK in-process — '
                    f'fully offline.</span>', unsafe_allow_html=True)

    VIEWS[choice](mode)


main()
