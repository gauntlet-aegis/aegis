# User Personas — Findings & Remediation

App under test: the Aegis Streamlit dashboard (`http://localhost:8765`). Date: 2026-06-22.
Iterations: 2 browser passes + a remediation-verification restart. The roster in `docs/USERS.md`
has 20 personas; passes exercised a representative subset spanning all five views, the mode selector,
and accessibility/naive cases (the dashboard is a small read-only console — a focused subset gives
full surface coverage). Browser: Playwright/Chromium, headless.

## Persona 1 — Priya Nair, security engineer (smart-user)
Goal: open a blocked `tool_call_arg_exfil` decision and confirm *why* it was blocked. | Outcome: achieved.

### Finding 1.1 — V5 Policy & Detectors crashes in every mode  [blocker]
- **Pass:** 1. **Where:** V5, on load (observe/balanced/strict).
- **Expected vs actual:** a readable policy panel; instead `KeyError: 'BALANCED'` — `badge()` looked
  up the *mode* name in the *action* color map (`ACTION_META`), which has no mode keys.
- **Remediation:** render the active mode as a plain chip, not an action badge (`dashboard/app.py`
  `view_policy`). **Status:** fixed. **Verified:** Pass 2 — V5 rendered in all three modes, no crash.

### Finding 1.2 — "Detail" button throws StreamlitAPIException  [major]
- **Pass:** 1. **Where:** V1, each row's Detail button.
- **Expected vs actual:** silent nav to V2; instead a red `st.session_state.nav cannot be modified
  after the widget with key nav is instantiated` flashed before recovering.
- **Remediation:** stage the nav target in a non-widget key (`_goto`) and promote it to `nav`
  *before* the radio widget is created (`app.py`). **Status:** fixed. **Verified:** Pass 2 — Detail
  navigated cleanly, including on rapid double-click, no exception.

### Finding 1.3 — V2 scenario dropdown appears to omit `tool_call_arg_exfil`  [major → dropped]
- **Pass:** 1. **Investigation:** compared the dropdown source (`get_scenarios`) with the feed
  source — both are the *same* 27 scenarios incl. all four `tool_exfil_*`. The omission was a
  headless-screenshot selectbox-virtualization artifact, not a data bug. **Status:** dropped
  (false positive). **Verified:** `dashboard.data` id-set comparison (feed == dropdown).

### Finding 1.4 — Filter requires Enter with a subtle affordance  [minor]
- **Remediation:** added a placeholder ("e.g. tool_exfil — then press Enter") and help text.
  **Status:** fixed (improved). Pass 2 noted the inline hint is still low-contrast (Streamlit
  default) — accepted.

### Finding 1.5 — Material icon name "keyboard_arrow_right" shows as literal text  [minor → declined]
- The expander glyph rendered as its icon *name* in the headless screenshot (Material Symbols font
  not loaded in that context). Renders as an icon in a real browser with fonts. **Status:** declined
  — Streamlit-internal / headless-font artifact, not our markup.

### Finding 1.6 — V4 benign vs malicious bars same color  [nitpick → already handled]
- The code already colors benign categories green (ALLOW) vs blue for attack categories
  (`view_metrics`). **Status:** no change (pre-existing differentiation).

## Persona 2 — Maria Lopez, policy administrator (smart-user)
Goal: audit V5 policy/detectors across modes; verify the Pass-1 fixes. | Outcome: achieved.

Confirmed both Pass-1 fixes: **V5 rendered in all three modes with no crash**, and the **Detail
button navigated without an exception**. No tracebacks anywhere.

### Finding 2.1 — V5 rule cards don't show the mode's effective action  [bug/medium]
- **Pass:** 2. **Where:** V5, "Loaded rules". **Expected vs actual:** in observe mode the cards still
  showed `BLOCK`, with the override behavior buried in the collapsed YAML — an admin could think
  observe enforces blocks.
- **Remediation:** added a mode-effect banner ("In observe mode, every BLOCK/SANITIZE/ESCALATE is
  downgraded to WARN…") and per-rule effective-action annotation via `apply_mode` (`app.py`).
  **Status:** fixed. **Verified:** restart render + logic check.

### Finding 2.2 — Honeytoken canary ids regenerate on every reload  [papercut]
- **Remediation:** cached `honeytoken_and_broker_registry` so ids are stable across reloads
  (`dashboard/data.py`). **Status:** fixed. **Verified:** ids identical across two calls.

### Finding 2.3 — V2 direct nav silently auto-selects the first scenario  [papercut]
- **Remediation:** added a caption telling the user to use the dropdown or a feed "Detail" button.
  **Status:** fixed.

### Finding 2.4 — V4 "EVIDENCE COMPLETE" label / V5 phase chips lack a header  [nitpick]
- **Status:** declined (cosmetic; labels are legible in context). Noted for a future polish pass.

## Summary
- **Fixed:** 2 blockers/majors (V5 crash, Detail exception) + 1 medium (V5 mode-effect clarity) +
  2 papercuts (stable canary ids, V2 selection hint) + filter affordance.
- **Dropped:** 1 false positive (V2 dropdown — proven complete).
- **Declined:** headless icon-font artifact; two cosmetic nitpicks.
- **Result:** no remaining blockers or majors; the two original blockers/majors are verified fixed.
  Dashboard data-layer tests (11) green, ruff clean, app boots HTTP 200 after every change.
