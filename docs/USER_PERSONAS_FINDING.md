# User Personas — Findings & Remediation

App under test: the Aegis Streamlit dashboard (`http://localhost:8765`). Date: 2026-06-22.
Iterations: 2 early passes (Priya, Maria) + the full 20-persona roster run in 3 batches + a
remediation-verification pass. Browser: Playwright/Chromium. The dashboard is a read-only,
stateless, in-process console; batches were run in parallel (no shared-DB collision risk).

Target & scope: a **desktop, single-user, local demo console**. Findings rooted in Streamlit's
platform behavior (SPA single-URL, hydration, mobile reflow, internal widget a11y) are documented
as accepted limitations rather than fixed.

## Consolidated remediations (one pass, verified)

| Fix | Finding(s) | Personas | Status |
|---|---|---|---|
| **Detail button now loads the correct scenario** (set the V2 selectbox's own widget key, not just a staged key) | wrong/first scenario on drill-in | Lena, Patty, Hank | ✅ fixed, browser-verified 3/3 |
| **Plain-language legend + glossary** on V1 (actions, detectors, "turn", *exfil*/*conf*) + header clarified as **view-only, nothing to submit** | can't tell good/bad; pervasive jargon; expected a form | Joe, Patty, Bea, Rosa | ✅ fixed |
| **V3 intervention rows visibly tinted + "🛡 Aegis stopped this" tag**, attack rows sorted first, benign divider | promised highlight invisible; story buried under benign rows | Nina, Sofia, Bea | ✅ fixed |
| **V4 color legend** (green = benign allowed, blue = attack detected); section retitled "Outcome rate" | "100%" on benign categories misleads | Sofia, Marcus, Devon | ✅ fixed |
| **Malicious-detector evidence expanded by default**; `conf`→`conf.` + column caption; **rounded evidence floats** | canary id hidden in collapsed row; `conf` unexplained; `0.4499…` noise | Lena, Rosa, Ravi | ✅ fixed |
| **Stable trace_ids** (cached `decision_detail`) | trace_id churned every reload | Lena, Rosa | ✅ fixed |
| **Heading anchors removed** (`anchor=False`) | wrong V4 heading link + phantom keyboard tab-stops | Deb, Ken | ✅ fixed |
| Detail-button per-row tooltip; risk-bar `aria-label`; ESCALATE "already maximal" note; mode-selector caption | a11y / clarity nits | Deb, Aisha, Liam | ✅ fixed |

After remediation: **no blockers or majors remain that are in our control.** Ruff clean, 11
data-layer tests green, boots HTTP 200, Detail routing verified correct across row types.

## Declined / documented (Streamlit-platform limitations — out of scope for a local demo)

- **Browser Back → blank page; second tab → black screen; skeleton-on-reload; partial render under
  rapid reload** (Owen) — Streamlit SPA hydration / single-URL / websocket-per-session behavior.
- **No URL deep-linking / bookmarking** (Hank, rated blocker) — Streamlit doesn't sync app state to
  the URL by default. A future enhancement could use `st.query_params`; out of scope here.
- **Mobile/tablet reflow** (Bea, Liam) — V3 table collapses, sidebar overlays content, narrow
  Detail-button wraps. Target is desktop.
- **Sidebar-collapse button unlabeled; no landmark regions; dropdown arrow-keys don't move highlight;
  focus ring low-contrast** (Deb, Ken) — Streamlit-internal chrome we don't author.
- **V2 selectbox shows ~10 before scroll** (Priya, Tom) — Streamlit selectbox is scrollable; the
  Detail button is the primary path. The text filter not matching natural language (Patty/Chad) is
  expected substring behavior; placeholder/help already added.

## Per-persona log

**Smart-user (experts):**
- **Priya (security eng)** — goal achieved. Found the V5 crash + Detail exception (early pass) → both
  fixed and re-verified. Evidence chain praised.
- **Maria (policy admin)** — achieved. Confirmed the two early fixes; flagged V5 mode-effect clarity
  → fixed (banner + per-rule effective action).
- **Marcus (platform owner)** — achieved: attacks blocked, 0 false blocks. Nit: V4 benign "100%"
  framing → legend added.
- **Devon (agent dev)** — achieved: detector distribution + 7.5 ms latency under 50 ms target. Nit:
  bar legend → added. (Latency p99 view = noted future nicety.)
- **Aisha (SOC)** — achieved: confirmed strict > balanced > observe. Flagged canary ESCALATE
  unchanged in strict → clarified ("already maximal").
- **Tom (compliance)** — PASS: every non-allow decision carried trace_id + detectors + reason.
  Dropdown-scroll papercut documented (platform).
- **Ravi (ML eng)** — confirmed NIMBUS isn't overclaiming; caveat present. Float-noise + field
  labels → rounded + glossary.
- **Lena (red teamer)** — receipts confirmed (decoded payloads + 3 canary ids). Honeytoken evidence
  collapsed-by-default → now expanded; intermittent wrong-scenario Detail → fixed.
- **Sofia (evaluator)** — got the headline, but benign rows sorted first + invisible highlight →
  attacks-first + visible tint/tag.
- **Ken (SRE, keyboard)** — latency confirmed. Keyboard a11y (invisible focus, non-navigable
  dropdowns, phantom tab-stops) — phantom anchors removed; rest are Streamlit-internal (documented).

**Dumb-user (naive/careless):**
- **Joe (first-timer)** — blocked on understanding "is it safe?"; BLOCK read as error; jargon →
  legend + read-only clarification.
- **Bea (mobile)** — formed a vague "probably fine"; mobile layout breaks → documented (desktop
  target); verdict clarity → legend.
- **Chad (power-clicker)** — **could not break it** (zero tracebacks under abuse). Detail "teleports"
  to V2 + filter affordance → legend + tooltip already added.
- **Nina (colorblind)** — not blocked (badge text is the signal). Promised V3 highlight absent →
  fixed with a visible tint + text tag (colorblind-safe).
- **Owen (refresh/flaky)** — Streamlit hydration artifacts (blank Back, black 2nd tab, skeleton) →
  documented as platform limitations.
- **Patty (expects a form)** — confused by read-only; hunted for Submit → header now says
  "view-only … nothing to submit". Detail-wrong-scenario → fixed.
- **Liam (kid, tablet)** — had fun; tablet layout nits (button wrap, sidebar overlay) → documented.
  Found nothing that crashed.
- **Rosa (ESL)** — eventually understood via the inbound/refusal panel; heavy jargon (nimbus,
  leakage ratio, conf, exfil, turns) → legend/glossary + spelled-out columns + rounded numbers.
- **Hank (deep-link)** — could not bookmark/share a view (URL never changes) → documented (Streamlit
  limitation; possible future `st.query_params`).
- **Deb (screen-reader)** — nav reachable + metric readable, but missing landmarks / unlabeled
  collapse button / identical Detail labels / bars without aria — wrong heading anchor removed,
  Detail tooltips + bar aria-labels added; remaining items are Streamlit chrome (documented).

## Summary
- **Fixed (in our control):** the Detail-routing bug + ~10 UX/clarity/a11y issues, all verified.
- **Hardened earlier:** V5 crash + Detail exception (initial passes).
- **Documented as platform limitations:** Streamlit SPA/URL/hydration, mobile reflow, internal
  widget a11y — appropriate for a desktop local demo console.
- **Result:** stable under abuse (Chad), correct drill-in (verified), legible to naive users
  (legend), honest metrics, no remaining in-scope blockers/majors.
