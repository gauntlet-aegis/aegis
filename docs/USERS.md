# Aegis Dashboard — User Personas

20 realistic users for black-box, browser-only acceptance testing of the Aegis dashboard
(`http://localhost:8765`). The dashboard is a **read-only observability surface** over the Aegis
SDK/eval: five views — Live Decision Feed, Decision Detail, Baseline vs Protected, Metrics & Eval
Summary, Policy & Detectors — plus an observe/balanced/strict policy-mode selector. There is no
login and no data entry; users navigate, read, switch mode, and drill into decisions.

Roster: ~10 expert/domain users (`smart-user`) and ~10 naive/careless users (`dumb-user`). Each has
one concrete goal tied to a view.

| # | Name | Agent | Tech | Device | Goal |
|---|------|-------|------|--------|------|
| 1 | Priya Nair — security engineer | smart-user | expert | desktop | Open the blocked `tool_call_arg_exfil` turn and confirm *why* it was blocked (detector evidence + reason). |
| 2 | Marcus Bell — AI platform owner | smart-user | high | desktop | Use Baseline vs Protected to decide whether to roll Aegis out — does it stop attacks without blocking benign traffic? |
| 3 | Lena Ortiz — red teamer | smart-user | expert | desktop | Confirm the encoded-leak and honeytoken attacks were caught (feed + detail). |
| 4 | Devon Clark — agent developer | smart-user | high | laptop | Read the detector-hit distribution and per-turn latency before integrating the SDK. |
| 5 | Aisha Khan — SOC analyst | smart-user | high | desktop | Switch to **strict** mode and verify actions get more conservative. |
| 6 | Tom Reilly — compliance officer | smart-user | medium | laptop | Verify every non-allow decision carries structured evidence (audit requirement). |
| 7 | Ravi Menon — ML engineer | smart-user | expert | desktop | Understand the NIMBUS cumulative-leakage signal and find the "not a formal bound" caveat. |
| 8 | Sofia Diaz — capstone evaluator | smart-user | high | laptop | Get the baseline-vs-protected headline story in under two minutes. |
| 9 | Ken Tanaka — SRE | smart-user | expert | desktop, keyboard-only | Confirm detector overhead is under the 50 ms/turn target. |
| 10 | Maria Lopez — policy admin | smart-user | high | desktop | Inspect the active YAML policy rules and the credential-broker handles in play. |
| 11 | "Grandpa" Joe — first-timer | dumb-user | low | old small laptop, impatient | Find out "is it safe?" — clicks around with no domain knowledge. |
| 12 | Bea Wallace — non-technical manager | dumb-user | low | phone (mobile) | Glance to see if "anything is red / bad". |
| 13 | Chad Rourke — careless power-clicker | dumb-user | medium | desktop | Flip the mode selector rapidly and double-click everything to see if it breaks. |
| 14 | Nina Park — colorblind analyst | dumb-user | medium | laptop | Tell ALLOW from BLOCK without relying on red/green color alone. |
| 15 | Owen Pratt — impatient, flaky wifi | dumb-user | low | laptop, slow conn | See the live feed; refreshes mid-load repeatedly. |
| 16 | Patty Shaw — expects a form | dumb-user | low | desktop | Looks for a "submit/run" button; confused by a read-only dashboard. |
| 17 | Liam (age 11) — random clicker | dumb-user | low | tablet | "Make the numbers change." |
| 18 | Rosa Méndez — ESL, jargon-averse | dumb-user | low | laptop | Understand what one feed row means despite terms like ESCALATE/honeytoken. |
| 19 | Hank Doyle — deep-link paster | dumb-user | medium | desktop | Paste a URL with a `?view=`/node-style anchor expecting to land on a specific decision. |
| 20 | Deb Frost — screen-reader user | dumb-user | medium | desktop + screen reader | Navigate the view nav and read a metric value non-visually. |

## Notes for testers
- Browser only — interact through the rendered Streamlit page; no API/CLI.
- The app is hermetic (SDK/eval run in-process); no real credentials, accounts, or network.
- Expert personas judge correctness and evidence completeness; naive personas judge clarity,
  discoverability, color/contrast/accessibility, and resilience to misuse (rapid clicks, refreshes).
