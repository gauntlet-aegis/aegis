# Aegis — Production Roadmap

Aegis (this repo) is a **demo-grade reference implementation** built from `docs/aegis-plan.pdf`. The
architecture is production-*shaped* — SDK-first, Inspect→Score→Enforce, credential broker, layered
detectors, explainable decisions, an eval loop — but it is explicitly not production-grade. This is
the path to closing that gap.

Phases are ordered by **risk**, not feature count: **P0** makes the system safe to run at all; **P1**
makes the detection trustworthy; **P2** scales it and broadens coverage.

## Where it stands today

- **Production-shaped:** the spine and the integration thesis (tool-call argument exfiltration +
  honeytokens + cumulative leakage + broker, behind one explainable, closed-API-compatible layer).
- **The gap is ~80% in two places:**
  1. **Detection efficacy** against an adaptive attacker on real traffic, with calibrated false-
     positive / false-negative rates. *(R&D / security risk — the hard part.)*
  2. **Standard hardening** of a stateful, secret-handling, high-availability security service.
     *(Well-understood engineering.)*
- Known, documented evasions/limits to retire: session-id rotation defeats the cumulative budget;
  bare credential with no cue/shape; cross-field split secrets; in-memory single-process state;
  Streamlit platform limits. (See `docs/EDGE_CASES.md` and `docs/USER_PERSONAS_FINDING.md`.)

---

## P0 — Safe to deploy (enforcement, state, identity, secrets)

Nothing below is optional before real traffic touches this.

- **Credential broker, for real.** Replace `FakeSecretStore` (env/JSON) with a real secret manager
  (HashiCorp Vault / AWS Secrets Manager / cloud KMS); add rotation and least-privilege. **Enforce**
  handle resolution at the tool-execution boundary instead of relying on the caller to invoke it, so
  raw secrets never enter model context *by construction* (taint enforcement / sandboxing), not by
  convention.
- **Durable, concurrency-safe shared state.** Move the leakage ledger, honeytoken registry, and
  conversation store out of process memory into Redis/DB with TTL + eviction; make workers stateless
  so the gateway scales horizontally. (The ledger currently shares a dict with no lock — fine
  single-threaded, unsafe otherwise.)
- **Host-bound sessions.** Bind `session_id` to the host's conversation identity so the cumulative
  leakage budget can't be reset by per-turn session rotation (a documented evasion).
- **Gateway hardening.** AuthN/AuthZ, TLS (and mTLS where applicable), rate limiting, per-tenant
  quotas, request-size caps and per-detector timeouts, provider retries/timeouts/circuit breakers,
  and **streaming** responses with incremental/partial-output scanning (today the gateway forces
  `stream:false`).
- **Secure the security tool (it sees everything).** Turn the JSONL trace sink into a proper
  **encrypted, access-controlled, retention-bounded audit log**; do a formal log-hygiene review on
  top of the existing redaction; careful secret-in-memory handling; pin dependencies + publish an
  SBOM; require authN on the dashboard (currently unauthenticated).
- **Wire the ESCALATE path.** Today ESCALATE is a label; route it to a real sink (SIEM / PagerDuty /
  ticketing) with incident runbooks and on-call. Multiple persona reviewers asked "escalate to whom?"

## P1 — Trustworthy detection (efficacy, calibration, assurance)

This is the genuine R&D/security risk and the work that justifies the product's claims.

- **Secret + encoding detection.** Add **live credential verification** (does the token actually
  authenticate?), broaden formats/encodings, and resolve the documented FP/FN tradeoffs (e.g. the
  bare-AWS-key-without-cue evasion) without re-introducing the SHA/nonce false positives.
- **Real cumulative leakage accounting.** Replace the fragment-counting heuristic with the research
  InfoNCE estimator (or genuine information-flow control), on top of host-bound sessions; calibrate
  the budget on real traffic. Only then can the "signal, not a bound" caveat be relaxed.
- **Tool-call scanner generality.** Ingest tool definitions from **MCP / OpenAPI** and do schema-
  aware validation for arbitrary tools (today only `send_email` / `http_request` / `query_database`
  are hardcoded); close the residual cross-field split-secret gap.
- **White-box CIFT + ML probe.** Implement activation probing for open-weight models (the research
  differentiator, currently a stub) and add the ML risk probe as a calibrated, still-non-blocking
  signal.
- **Calibration & drift.** Tune thresholds against real benign traffic for an acceptable false-block
  rate; monitor drift; support per-tenant / per-data-classification policy with **versioning, canary
  rollout, and change audit**.
- **Continuous assurance.** Adaptive red-teaming against AgentDojo / InjecAgent + real traffic;
  measured FP/FN at scale; **independent security review / penetration test** (the PRD flags this).
- **Observability.** OpenTelemetry tracing, latency **percentiles (p99**, not just the mean),
  alerting, health/readiness probes, and monitoring of the "detector degraded to stub" path.

## P2 — Scale & breadth

- **Multi-agent / inter-agent channels.** Research (AgentLeak) shows the majority of real leakage is
  inter-agent and invisible to output-only auditing — entirely out of current scope.
- **Streaming & modalities.** Partial-output scanning during generation; non-text modalities.
- **Production UI.** Replace the Streamlit replay console with a real web app (proper routing,
  WCAG accessibility, authN) consuming a **live event bus** instead of in-process eval replay.
- **Compliance / governance.** Tamper-evident audit trail, retention policy, RBAC, data residency,
  and SOC 2 / HIPAA / etc. as the deployment requires.

---

## Honest framing

P1 (detection efficacy + calibration + independent validation) is where the real uncertainty lives;
P0 and P2 are mostly known engineering. Until P1 lands, the claim discipline in the README holds: the
leakage ledger is a learned **signal**, not a formal information-flow bound, and deterministic
detectors — not the ML/white-box layers — remain authoritative.
