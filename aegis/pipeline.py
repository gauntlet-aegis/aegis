"""The Inspect -> Score -> Enforce pipeline (PDF section 4.4).

This is the heart of the SDK. Given a normalized :class:`~aegis.events.AegisEvent`:

1. **Inspect** — run every detector whose ``phases`` include the event's phase; collect
   :class:`~aegis.detectors.base.DetectorResult`s. Plus a broker guard: if a *raw* secret from
   the store appears in model-visible content, that is an independent, forced finding.
2. **Score / Enforce** — hand the detector results to the policy engine, which maps them to a
   final :class:`~aegis.decision.Action` under the active mode. The most severe action wins;
   scores are never numerically fused.
3. Build the :class:`~aegis.decision.AegisDecision`, computing a least-disclosure sanitized
   payload when the action is SANITIZE, and append the event + decision to the trace sink.

The pipeline keeps orchestration deterministic; only the detectors carry detection logic.
"""

from __future__ import annotations

from aegis.decision import Action, AegisDecision, Phase, Verdict, most_severe
from aegis.detectors.base import Detector, DetectorResult
from aegis.events import AegisEvent
from aegis.obs.trace import TraceSink, redact


class Pipeline:
    def __init__(self, detectors: list[Detector], policy_engine, *, broker=None,
                 trace_sink: TraceSink | None = None, local_test_mode: bool = False) -> None:
        self.detectors = detectors
        self.policy = policy_engine
        self.broker = broker
        self.trace = trace_sink
        self.local_test_mode = local_test_mode

    def run(self, event: AegisEvent) -> AegisDecision:
        # 1. Inspect — only detectors that apply to this phase.
        results: list[DetectorResult] = []
        for det in self.detectors:
            if event.phase in det.phases:
                try:
                    results.append(det.run(event))
                except Exception as exc:  # a detector must never take down the pipeline
                    results.append(DetectorResult(detector_name=getattr(det, "name", "unknown"),
                                                  score=0.0, verdict=Verdict.SKIPPED,
                                                  evidence={"error": str(exc)}))

        # Broker guard: a raw store secret reaching ANY boundary forces a non-allow decision.
        # This includes TOOL_CALL — an opaque store secret (no credential *shape*) smuggled into a
        # tool argument is exactly the marquee exfiltration path, so it must be scanned here too.
        broker_action = Action.ALLOW
        broker_reason: list[str] = []
        broker_finding = None
        if self.broker is not None and event.phase in (Phase.REQUEST, Phase.RESPONSE, Phase.TOOL_CALL):
            broker_finding = self.broker.scan_model_visible(event.inspectable_text())
            if broker_finding is not None and getattr(broker_finding, "leaked", False):
                broker_action = broker_finding.forced_action
                broker_reason.append(broker_finding.message)

        # 2. Score / Enforce.
        outcome = self.policy.decide(results)
        action = most_severe([outcome.action, broker_action])
        reasons = list(outcome.reasons) + broker_reason
        risk = max((r.score for r in results), default=0.0)

        # 3. Build the decision (+ least-disclosure sanitize).
        sanitized = None
        if action is Action.SANITIZE:
            sanitized = self._sanitize(event)

        event.detector_evidence = results
        event.policy_decision = {"action": action.name, "reasons": reasons}
        event.input_summary = redact(event.inspectable_text(), known_secrets=self._known_secrets())

        decision = AegisDecision(action=action, risk_score=risk, reasons=reasons,
                                 detector_hits=results, sanitized_payload=sanitized,
                                 trace_id=event.trace_id, event_id=event.event_id)
        if self.trace is not None:
            self.trace.write(event)
        return decision

    def _known_secrets(self) -> list[str]:
        store = getattr(self.broker, "store", None)
        if store is not None and hasattr(store, "all_values"):
            try:
                return list(store.all_values())
            except Exception:
                return []
        return []

    def _sanitize(self, event: AegisEvent) -> str | dict:
        """OCELOT-style least disclosure: redact the offending credential spans, keep the rest."""
        known = self._known_secrets()
        if event.phase is Phase.RESPONSE:
            return redact(event.output_text or "", known_secrets=known)
        if event.phase is Phase.TOOL_CALL and event.tool_arguments is not None:
            return _redact_args(event.tool_arguments, known)
        if event.messages:
            return redact(event.inspectable_text(), known_secrets=known)
        return redact(event.inspectable_text(), known_secrets=known)


def _redact_args(args: dict, known: list[str]) -> dict:
    out = {}
    for k, v in args.items():
        if isinstance(v, str):
            out[k] = redact(v, known_secrets=known)
        elif isinstance(v, dict):
            out[k] = _redact_args(v, known)
        else:
            out[k] = v
    return out
