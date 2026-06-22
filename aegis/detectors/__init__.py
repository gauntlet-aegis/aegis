"""Detector layer — each detector inspects a normalized event and recommends an action.

All detectors implement the :class:`~aegis.detectors.base.Detector` protocol and return a
:class:`~aegis.detectors.base.DetectorResult`. The pipeline runs them (Inspect), the policy
engine maps their results to a final action under a mode (Score/Enforce). Deterministic
detectors are authoritative; the ML probe and CIFT adapter are non-blocking stubs.
"""
