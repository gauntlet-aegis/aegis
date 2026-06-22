"""Aegis dashboard — a read-only observability surface over the Aegis SDK (PDF FR-11).

The dashboard never makes a security decision; it renders the decisions the SDK/eval harness
produce. :mod:`dashboard.data` is the pure (Streamlit-free, unit-testable) data layer that drives
``aegis.eval.run_suite`` and the SDK in-process; :mod:`dashboard.app` is the thin Streamlit UI on
top of it.
"""
