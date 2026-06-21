"""M7 NIMBUS eval deliverables: budget-sensitivity sweep + honest short-session failure curve.

Replays the 50-conversation synthetic suite (``detect/nimbus/suite.build_suite``) through the
same per-turn InfoNCE estimator the live ``NimbusStage`` uses, accumulates cumulative leakage bits
per conversation, then:

  1. **Budget sweep (paper Fig. 5)** — vary the budget B and report detection rate (drips blocked),
     false-block rate (benign blocked), and mean turn-at-block. Marks the deployed B.
  2. **Short-session failure curve** — detection rate vs. session length at the deployed B. Names
     the regime where NIMBUS is structurally blind (short 2-3 turn drips can't accumulate past the
     per-turn ceiling log2(N+1) before the conversation ends). Reported honestly, not hidden.
  3. **Per-turn trace** — i_turn / i_cum for a representative drip conversation, with the
     warn/sanitize/block gridlines, naming the crossing turn (matches the dashboard meter).

Run (NIMBUS needs no torch / no model):

    .venv/bin/python scripts/eval_nimbus.py
    .venv/bin/python scripts/eval_nimbus.py --out data/eval/nimbus --budget 4.66

Figures (PNG) + the underlying numbers (results.json) land under ``--out``.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # headless: render straight to PNG, no display needed
import matplotlib.pyplot as plt
import numpy as np

from sentinel.config import load_settings
from sentinel.detect.nimbus.critic import LeakageCritic
from sentinel.detect.nimbus.encoder import CharNGramEncoder
from sentinel.detect.nimbus.estimator import NimbusEstimator
from sentinel.detect.nimbus.suite import build_suite
from sentinel.eval.metrics import rate
from sentinel.stages.nimbus_stage import BLOCK_RATIO, SANITIZE_RATIO, WARN_RATIO

# These match NimbusStage's accumulation + threshold logic exactly; the stage blocks at ratio>=1.0
# (i_cum >= B), so "detection" == the cumulative budget crossing B by the end of the conversation.


def build_estimator(settings) -> tuple[NimbusEstimator, dict]:
    """Assemble the estimator the way the live proxy does (bootstrap.build_detectors).

    Prefers the trained artifacts (critic + negative bank + calibrated temperature) when present;
    otherwise rebuilds deterministically from the suite exactly like scripts/train_nimbus.py, so the
    eval reproduces on a fresh clone with no ``data/`` artifacts.
    """
    dim = settings.nimbus.encoder_dim
    enc = CharNGramEncoder(dim=dim)
    temperature = settings.nimbus.temperature
    source = "trained-artifacts"

    critic = LeakageCritic.load(settings.nimbus.critic_path)
    bank_path = Path(settings.nimbus.neg_bank_path)
    meta_path = Path(settings.nimbus.meta_path)
    if critic is not None and bank_path.exists():
        neg_bank = np.load(bank_path)
        if meta_path.exists():
            temperature = json.loads(meta_path.read_text()).get("temperature", temperature)
    else:
        # Rebuild from the suite (cosine critic, benign-output negative bank).
        convs = build_suite(50, seed=0)
        neg_bank = np.stack(
            [enc.encode(t) for c in convs if c["label"] == "benign" for t in c["turns"]]
        )
        critic = LeakageCritic(dim)
        source = "rebuilt-from-suite"

    est = NimbusEstimator(
        enc, critic, neg_bank, n_neg=settings.nimbus.n_neg, temperature=temperature
    )
    info = {
        "encoder_dim": dim,
        "temperature": temperature,
        "n_neg": est.n_neg,
        "ceiling_bits": est.ceiling_bits(),
        "neg_bank_size": int(len(neg_bank)),
        "estimator_source": source,
    }
    return est, info


def replay(est: NimbusEstimator, convs: list[dict]) -> list[dict]:
    """Per-conversation per-turn i_turn and i_cum, using one estimator in suite order (as deployed)."""
    out = []
    for c in convs:
        i_turn = [
            est.infonce_bits(c["secret"], c["conversation_id"], t) for t in c["turns"]
        ]
        i_cum = np.cumsum(i_turn).tolist()
        out.append(
            {
                "conversation_id": c["conversation_id"],
                "label": c["label"],
                "length": len(c["turns"]),
                "drip_rate": c["drip_rate"],
                "i_turn": i_turn,
                "i_cum": i_cum,
                "final_cum": i_cum[-1] if i_cum else 0.0,
            }
        )
    return out


def turn_at_block(i_cum: list[float], budget: float) -> int | None:
    """1-based index of the first turn whose cumulative bits reach the budget; None if never."""
    for t, cum in enumerate(i_cum, start=1):
        if cum >= budget:
            return t
    return None


def sweep_budget(replays: list[dict], budgets: np.ndarray) -> dict:
    drips = [r for r in replays if r["label"] == "drip"]
    longs = [r for r in drips if r["length"] > 3]
    benigns = [r for r in replays if r["label"] == "benign"]

    det_all, det_long, false_block, mean_tab = [], [], [], []
    for b in budgets:
        det_all.append(rate(r["final_cum"] >= b for r in drips))
        det_long.append(rate(r["final_cum"] >= b for r in longs))
        false_block.append(rate(r["final_cum"] >= b for r in benigns))
        tabs = [turn_at_block(r["i_cum"], b) for r in drips]
        tabs = [t for t in tabs if t is not None]
        mean_tab.append(float(np.mean(tabs)) if tabs else float("nan"))

    return {
        "budgets": budgets.tolist(),
        "detection_all": det_all,
        "detection_long": det_long,
        "false_block": false_block,
        "mean_turn_at_block": mean_tab,
        "n_drip": len(drips),
        "n_drip_long": len(longs),
        "n_benign": len(benigns),
    }


def short_session_curve(replays: list[dict], budget: float) -> dict:
    """Detection rate vs. session length at the deployed budget — the structural blind spot.

    Also reports detection by drip rate, because the blind spot is really about *total accumulated
    signal* (turns x fragment size): a few long but low-rate (tiny-fragment) drips under-accumulate
    just like short ones do. We surface both so the figure doesn't misattribute the cause to length.
    """
    drips = [r for r in replays if r["label"] == "drip"]
    by_len: dict[int, list[bool]] = {}
    by_rate: dict[int, list[bool]] = {}
    for r in drips:
        by_len.setdefault(r["length"], []).append(r["final_cum"] >= budget)
        by_rate.setdefault(r["drip_rate"], []).append(r["final_cum"] >= budget)
    lengths = sorted(by_len)
    rates = sorted(by_rate)
    return {
        "lengths": lengths,
        "detection_rate": [rate(by_len[length]) for length in lengths],
        "n_per_length": [len(by_len[length]) for length in lengths],
        "drip_rates": rates,
        "detection_by_rate": [rate(by_rate[dr]) for dr in rates],
        "n_per_rate": [len(by_rate[dr]) for dr in rates],
        # Per-conversation (length, cumulative, detected) for the honest scatter.
        "points": [
            {"length": r["length"], "final_cum": r["final_cum"], "drip_rate": r["drip_rate"],
             "detected": bool(r["final_cum"] >= budget)}
            for r in drips
        ],
    }


def pick_demo(replays: list[dict], budget: float) -> dict:
    """A drip that blocks *mid-conversation* — the strong story (NIMBUS halts the drip with turns
    still to come, before the secret finishes leaking), with a visible PASS->WARN->BLOCK climb."""
    crossing = [
        (r, turn_at_block(r["i_cum"], budget))
        for r in replays
        if r["label"] == "drip" and turn_at_block(r["i_cum"], budget) is not None
    ]
    if not crossing:  # degenerate calibration: fall back to the highest-accumulating drip
        drips = [r for r in replays if r["label"] == "drip"]
        return max(drips, key=lambda r: r["final_cum"])
    # Prefer: a visible climb before the block (tab >= 3), then the most turns left after blocking
    # (caught earliest relative to the end), then the longer conversation.
    crossing.sort(key=lambda rt: (rt[1] >= 3, rt[0]["length"] - rt[1], rt[0]["length"]), reverse=True)
    return crossing[0][0]


# ---- figures ---------------------------------------------------------------------------------

def fig_budget_sweep(sweep: dict, budget: float, path: Path) -> None:
    b = sweep["budgets"]
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(b, sweep["detection_all"], color="#1b7837", lw=2, label="detection (all drips)")
    ax.plot(b, sweep["detection_long"], color="#1b7837", lw=2, ls="--",
            label="detection (long drips, >3 turns)")
    ax.plot(b, sweep["false_block"], color="#b2182b", lw=2, label="false-block (benign)")
    ax.set_xlabel("budget B (bits)")
    ax.set_ylabel("rate")
    ax.set_ylim(-0.03, 1.03)
    ax.axvline(budget, color="#333", ls=":", lw=1.5)
    ax.text(budget, 1.0, f"  deployed B={budget:g}", color="#333", va="top", fontsize=9)

    ax2 = ax.twinx()
    ax2.plot(b, sweep["mean_turn_at_block"], color="#2166ac", lw=1.5, alpha=0.7,
             label="mean turn-at-block")
    ax2.set_ylabel("mean turn-at-block", color="#2166ac")
    ax2.tick_params(axis="y", labelcolor="#2166ac")

    # Only the real data series — exclude matplotlib's auto-labeled artists (e.g. the axvline).
    lines = [ln for ln in ax.get_lines() + ax2.get_lines() if not ln.get_label().startswith("_")]
    ax.legend(lines, [ln.get_label() for ln in lines], loc="lower center", fontsize=9,
              framealpha=0.9)
    ax.set_title("NIMBUS budget sensitivity (Fig. 5): detection / false-block / turn-at-block vs B")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def fig_short_session(curve: dict, budget: float, ceiling: float, path: Path) -> None:
    """Two honest views: detection-rate-vs-length (the asked curve) + a (length, cum) scatter that
    reveals the real cause (total accumulated signal vs B), so long low-rate misses aren't hidden."""
    fig, (axL, axR) = plt.subplots(1, 2, figsize=(13, 5))

    # Left: detection rate vs session length (the requested curve).
    lengths = curve["lengths"]
    rates = curve["detection_rate"]
    colors = ["#b2182b" if length <= 3 else "#4393c3" for length in lengths]
    axL.bar([str(length) for length in lengths], rates, color=colors)
    for x, (r, nval) in enumerate(zip(rates, curve["n_per_length"])):
        axL.text(x, r + 0.02, f"{r:.0%}\nn={nval}", ha="center", va="bottom", fontsize=7)
    axL.set_xlabel("session length (turns)")
    axL.set_ylabel(f"detection rate @ B={budget:g}")
    axL.set_ylim(0, 1.15)
    axL.set_title(f"Detection vs. session length (red = short ≤3-turn drips)\n"
                  f"per-turn ceiling = log2(N+1) = {ceiling:.2f} bits")

    # Right: per-conversation (length, cumulative bits), colored by detected, with the budget line.
    pts = curve["points"]
    det = [p for p in pts if p["detected"]]
    miss = [p for p in pts if not p["detected"]]
    axR.scatter([p["length"] for p in det], [p["final_cum"] for p in det],
                c="#1b7837", s=40, label="detected", zorder=3)
    axR.scatter([p["length"] for p in miss], [p["final_cum"] for p in miss],
                c="#b2182b", marker="x", s=55, label="missed", zorder=3)
    axR.axhline(budget, color="#333", ls=":", lw=1.5)
    axR.text(axR.get_xlim()[1], budget, f" B={budget:g}", color="#333", va="bottom", ha="right",
             fontsize=9)
    axR.axvspan(0, 3.5, color="#b2182b", alpha=0.07)
    axR.set_xlabel("session length (turns)")
    axR.set_ylabel("cumulative leakage (bits)")
    axR.set_title("Why misses happen: short OR low-rate drips under-accumulate")
    axR.legend(loc="upper right", fontsize=9)

    fig.suptitle("NIMBUS short-session failure (reported honestly)", fontsize=13)
    fig.tight_layout(rect=(0, 0, 1, 0.96))
    fig.savefig(path, dpi=150)
    plt.close(fig)


def fig_trace(demo: dict, budget: float, path: Path) -> None:
    turns = np.arange(1, demo["length"] + 1)
    i_turn = demo["i_turn"]
    i_cum = demo["i_cum"]
    tab = turn_at_block(i_cum, budget)

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.bar(turns, i_turn, color="#bdbdbd", label="i_turn (per-turn bits)")
    ax.plot(turns, i_cum, color="#2166ac", marker="o", lw=2, label="i_cum (cumulative bits)")
    for ratio, name, color in [
        (WARN_RATIO, "warn", "#fdae61"),
        (SANITIZE_RATIO, "sanitize", "#f46d43"),
        (BLOCK_RATIO, "block", "#b2182b"),
    ]:
        y = ratio * budget
        ax.axhline(y, color=color, ls="--", lw=1.2)
        ax.text(turns[-1], y, f" {name} ({ratio:g}B)", color=color, va="bottom", ha="right",
                fontsize=8)
    if tab is not None:
        ax.axvline(tab, color="#b2182b", ls=":", lw=1.5)
        ax.text(tab, max(i_cum) * 0.5, f"blocks at turn {tab}", color="#b2182b", rotation=90,
                va="center", ha="right", fontsize=9)
    ax.set_xlabel("turn")
    ax.set_ylabel("bits")
    ax.set_xticks(turns)
    ax.legend(loc="upper left", fontsize=9)
    ax.set_title(f"NIMBUS per-turn trace — {demo['conversation_id']} "
                 f"(drip rate {demo['drip_rate']}, B={budget:g})")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def main() -> None:
    ap = argparse.ArgumentParser(description="NIMBUS M7 eval: budget sweep + short-session curve.")
    ap.add_argument("--out", default="data/eval/nimbus", help="output directory for figures + JSON")
    ap.add_argument("--n", type=int, default=50, help="suite size")
    ap.add_argument("--seed", type=int, default=0, help="suite seed")
    ap.add_argument("--budget", type=float, default=None,
                    help="override deployed budget B (default: configs/default.yaml)")
    ap.add_argument("--sweep-points", type=int, default=60)
    args = ap.parse_args()

    settings = load_settings()
    budget = args.budget if args.budget is not None else settings.nimbus.budget_bits
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    est, info = build_estimator(settings)
    convs = build_suite(args.n, seed=args.seed)
    replays = replay(est, convs)

    max_cum = max((r["final_cum"] for r in replays), default=1.0)
    budgets = np.linspace(0.1, max(max_cum * 1.05, budget * 1.2), args.sweep_points)
    sweep = sweep_budget(replays, budgets)
    curve = short_session_curve(replays, budget)
    demo = pick_demo(replays, budget)

    fig_budget_sweep(sweep, budget, out / "fig5_budget_sweep.png")
    fig_short_session(curve, budget, info["ceiling_bits"], out / "fig_short_session.png")
    fig_trace(demo, budget, out / "fig_trace.png")

    # Operating point at the deployed budget.
    drips = [r for r in replays if r["label"] == "drip"]
    longs = [r for r in drips if r["length"] > 3]
    shorts = [r for r in drips if r["length"] <= 3]
    benigns = [r for r in replays if r["label"] == "benign"]
    tabs = [turn_at_block(r["i_cum"], budget) for r in drips]
    tabs = [t for t in tabs if t is not None]
    operating_point = {
        "budget_bits": budget,
        "detection_all": rate(r["final_cum"] >= budget for r in drips),
        "detection_long": rate(r["final_cum"] >= budget for r in longs),
        "detection_short": rate(r["final_cum"] >= budget for r in shorts),
        "false_block": rate(r["final_cum"] >= budget for r in benigns),
        "mean_turn_at_block": float(np.mean(tabs)) if tabs else None,
        "benign_max_cum": max((r["final_cum"] for r in benigns), default=0.0),
        "drip_median_cum": float(np.median([r["final_cum"] for r in drips])) if drips else 0.0,
        "demo_conversation": demo["conversation_id"],
        "demo_blocks_at_turn": turn_at_block(demo["i_cum"], budget),
    }

    results = {
        "config": info,
        "suite": {"n": args.n, "seed": args.seed, "n_drip": len(drips),
                  "n_drip_long": len(longs), "n_drip_short": len(shorts), "n_benign": len(benigns)},
        "operating_point": operating_point,
        "budget_sweep": sweep,
        "short_session_curve": curve,
        "demo_trace": {k: demo[k] for k in
                       ("conversation_id", "label", "length", "drip_rate", "i_turn", "i_cum")},
    }
    (out / "results.json").write_text(json.dumps(results, indent=2))

    # Console summary.
    op = operating_point
    print(f"estimator: {info['estimator_source']}  dim={info['encoder_dim']}  "
          f"temp={info['temperature']}  n_neg={info['n_neg']}  ceiling={info['ceiling_bits']:.2f} bits")
    print(f"suite: {results['suite']}")
    print(f"\n-- operating point @ B={budget:g} --")
    print(f"  detection  all={op['detection_all']:.0%}  long={op['detection_long']:.0%}  "
          f"short={op['detection_short']:.0%}")
    print(f"  false-block(benign)={op['false_block']:.0%}   "
          f"mean turn-at-block={op['mean_turn_at_block']}")
    print(f"  benign max cum={op['benign_max_cum']:.2f}  drip median cum={op['drip_median_cum']:.2f}")
    print(f"  demo {op['demo_conversation']} blocks at turn {op['demo_blocks_at_turn']}")
    print(f"\n-- short-session curve (detection @ B={budget:g}) --")
    for length, r, nval in zip(curve["lengths"], curve["detection_rate"], curve["n_per_length"]):
        print(f"  length {length:>2}: {r:.0%}  (n={nval})")
    print("-- by drip rate (chars/turn; smaller fragment = weaker per-turn signal) --")
    for dr, r, nval in zip(curve["drip_rates"], curve["detection_by_rate"], curve["n_per_rate"]):
        print(f"  rate {dr}: {r:.0%}  (n={nval})")
    print(f"\nwrote figures + results.json -> {out}/")


if __name__ == "__main__":
    main()
