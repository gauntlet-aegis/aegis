"""Drive a campaign through a running proxy and print per-turn outcomes.

Start the proxy first (scripts/run_proxy.py), open http://127.0.0.1:8000/ to watch live, then:
  .venv/bin/python scripts/run_demo.py --campaign encoding
"""

from __future__ import annotations

import argparse

from rich.console import Console
from rich.table import Table

from sentinel.redteam.agent import (
    ScriptedAgent,
    benign_campaign,
    drip_campaign,
    encoding_campaign,
)

CAMPAIGNS = {
    "benign": benign_campaign,
    "encoding": encoding_campaign,
    "drip": drip_campaign,
}

# The real credential the agent "holds" — flows through the tool runtime, never to the model.
REAL_SECRET = "sk-REAL-d0n0tle4k-9f3a8c2b1e7d6f5a4c3b2a19"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign", choices=list(CAMPAIGNS), default="encoding")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()

    campaign = CAMPAIGNS[args.campaign]()
    agent = ScriptedAgent(args.base_url)
    results = agent.run(campaign, real_secret=REAL_SECRET)

    console = Console()
    table = Table(title=f"Campaign: {campaign.name}")
    table.add_column("turn")
    table.add_column("attack")
    table.add_column("action")
    table.add_column("caught_by")
    table.add_column("landed")
    table.add_column("expected")

    for i, r in enumerate(results):
        x = r["x_sentinel"]
        expected = campaign.expected.get(i, "")
        ok = (not expected) or x["caught_by"] == expected
        table.add_row(
            str(i),
            campaign.turns[i].attack_label or "-",
            str(x["action"]),
            str(x["caught_by"]),
            "✗LANDED" if x["landed"] else "caught/ok",
            f"{expected} {'✓' if ok else '✗'}".strip(),
        )
    console.print(table)


if __name__ == "__main__":
    main()
