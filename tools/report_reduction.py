"""Report the cancellation-lattice reduction result in readable form."""

from __future__ import annotations

import json
import sys


def main(path: str) -> None:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)

    print("PROFILE")
    for key, value in data["profile"].items():
        print(f"  {key}: {value}")

    print()
    print("VALIDATION (must all pass or the norms are meaningless)")
    for key, value in data["validation"].items():
        print(f"  {key}: {value}")

    print()
    print("SHORTEST CANCELLATION BY REDUCTION STAGE")
    header = f"  {'stage':10s} {'inf':>5s} {'l2':>9s} {'d_block':>8s}"
    print(header)
    for stage, found in data["stages"].items():
        print(
            f"  {stage:10s} {found['infinity_norm']:5d} "
            f"{found['l2_norm']:9.2f} {found['second_block_max']:8d}"
        )

    verdict = data["verdict"]
    print()
    print("VERDICT")
    print(f"  shortest inf-norm    : {verdict['shortest_infinity_norm']}")
    print(f"  challenge peak p     : {verdict['challenge_peak']}")
    print(f"  below peak           : {verdict['below_peak']}")
    print(f"  unchanged by BKZ     : {verdict['unchanged_by_reduction']}")
    print()
    print(f"  {verdict['meaning']}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/red.json")
