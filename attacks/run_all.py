"""
New file: run every attack and print one summary table.

Each attack runs against its own fresh overlay of real peers, so one
attack cannot affect the next.

Run:   python -m attacks.run_all                      all six attacks
       python -m attacks.run_all replay flooding      only these
       python -m attacks.run_all --details            with the evidence
       python -m attacks.run_all --csv results.csv    also save a CSV file
"""

import argparse
import csv

from attacks import (fake_registration, flooding, impersonation, replay_attack,
                     tampering, unauthorized_peer)
from attacks.lab import AttackLab

ATTACKS = {
    "unauthorized_peer": unauthorized_peer,
    "fake_registration": fake_registration,
    "impersonation": impersonation,
    "tampering": tampering,
    "replay": replay_attack,
    "flooding": flooding,
}


# Run the chosen attacks, each in a fresh overlay, and return the results.
def run_attacks(names=None):
    results = []
    for name in names or ATTACKS:
        with AttackLab() as lab:
            results.append(ATTACKS[name].run(lab))
    return results


# The results as a plain-text table.
def table(results):
    yes = {True: "YES", False: "NO"}
    rows = [("Attack", "Blocked", "Detected", "Response")]
    rows += [(r.name, yes[r.blocked], yes[r.detected], r.response) for r in results]
    widths = [max(len(row[i]) for row in rows) for i in range(3)]
    lines = []
    for index, row in enumerate(rows):
        lines.append("  ".join(row[i].ljust(widths[i]) for i in range(3)) + "  " + row[3])
        if index == 0:
            lines.append("-" * len(lines[0]))
    passed = sum(1 for r in results if r.passed)
    lines.append("")
    lines.append(f"{passed} of {len(results)} attacks blocked and detected")
    return "\n".join(lines)


def save_csv(results, path):
    with open(path, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["attack", "goal", "blocked", "detected", "response", "evidence"])
        for r in results:
            writer.writerow([r.name, r.goal, r.blocked, r.detected, r.response, " | ".join(r.evidence)])


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run the attack scripts against real peers")
    parser.add_argument("attacks", nargs="*", metavar="attack",
                        help="attacks to run (default: all): " + ", ".join(ATTACKS))
    parser.add_argument("--details", action="store_true", help="print the evidence of each attack")
    parser.add_argument("--csv", metavar="FILE", help="also save the results as CSV")
    args = parser.parse_args(argv)
    unknown = [name for name in args.attacks if name not in ATTACKS]
    if unknown:
        parser.error(f"unknown attack {', '.join(unknown)} (choose from {', '.join(ATTACKS)})")

    results = run_attacks(args.attacks)
    if args.details:
        for r in results:
            print("\n".join(r.lines()))
            print()
    print(table(results))
    if args.csv:
        save_csv(results, args.csv)
        print(f"Saved {args.csv}")
    return 0 if all(r.passed for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
