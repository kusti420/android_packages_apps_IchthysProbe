#!/usr/bin/env python3
# Copyright (C) 2026 IchthysOS
# SPDX-License-Identifier: Apache-2.0
"""Compare IchthysProbe reports across runs.

usage: compare.py DIR_OR_REPORT... [--details PROBE_ID] [--all] [--no-color]

Prints one table row per probe (grouped by category) with one column per run, then every
IchthysOS expectation that failed, then the host-side checks of run_matrix.sh
(host-checks.json). Exit status 1 when anything failed.

Cell format: <outcome> plus a verdict mark: "ok" kept a promise, "FAIL" broke one, nothing for
information only, "-" not run.
"""

import argparse
import glob
import json
import os
import sys

SHORT = {
    "visible": "visible",
    "empty": "empty",
    "blocked-by-permission": "blk-perm",
    "blocked-by-IchthysOS": "blk-ichthys",
    "unavailable": "n/a",
    "skipped": "skip",
    "error": "error",
}
RUN_ORDER = ["a", "b", "c", "c-paused", "c-resumed", "d"]


def load(paths):
    reports, host = [], []
    files = []
    for p in paths:
        if os.path.isdir(p):
            files += sorted(glob.glob(os.path.join(p, "*.json")))
        else:
            files.append(p)
    for f in files:
        try:
            with open(f) as fh:
                data = json.load(fh)
        except (OSError, ValueError) as e:
            print(f"skipping {f}: {e}", file=sys.stderr)
            continue
        if os.path.basename(f) == "host-checks.json" and isinstance(data, list):
            host += data
        elif isinstance(data, dict) and "probes" in data:
            data["_file"] = f
            reports.append(data)
    return reports, host


def run_key(report):
    label = report.get("label", "")
    prefix = label.split("-")[0]
    for i, r in enumerate(RUN_ORDER):
        if label == r or label.startswith(r + "-2"):
            return (i, label)
    return (len(RUN_ORDER), prefix, report.get("started", ""), label)


def short_label(label):
    # "a-20261027-101500" -> "a"; run_matrix labels end in the timestamp.
    parts = label.split("-")
    if len(parts) >= 3 and parts[-2].isdigit() and parts[-1].isdigit():
        return "-".join(parts[:-2])
    return label


def color(s, code, enabled):
    return f"\033[{code}m{s}\033[0m" if enabled else s


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--details", metavar="PROBE_ID",
                    help="print the redacted details of one probe across runs")
    ap.add_argument("--all", action="store_true",
                    help="show every probe, not only the ones that differ or have a verdict")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()
    use_color = sys.stdout.isatty() and not args.no_color

    reports, host = load(args.paths)
    if not reports and not host:
        print("no reports found")
        return 2
    reports.sort(key=run_key)
    labels = [short_label(r.get("label", "?")) for r in reports]

    # probe id -> (category, {run index: probe dict})
    table = {}
    order = []
    for i, r in enumerate(reports):
        for p in r["probes"]:
            pid = p["id"]
            if pid not in table:
                table[pid] = (p.get("category", "?"), {})
                order.append(pid)
            table[pid][1][i] = p

    print("Runs:")
    for lab, r in zip(labels, reports):
        dev = r.get("device", {})
        tot = r.get("totals", {})
        print(f"  {lab:10} {r.get('label')}  started {r.get('started')}  "
              f"locked={dev.get('keyguard_locked')} interactive={dev.get('interactive')}  "
              f"pass={tot.get('pass')} fail={tot.get('fail')} info={tot.get('info')} "
              f"skip={tot.get('skip')}")
    print()

    if args.details:
        cat, cells = table.get(args.details, ("?", {}))
        print(f"{args.details} ({cat})")
        for i, lab in enumerate(labels):
            p = cells.get(i)
            if not p:
                print(f"  {lab}: -")
                continue
            print(f"  {lab}: {p['outcome']} [{p['verdict']}] granted={p.get('granted')}")
            for k, v in p.get("detail", {}).items():
                print(f"      {k} = {v}")
            if p.get("verdict_why"):
                print(f"      -> {p['verdict_why']}")
        return 0

    idw = max([len(x) for x in order] + [10])
    colw = max([len(x) for x in labels] + [16])
    header = "probe".ljust(idw) + "  " + "  ".join(l.ljust(colw) for l in labels)
    current_cat = None
    printed_header = False
    for pid in sorted(order, key=lambda x: (table[x][0], order.index(x))):
        cat, cells = table[pid]
        outcomes = {cells[i]["outcome"] for i in cells}
        verdicts = {cells[i]["verdict"] for i in cells}
        if not args.all and len(outcomes) <= 1 and verdicts <= {"info", "skip"}:
            continue
        if not printed_header:
            print(header)
            print("-" * len(header))
            printed_header = True
        if cat != current_cat:
            print(color(f"[{cat}]", "1", use_color))
            current_cat = cat
        row = pid.ljust(idw)
        for i in range(len(reports)):
            p = cells.get(i)
            if not p:
                cell = "-"
            else:
                cell = SHORT.get(p["outcome"], p["outcome"])
                v = p["verdict"]
                if v == "pass":
                    cell += " ok"
                elif v == "fail":
                    cell += " FAIL"
            pad = cell.ljust(colw)
            if p and p["verdict"] == "fail":
                pad = color(pad, "31", use_color)
            elif p and p["verdict"] == "pass":
                pad = color(pad, "32", use_color)
            row += "  " + pad
        print(row)
    if not args.all:
        print("\n(rows with the same informational outcome in every run are hidden; --all shows "
              "them)")

    failures = 0
    print("\nIchthysOS expectations that FAILED:")
    seen = False
    for lab, r in zip(labels, reports):
        for p in r["probes"]:
            if p.get("verdict") != "fail":
                continue
            seen = True
            failures += 1
            e = p.get("expectation", {})
            print(f"  [{lab}] {p['id']}: {e.get('feature', '?')}")
            print(f"        promise : {e.get('promise', '')}")
            print(f"        observed: {p['outcome']} ({p.get('verdict_why', '')})")
            det = ", ".join(f"{k}={v}" for k, v in p.get("detail", {}).items())
            if det:
                print(f"        detail  : {det}")
            print(f"        source  : {e.get('source', '')}")
    if not seen:
        print("  none")

    if host:
        print("\nHost-side checks (run_matrix.sh):")
        for h in host:
            v = h.get("verdict", "?")
            mark = {"pass": "ok", "fail": "FAIL"}.get(v, v)
            line = (f"  {mark:5} {h.get('id')}: {h.get('feature')}: expected "
                    f"{h.get('expected')}, got {h.get('actual')}")
            if v == "fail":
                failures += 1
                line = color(line, "31", use_color)
            print(line)
            if v == "fail" or h.get("detail"):
                print(f"        source: {h.get('source', '')}")
                if h.get("detail"):
                    print(f"        detail: {h.get('detail')}")

    print(f"\n{failures} failed expectation(s) across {len(reports)} run(s).")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
