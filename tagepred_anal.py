#!/usr/bin/env python3
"""
Parse gem5 TAGE branch predictor output and summarize lifetimes per branch+bank context.

Input format (one line per branch occurrence):
  pc  pred_bank  alt_pred_bank  pred_taken  correct

A unique "trajectory" is identified by (pc, pred_bank, alt_pred_bank) — because
a different bank pair means the branch arrived under a different history context.
"""

import sys
import argparse
from collections import defaultdict


def parse_file(path):
    records = []
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 5:
                print(f"Warning: skipping malformed line {lineno}: {line!r}", file=sys.stderr)
                continue
            pc, pred_bank, alt_pred_bank, pred_taken, correct = parts
            records.append({
                "lineno": lineno,
                "pc": pc,
                "pred_bank": int(pred_bank),
                "alt_pred_bank": int(alt_pred_bank),
                "pred_taken": int(pred_taken),
                "correct": int(correct),
            })
    return records


def summarize(records):
    """
    Group by (pc, pred_bank, alt_pred_bank) — each unique triple is one
    history-context trajectory for that branch.
    Returns a dict keyed by (pc, pred_bank, alt_pred_bank) -> summary dict.

    Promotion detection:
      A trajectory (pc, bank, ...) is considered promoted if, at any point
      *after* its last occurrence, the same pc appears with a strictly higher
      pred_bank.  The promotion is appended as 'P' at the end of the trajectory
      string.  If no promotion ever follows, the trajectory is marked [FINAL].
    """
    trajectories = defaultdict(list)
    for r in records:
        key = (r["pc"], r["pred_bank"], r["alt_pred_bank"])
        trajectories[key].append(r)

    # For each pc, collect the ordered sequence of (lineno, pred_bank) across
    # ALL trajectories so we can look up what happened after a trajectory ended.
    pc_timeline = defaultdict(list)  # pc -> sorted list of (lineno, pred_bank)
    for r in records:
        pc_timeline[r["pc"]].append((r["lineno"], r["pred_bank"]))
    # Already insertion-ordered since records are parsed in line order, but sort
    # explicitly to be safe.
    for pc in pc_timeline:
        pc_timeline[pc].sort()

    summaries = {}
    for key, events in trajectories.items():
        pc, pred_bank, alt_pred_bank = key
        total      = len(events)
        correct    = sum(e["correct"] for e in events)
        mispred    = total - correct
        taken      = sum(e["pred_taken"] for e in events)
        not_taken  = total - taken
        first_line = events[0]["lineno"]
        last_line  = events[-1]["lineno"]
        accuracy   = correct / total * 100

        # Build a compact run-length-encoded trajectory string of outcomes
        # 'C'=correct, 'M'=mispredicted, grouped into runs
        outcome_seq = ["C" if e["correct"] else "M" for e in events]
        rle = []
        cur, cnt = outcome_seq[0], 1
        for o in outcome_seq[1:]:
            if o == cur:
                cnt += 1
            else:
                rle.append((cur, cnt))
                cur, cnt = o, 1
        rle.append((cur, cnt))
        trajectory_str = " ".join(
            f"{sym}x{n}" if n > 1 else sym for sym, n in rle
        )

        # Promotion: does this pc ever appear with a higher pred_bank after
        # this trajectory's last occurrence?
        promoted = any(
            bank > pred_bank
            for lineno, bank in pc_timeline[pc]
            if lineno > last_line
        )
        promotion_status = "P" if promoted else "[FINAL]"

        summaries[key] = {
            "pc": pc,
            "pred_bank": pred_bank,
            "alt_pred_bank": alt_pred_bank,
            "total": total,
            "correct": correct,
            "mispred": mispred,
            "accuracy_pct": accuracy,
            "pred_taken": taken,
            "pred_not_taken": not_taken,
            "first_occurrence_line": first_line,
            "last_occurrence_line": last_line,
            "outcome_trajectory": trajectory_str,
            "promoted": promoted,
            "promotion_status": promotion_status,
        }
    return summaries


def print_summaries(summaries, sort_by="first_occurrence_line"):
    entries = list(summaries.values())

    sort_keys = {
        "first_occurrence_line": lambda e: e["first_occurrence_line"],
        "pc":                    lambda e: int(e["pc"], 16),
        "total":                 lambda e: -e["total"],          # descending
        "accuracy":              lambda e: e["accuracy_pct"],
        "mispred":               lambda e: -e["mispred"],        # descending
    }
    entries.sort(key=sort_keys.get(sort_by, sort_keys["first_occurrence_line"]))

    # Header
    print(f"{'Status':<8} {'PC':<18} {'PBank':>5} {'ABank':>5} {'Total':>6} {'Correct':>7} "
          f"{'Mispr':>5} {'Acc%':>6} {'Taken':>6} {'!Taken':>6} "
          f"{'FirstLine':>9} {'LastLine':>8}  Outcome Trajectory")
    print("-" * 128)

    for e in entries:
        print(
            f"{e['promotion_status']:<8} "
            f"{e['pc']:<18} "
            f"{e['pred_bank']:>5} "
            f"{e['alt_pred_bank']:>5} "
            f"{e['total']:>6} "
            f"{e['correct']:>7} "
            f"{e['mispred']:>5} "
            f"{e['accuracy_pct']:>6.1f} "
            f"{e['pred_taken']:>6} "
            f"{e['pred_not_taken']:>6} "
            f"{e['first_occurrence_line']:>9} "
            f"{e['last_occurrence_line']:>8}  "
            f"{e['outcome_trajectory']}"
        )

    print()
    print(f"  Unique trajectories : {len(entries)}")
    print(f"  Unique PCs          : {len(set(e['pc'] for e in entries))}")
    total_events = sum(e['total'] for e in entries)
    total_correct = sum(e['correct'] for e in entries)
    n_promoted = sum(1 for e in entries if e["promoted"])
    n_final    = len(entries) - n_promoted
    print(f"  Total branch events : {total_events}")
    print(f"  Overall accuracy    : {total_correct/total_events*100:.2f}%")
    print(f"  Promoted            : {n_promoted}")
    print(f"  Final (not promoted): {n_final}")

    # Bar chart: final trajectory count per pred_bank
    final_entries = [e for e in entries if not e["promoted"]]
    if final_entries:
        from collections import Counter
        bank_counts = Counter(e["pred_bank"] for e in final_entries)
        all_banks   = sorted(bank_counts)
        max_count   = max(bank_counts.values())
        bar_width   = 24  # max number of block characters
        label_w     = max(len(f"bank {b}") for b in all_banks)

        print()
        print("  Final Trajectory Distribution by Pred Bank:")
        for bank in all_banks:
            count   = bank_counts[bank]
            pct     = count / n_final * 100
            filled  = round(bar_width * count / max_count)
            bar     = "█" * filled
            label   = f"bank {bank}"
            print(f"    {label:>{label_w}} : {count:>5}  ({pct:>5.1f}%)  {bar}")


def main():
    parser = argparse.ArgumentParser(
        description="Summarize gem5 TAGE branch predictor output by branch+history trajectory."
    )
    parser.add_argument("input", help="Path to the gem5 output file")
    parser.add_argument(
        "--sort", default="first_occurrence_line",
        choices=["first_occurrence_line", "pc", "total", "accuracy", "mispred"],
        help="Sort output by this field (default: first_occurrence_line)"
    )
    args = parser.parse_args()

    records = parse_file(args.input)
    print(f"Parsed {len(records)} branch events from '{args.input}'\n")

    summaries = summarize(records)
    print_summaries(summaries, sort_by=args.sort)


if __name__ == "__main__":
    main()
