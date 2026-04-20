#!/usr/bin/env python3
"""
compare_branches.py
Compares LLVM static branch analysis with TAGE simulation output.
Matches branches by !dbg number, reports LLVM predicted bank, TAGE final bank,
accuracy, mispredictions, taken/not-taken counts.
"""

import sys
import re
import argparse
from collections import defaultdict

# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_llvm(path):
    """
    Parse llvm.anal
    Returns dict: dbg_num (int) -> list of {function, node, H, explanation}
    Multiple entries can share the same dbg number (different nodes / files).
    """
    entries = defaultdict(list)
    header_re = re.compile(
        r'^(?P<func>[^:]+)::(?P<node>\S+)\s*\|\s*'
        r'(?P<dbg>!dbg\s+!\d+|—)\s*\|\s*'
        r'(?P<h>\S+)\s*\|\s*(?P<expl>.+)$'
    )
    with open(path) as f:
        for line in f:
            line = line.rstrip()
            m = header_re.match(line)
            if not m:
                continue
            dbg_raw = m.group('dbg').strip()
            if dbg_raw == '—':
                dbg_num = None
            else:
                dbg_num = int(re.search(r'\d+', dbg_raw).group())
            h = m.group('h').strip()
            entries[dbg_num].append({
                'function': m.group('func').strip().lstrip('.'),
                'node':     m.group('node').strip(),
                'H':        h,
                'explanation': m.group('expl').strip(),
                'dbg':      dbg_raw,
            })
    return entries


def parse_tage(path):
    """
    Parse tage.anal
    Returns two dicts keyed by PC (hex string, lowercase, no leading zeros stripped):
        provisional[pc] = list of provisional rows   (Status == 'P')
        final[pc]       = final row                  (Status == '[FINAL]')

    Each row dict:
        pc, pbank, abank, total, correct, mispr, acc,
        taken, not_taken, first_line, last_line, trajectory, status
    """
    col_re = re.compile(
        r'^(?P<status>P|\[FINAL\])\s+'
        r'(?P<pc>[0-9a-fA-F]+)\s+'
        r'(?P<pbank>\d+)\s+'
        r'(?P<abank>\d+)\s+'
        r'(?P<total>\d+)\s+'
        r'(?P<correct>\d+)\s+'
        r'(?P<mispr>\d+)\s+'
        r'(?P<acc>[\d.]+)\s+'
        r'(?P<taken>\d+)\s+'
        r'(?P<not_taken>\d+)\s+'
        r'(?P<first_line>\d+)\s+'
        r'(?P<last_line>\d+)\s+'
        r'(?P<trajectory>.+)$'
    )
    provisional = defaultdict(list)
    final = {}
    with open(path) as f:
        for line in f:
            line = line.rstrip()
            m = col_re.match(line)
            if not m:
                continue
            row = {
                'status':     m.group('status'),
                'pc':         m.group('pc').lower(),
                'pbank':      int(m.group('pbank')),
                'abank':      int(m.group('abank')),
                'total':      int(m.group('total')),
                'correct':    int(m.group('correct')),
                'mispr':      int(m.group('mispr')),
                'acc':        float(m.group('acc')),
                'taken':      int(m.group('taken')),
                'not_taken':  int(m.group('not_taken')),
                'first_line': int(m.group('first_line')),
                'last_line':  int(m.group('last_line')),
                'trajectory': m.group('trajectory').strip(),
            }
            pc = row['pc']
            if row['status'] == '[FINAL]':
                final[pc] = row
            else:
                provisional[pc].append(row)
    return provisional, final


# ---------------------------------------------------------------------------
# Matching logic
# ---------------------------------------------------------------------------

def bank_label(bank_int):
    """Convert numeric bank to human-readable label."""
    if bank_int == 0:
        return 'bimodal'
    return f'T{bank_int}'


def h_to_bank(h_str):
    """
    Map LLVM H value to a TAGE bank label for comparison.
    TAGE banks correspond to history lengths.
    Mapping based on typical TAGE-SC-L structure:
      bimodal -> 0
      H=5     -> bank 1
      H=9     -> bank 2
      H=15    -> bank 3
      H=26    -> bank 4
      H=44    -> bank 5
      H=76    -> bank 6
      H=130   -> bank 7
    """
    h_map = {
        'bimodal': 0,
        '5':  1,
        '9':  2,
        '15': 3,
        '26': 4,
        '44': 5,
        '76': 6,
        '130': 7,
    }
    return h_map.get(str(h_str), None)


def match_branches(llvm_entries, tage_provisional, tage_final, dbg_to_pc_map):
    """
    Join LLVM entries to TAGE rows via dbg_to_pc_map.
    dbg_to_pc_map: dict of dbg_num (int) -> list of pc strings
    Returns list of matched row dicts.
    """
    results = []

    for dbg_num, llvm_rows in llvm_entries.items():
        if dbg_num is None:
            continue
        pcs = dbg_to_pc_map.get(dbg_num, [])
        for llvm_row in llvm_rows:
            llvm_bank = h_to_bank(llvm_row['H'])
            llvm_bank_label = bank_label(llvm_bank) if llvm_bank is not None else llvm_row['H']

            if not pcs:
                results.append({
                    'dbg':          dbg_num,
                    'function':     llvm_row['function'],
                    'node':         llvm_row['node'],
                    'llvm_H':       llvm_row['H'],
                    'llvm_bank':    llvm_bank_label,
                    'explanation':  llvm_row['explanation'],
                    'pc':           None,
                    'tage_final_bank': None,
                    'tage_pbank':   None,
                    'tage_abank':   None,
                    'total':        None,
                    'correct':      None,
                    'mispr':        None,
                    'acc':          None,
                    'taken':        None,
                    'not_taken':    None,
                    'matched':      False,
                })
                continue

            for pc in pcs:
                fin = tage_final.get(pc)
                provs = tage_provisional.get(pc, [])
                # Last provisional row before final (highest line number seen)
                last_prov = max(provs, key=lambda r: r['last_line']) if provs else None

                tage_final_bank = bank_label(fin['pbank']) if fin else None
                tage_pbank      = bank_label(last_prov['pbank']) if last_prov else None
                tage_abank      = bank_label(last_prov['abank']) if last_prov else None

                results.append({
                    'dbg':          dbg_num,
                    'function':     llvm_row['function'],
                    'node':         llvm_row['node'],
                    'llvm_H':       llvm_row['H'],
                    'llvm_bank':    llvm_bank_label,
                    'explanation':  llvm_row['explanation'],
                    'pc':           pc,
                    'tage_final_bank': tage_final_bank,
                    'tage_pbank':   tage_pbank,
                    'tage_abank':   tage_abank,
                    'total':        fin['total']     if fin else None,
                    'correct':      fin['correct']   if fin else None,
                    'mispr':        fin['mispr']     if fin else None,
                    'acc':          fin['acc']       if fin else None,
                    'taken':        fin['taken']     if fin else None,
                    'not_taken':    fin['not_taken'] if fin else None,
                    'matched':      fin is not None,
                })
    return results


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def print_table(results):
    header = (
        f"{'DBG':>8}  {'Function':<30}  {'LLVM Bank':<12}  "
        f"{'PC':<10}  {'TAGE Final':<12}  {'TAGE PBank':<12}  "
        f"{'Acc%':>6}  {'Mispr':>6}  {'Total':>7}  {'Taken':>7}  {'!Taken':>7}  "
        f"Explanation"
    )
    sep = '-' * len(header)
    print(header)
    print(sep)
    for r in sorted(results, key=lambda x: (x['dbg'] or 0, x['pc'] or '')):
        pc_str         = r['pc']          if r['pc']               else '—'
        final_bank_str = r['tage_final_bank'] if r['tage_final_bank'] else '—'
        pbank_str      = r['tage_pbank']  if r['tage_pbank']       else '—'
        acc_str        = f"{r['acc']:.1f}" if r['acc'] is not None  else '—'
        mispr_str      = str(r['mispr'])  if r['mispr'] is not None else '—'
        total_str      = str(r['total'])  if r['total'] is not None else '—'
        taken_str      = str(r['taken'])  if r['taken'] is not None else '—'
        ntaken_str     = str(r['not_taken']) if r['not_taken'] is not None else '—'

        print(
            f"!{r['dbg']:>7}  {r['function']:<30}  {r['llvm_bank']:<12}  "
            f"{pc_str:<10}  {final_bank_str:<12}  {pbank_str:<12}  "
            f"{acc_str:>6}  {mispr_str:>6}  {total_str:>7}  "
            f"{taken_str:>7}  {ntaken_str:>7}  {r['explanation']}"
        )


def print_csv(results):
    import csv, io
    out = io.StringIO()
    fields = [
        'dbg', 'function', 'node', 'llvm_H', 'llvm_bank',
        'pc', 'tage_final_bank', 'tage_pbank', 'tage_abank',
        'total', 'correct', 'mispr', 'acc', 'taken', 'not_taken',
        'matched', 'explanation'
    ]
    w = csv.DictWriter(out, fieldnames=fields)
    w.writeheader()
    for r in sorted(results, key=lambda x: (x['dbg'] or 0, x['pc'] or '')):
        w.writerow(r)
    print(out.getvalue(), end='')


def print_summary(results):
    matched   = [r for r in results if r['matched']]
    unmatched = [r for r in results if not r['matched']]

    print(f"\n{'='*60}")
    print(f"  SUMMARY")
    print(f"{'='*60}")
    print(f"  Total LLVM branches:      {len(results)}")
    print(f"  Matched to TAGE final:    {len(matched)}")
    print(f"  Unmatched (no PC map):    {len(unmatched)}")

    if matched:
        # Bank agreement
        agree = sum(1 for r in matched if r['llvm_bank'] == r['tage_final_bank'])
        print(f"\n  LLVM bank == TAGE final bank: {agree}/{len(matched)} "
              f"({100*agree/len(matched):.1f}%)")

        # Accuracy distribution
        accs = [r['acc'] for r in matched if r['acc'] is not None]
        if accs:
            print(f"\n  Accuracy stats (TAGE final):")
            print(f"    Min:  {min(accs):.1f}%")
            print(f"    Max:  {max(accs):.1f}%")
            print(f"    Mean: {sum(accs)/len(accs):.1f}%")

        # Bank distribution comparison
        from collections import Counter
        llvm_banks  = Counter(r['llvm_bank'] for r in matched)
        tage_banks  = Counter(r['tage_final_bank'] for r in matched if r['tage_final_bank'])
        print(f"\n  LLVM predicted bank distribution:")
        for b, n in sorted(llvm_banks.items()):
            print(f"    {b:<12}: {n}")
        print(f"\n  TAGE final bank distribution:")
        for b, n in sorted(tage_banks.items()):
            print(f"    {b:<12}: {n}")
    print(f"{'='*60}\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def load_dbg_pc_map(path):
    """
    Load an optional mapping file: one entry per line
        <dbg_num> <pc_hex> [<pc_hex> ...]
    e.g.:
        3392 401a20
        3399 401b44 401c10
    """
    mapping = defaultdict(list)
    if path is None:
        return mapping
    with open(path) as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 2:
                try:
                    dbg = int(parts[0])
                    for pc in parts[1:]:
                        mapping[dbg].append(pc.lower())
                except ValueError:
                    pass
    return mapping


def main():
    parser = argparse.ArgumentParser(
        description='Compare LLVM static branch analysis with TAGE simulation output.'
    )
    parser.add_argument('llvm_file',  help='Path to llvm.anal')
    parser.add_argument('tage_file',  help='Path to tage.anal')
    parser.add_argument('--map',      help='Optional dbg->PC mapping file', default=None)
    parser.add_argument('--format',   choices=['table', 'csv'], default='table',
                        help='Output format (default: table)')
    parser.add_argument('--no-summary', action='store_true',
                        help='Suppress summary statistics')
    args = parser.parse_args()

    llvm_entries              = parse_llvm(args.llvm_file)
    tage_provisional, tage_final = parse_tage(args.tage_file)
    dbg_to_pc                 = load_dbg_pc_map(args.map)

    results = match_branches(llvm_entries, tage_provisional, tage_final, dbg_to_pc)

    if args.format == 'csv':
        print_csv(results)
    else:
        print_table(results)

    if not args.no_summary:
        print_summary(results)


if __name__ == '__main__':
    main()
