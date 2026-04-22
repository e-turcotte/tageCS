#!/usr/bin/env python3
"""
analyze_tage_hits.py

Analyzes a raw TAGE hits dump file (tage_hits_dump.out) and produces:
  1. A per-branch analysis showing the final/dominant bank, accuracy,
     taken/not-taken counts for every branch observed — including branches
     that coast on aliasing and never appear in tage.anal
  2. A patch CSV of (nop_pc, prefix_byte) pairs for binary patching,
     using the dominant bank from the hits data

Input file format (one line per branch event):
    pc  hitBank  hint  allocTable  taken

Where:
    pc         — branch PC (hex, no 0x prefix)
    hitBank    — TAGE bank that provided the prediction (0=bimodal, 1-7=tagged)
    hint       — whether the current hint/prefix matched (0 or 1)
    allocTable — whether an allocation occurred this cycle (0 or 1)
    taken      — branch outcome: 1=taken, -1=not-taken

Usage:
    # Analyze only
    python3 analyze_tage_hits.py \
        --hits  tage_hits_dump.out \
        --anal  hits_analysis.txt

    # Analyze and generate patch CSV
    python3 analyze_tage_hits.py \
        --hits  tage_hits_dump.out \
        --asm   mcf_r.asm \
        --anal  hits_analysis.txt \
        --patch patches.csv \
        --clean-only
"""

import re
import sys
import csv
import argparse
from collections import defaultdict

# ---------------------------------------------------------------------------
# CUSTOMIZABLE BANK -> PREFIX BYTE MAPPING
# Index = TAGE bank number (0=bimodal, 1-7=tagged banks)
# ---------------------------------------------------------------------------
BANK_TO_BYTE = [
    0x06,   # bank 0 — bimodal
    0x07,   # bank 1 — H=5
    0x0E,   # bank 2 — H=9
    0x16,   # bank 3 — H=15
    0x17,   # bank 4 — H=26
    0x1E,   # bank 5 — H=44
    0x1F,   # bank 6 — H=76
    0x27,   # bank 7 — H=130
]

# Size in bytes of the NOP inserted before each branch
NOP_SIZE = 1

# Minimum number of observations required to include a branch
MIN_OBSERVATIONS = 1

# ---------------------------------------------------------------------------
# Step 1: Parse raw hits dump
# ---------------------------------------------------------------------------

def parse_hits(hits_path):
    """
    Parse tage_hits_dump.out line by line.

    Returns per-branch stats dict:
        pc -> {
            'total':       int,
            'taken':       int,
            'not_taken':   int,
            'bank_counts': {bank: count},   # how often each bank predicted
            'correct':     int,             # hint==1 count
            'mispr':       int,             # hint==0 count
            'alloc_count': int,
            'first_line':  int,
            'last_line':   int,
        }
    """
    stats = defaultdict(lambda: {
        'total':       0,
        'taken':       0,
        'not_taken':   0,
        'bank_counts': defaultdict(int),
        'correct':     0,
        'mispr':       0,
        'alloc_count': 0,
        'first_line':  None,
        'last_line':   None,
    })

    line_re = re.compile(
        r'^([0-9a-fA-F]+)\s+'   # pc
        r'(-?\d+)\s+'            # hitBank
        r'(-?\d+)\s+'            # hint
        r'(-?\d+)\s+'            # allocTable
        r'(-?\d+)'               # taken (1 or -1)
    )

    print(f"[*] Parsing hits dump...", file=sys.stderr)
    total_lines   = 0
    skipped_lines = 0

    with open(hits_path) as f:
        for lineno, raw in enumerate(f, 1):
            raw = raw.strip()
            if not raw or raw.startswith('#'):
                continue
            m = line_re.match(raw)
            if not m:
                skipped_lines += 1
                if skipped_lines <= 5:
                    print(f"    Warning: skipping malformed line {lineno}: {repr(raw)}",
                          file=sys.stderr)
                continue

            total_lines += 1
            pc         = m.group(1).lower()
            hit_bank   = int(m.group(2))
            hint       = int(m.group(3))
            alloc      = int(m.group(4))
            taken_raw  = int(m.group(5))
            taken      = taken_raw == 1

            s = stats[pc]
            s['total'] += 1
            if taken:
                s['taken'] += 1
            else:
                s['not_taken'] += 1
            s['bank_counts'][hit_bank] += 1
            if hint == 1:
                s['correct'] += 1
            else:
                s['mispr'] += 1
            if alloc:
                s['alloc_count'] += 1
            if s['first_line'] is None:
                s['first_line'] = lineno
            s['last_line'] = lineno

    print(f"[*] Parsed {total_lines} events across {len(stats)} unique PCs",
          file=sys.stderr)
    if skipped_lines:
        print(f"[*] Skipped {skipped_lines} malformed lines", file=sys.stderr)

    return stats


# ---------------------------------------------------------------------------
# Step 2: Compute dominant bank per branch
# ---------------------------------------------------------------------------

def compute_dominant_bank(stats):
    """
    For each PC determine the dominant bank  the bank that predicted
    the most often over the full execution.

    Returns: pc -> dominant_bank (int)
    """
    dominant = {}
    for pc, s in stats.items():
        if s['total'] < MIN_OBSERVATIONS:
            continue
        dominant[pc] = max(s['bank_counts'], key=lambda b: s['bank_counts'][b])
    return dominant


# ---------------------------------------------------------------------------
# Step 3: Write analysis report
# ---------------------------------------------------------------------------

def write_analysis(stats, dominant, output_path):
    """
    Write a human-readable analysis similar to tage.anal [FINAL] format
    but covering all branches including those that coast on aliasing.
    """
    with open(output_path, 'w') as f:
        f.write(f"Analyzed {sum(s['total'] for s in stats.values())} "
                f"branch events across {len(stats)} unique PCs\n\n")

        f.write(f"{'PC':<10}  {'DomBank':>7}  {'Total':>8}  {'Correct':>8}  "
                f"{'Mispr':>6}  {'Acc%':>6}  {'Taken':>8}  {'!Taken':>8}  "
                f"{'AllocCt':>7}  BankDist\n")
        f.write('-' * 120 + '\n')

        for pc in sorted(stats, key=lambda p: stats[p]['total'], reverse=True):
            s = stats[pc]
            if s['total'] < MIN_OBSERVATIONS:
                continue
            dom   = dominant.get(pc, -1)
            acc   = 100.0 * s['correct'] / s['total'] if s['total'] else 0.0
            bdist = '  '.join(
                f"b{b}:{c}" for b, c in sorted(s['bank_counts'].items())
            )
            f.write(
                f"{pc:<10}  {dom:>7}  {s['total']:>8}  {s['correct']:>8}  "
                f"{s['mispr']:>6}  {acc:>6.1f}  {s['taken']:>8}  "
                f"{s['not_taken']:>8}  {s['alloc_count']:>7}  {bdist}\n"
            )

    print(f"[*] Wrote analysis to {output_path}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Step 4: Parse asm for NOPs and branches (same as gen_prefix_patch_tage.py)
# ---------------------------------------------------------------------------

def load_asm_nops(asm_path):
    nop_re = re.compile(
        r'^\s*([0-9a-fA-F]+):\s+'
        r'(?:[0-9a-fA-F]{2}\s+)*'
        r'nop\b'
    )
    branch_re = re.compile(
        r'^\s*([0-9a-fA-F]+):\s+'
        r'(?:[0-9a-fA-F]{2}\s+)*'
        r'(j[a-z]+|call|callq|jmp|jmpq)\s'
    )
    branch_re_nobytes = re.compile(
        r'^\s*([0-9a-fA-F]+):\s+'
        r'(j[a-z]+|call|callq|jmp|jmpq)\s'
    )

    nop_pcs    = set()
    branch_pcs = set()

    with open(asm_path) as f:
        for line in f:
            m = nop_re.match(line)
            if m:
                nop_pcs.add(m.group(1).lower())
                continue
            m = branch_re.match(line) or branch_re_nobytes.match(line)
            if m:
                branch_pcs.add(m.group(1).lower())

    print(f"[*] Found {len(nop_pcs)} NOPs and {len(branch_pcs)} branches in asm",
          file=sys.stderr)
    return nop_pcs, branch_pcs


# ---------------------------------------------------------------------------
# Step 5: Build patch table
# ---------------------------------------------------------------------------

def pc_plus(pc_hex, offset):
    val = int(pc_hex, 16) + offset
    return format(val, f'0{len(pc_hex)}x')


def build_patch_table(stats, dominant, nop_pcs, branch_pcs):
    rows  = []
    patch_stats = defaultdict(int)

    # Diagnostics
    print(f"\n[*] Sample hits PCs:       {sorted(stats.keys())[:5]}", file=sys.stderr)
    print(f"[*] Sample asm NOP PCs:    {sorted(nop_pcs)[:5]}", file=sys.stderr)
    print(f"[*] Sample asm branch PCs: {sorted(branch_pcs)[:5]}", file=sys.stderr)

    matches = set(stats.keys()) & nop_pcs
    print(f"[*] Direct hits PC matches in nop_pcs: {len(matches)}", file=sys.stderr)

    for pc in sorted(stats):
        s    = stats[pc]
        bank = dominant.get(pc)

        if bank is None:
            patch_stats['below_min_observations'] += 1
            continue

        if bank < 0 or bank >= len(BANK_TO_BYTE):
            patch_stats['bank_out_of_range'] += 1
            continue

        prefix_byte = BANK_TO_BYTE[bank]
        nop_pc      = pc
        branch_pc   = pc_plus(pc, NOP_SIZE)
        valid_nop   = nop_pc in nop_pcs
        in_asm      = branch_pc in branch_pcs
        acc         = 100.0 * s['correct'] / s['total'] if s['total'] else 0.0

        if valid_nop and in_asm:
            note = 'ok'
        elif valid_nop and not in_asm:
            note = 'branch_not_found_after_nop'
        elif not valid_nop and in_asm:
            note = 'nop_not_found'
        else:
            note = 'neither_found_in_asm'

        patch_stats[note] += 1

        rows.append({
            'nop_pc':      f'0x{nop_pc}',
            'prefix_byte': f'0x{prefix_byte:02x}',
            'branch_pc':   f'0x{branch_pc}',
            'dom_bank':    bank,
            'total':       s['total'],
            'correct':     s['correct'],
            'mispr':       s['mispr'],
            'acc':         f"{acc:.1f}",
            'taken':       s['taken'],
            'not_taken':   s['not_taken'],
            'alloc_count': s['alloc_count'],
            'valid_nop':   valid_nop,
            'note':        note,
        })

    print(f"\n[*] Patch table summary:", file=sys.stderr)
    for k, v in sorted(patch_stats.items()):
        print(f"    {k:<40}: {v}", file=sys.stderr)

    return rows


# ---------------------------------------------------------------------------
# Step 6: Write patch CSV
# ---------------------------------------------------------------------------

def write_patch_csv(rows, output_path, clean_only=False):
    if clean_only:
        rows = [r for r in rows if r['note'] == 'ok']

    fieldnames = [
        'nop_pc', 'prefix_byte',
        'branch_pc', 'dom_bank', 'total', 'correct', 'mispr', 'acc',
        'taken', 'not_taken', 'alloc_count', 'valid_nop', 'note'
    ]

    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in sorted(rows, key=lambda r: r['nop_pc']):
            writer.writerow(row)

    print(f"[*] Wrote {len(rows)} patch rows to {output_path}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Fallback patch loader
# ---------------------------------------------------------------------------

def load_fallback_patch(patch_path):
    """
    Load an existing patch CSV.
    Returns: dict of nop_pc (hex str, no 0x) -> row dict
    """
    entries = {}
    with open(patch_path, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            nop_pc = row['nop_pc'].replace('0x', '').lower()
            entries[nop_pc] = row
    print(f"[*] Loaded {len(entries)} entries from fallback patch", file=sys.stderr)
    return entries


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global NOP_SIZE, MIN_OBSERVATIONS

    parser = argparse.ArgumentParser(
        description='Analyze raw TAGE hits dump and optionally generate patch CSV'
    )
    parser.add_argument('--hits',     required=True,
                        help='Path to tage_hits_dump.out')
    parser.add_argument('--anal',     required=True,
                        help='Output path for analysis report')
    parser.add_argument('--asm',      default=None,
                        help='objdump disassembly (required for --patch without --fallback-patch)')
    parser.add_argument('--patch',    default=None,
                        help='Output path for patch CSV (optional)')
    parser.add_argument('--clean-only', action='store_true',
                        help='Only output patch rows with note==ok')
    parser.add_argument('--nop-size', type=int, default=NOP_SIZE,
                        help=f'NOP size in bytes (default: {NOP_SIZE})')
    parser.add_argument('--min-obs',  type=int, default=MIN_OBSERVATIONS,
                        help=f'Minimum observations to include a branch '
                             f'(default: {MIN_OBSERVATIONS})')
    parser.add_argument('--fallback-patch', default=None,
                        help='Existing patch CSV whose PCs must all be covered. '
                             'PCs missing from hits data receive the bimodal '
                             'prefix byte (BANK_TO_BYTE[0]) as a default.')
    args = parser.parse_args()

    if args.patch and not args.asm and not args.fallback_patch:
        parser.error('--asm is required when --patch is specified without --fallback-patch')

    NOP_SIZE         = args.nop_size
    MIN_OBSERVATIONS = args.min_obs

    if args.patch:
        print(f"[*] Active BANK_TO_BYTE mapping:", file=sys.stderr)
        for i, b in enumerate(BANK_TO_BYTE):
            print(f"    bank {i}: 0x{b:02x}", file=sys.stderr)
        print(f"[*] NOP_SIZE: {NOP_SIZE} byte(s)", file=sys.stderr)

    stats    = parse_hits(args.hits)
    dominant = compute_dominant_bank(stats)
    write_analysis(stats, dominant, args.anal)

    if args.patch:
        # Build the base patch from hits data
        if args.asm:
            nop_pcs, branch_pcs = load_asm_nops(args.asm)
            rows = build_patch_table(stats, dominant, nop_pcs, branch_pcs)
        else:
            rows = []

        if args.fallback_patch:
            # Index rows already generated by nop_pc
            covered = {r['nop_pc'].replace('0x', '').lower(): r for r in rows}

            fallback     = load_fallback_patch(args.fallback_patch)
            bimodal_byte = BANK_TO_BYTE[0]
            added        = 0
            already      = 0

            for nop_pc, fb_row in sorted(fallback.items()):
                if nop_pc in covered:
                    already += 1
                    continue
                # Not in hits data — use bimodal as default
                rows.append({
                    'nop_pc':      f'0x{nop_pc}',
                    'prefix_byte': f'0x{bimodal_byte:02x}',
                    'branch_pc':   fb_row.get('branch_pc', ''),
                    'dom_bank':    0,
                    'total':       0,
                    'correct':     0,
                    'mispr':       0,
                    'acc':         '',
                    'taken':       0,
                    'not_taken':   0,
                    'alloc_count': 0,
                    'valid_nop':   True,
                    'note':        'bimodal_default',
                })
                added += 1

            print(f"[*] Fallback: {already} PCs already covered by hits data",
                  file=sys.stderr)
            print(f"[*] Fallback: {added} PCs filled with bimodal default (0x{bimodal_byte:02x})",
                  file=sys.stderr)

        write_patch_csv(rows, args.patch, clean_only=args.clean_only)


if __name__ == '__main__':
    main()
