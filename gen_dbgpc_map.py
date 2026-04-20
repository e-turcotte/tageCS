#!/usr/bin/env python3
"""
gen_dbg_pc_map.py

Generates a dbg->PC mapping file by:
1. Extracting all branch PCs from the TAGE analysis file
2. Running llvm-symbolizer on each PC to get file/line/column
3. Parsing the linked .ll file for branch instructions and their !dbg metadata
4. Joining on file/line/col, using branch instruction check to disambiguate
   when multiple !dbg numbers share the same source location
5. Reporting unmatched LLVM branches for diagnosis

Usage:
    python3 gen_dbg_pc_map.py \
        --tage    tage.anal \
        --ll      mcf_r_linked.ll \
        --binary  mcf_r \
        --llvm-bin /home/eddiet/interplay/tageCS/build/bin \
        --output  dbg_pc.map
"""

import re
import sys
import argparse
import subprocess
from collections import defaultdict


# ---------------------------------------------------------------------------
# Step 1: Extract all unique PCs from tage.anal
# ---------------------------------------------------------------------------

def extract_tage_pcs(tage_path):
    pc_re = re.compile(r'^(?:P|\[FINAL\])\s+([0-9a-fA-F]+)\s+')
    pcs = set()
    with open(tage_path) as f:
        for line in f:
            m = pc_re.match(line)
            if m:
                pcs.add(m.group(1).lower())
    print(f"[*] Extracted {len(pcs)} unique PCs from TAGE file", file=sys.stderr)
    return pcs


# ---------------------------------------------------------------------------
# Step 2: Symbolize PCs -> file/line/col
# ---------------------------------------------------------------------------

def symbolize_pcs(pcs, binary, llvm_bin):
    symbolizer = f"{llvm_bin}/llvm-symbolizer"
    pc_to_locs = defaultdict(list)
    addr_list  = sorted(pcs)
    input_str  = '\n'.join(f"0x{pc}" for pc in addr_list)

    cmd = [symbolizer, f"--exe={binary}", "--output-style=GNU", "--inlines"]
    print(f"[*] Running llvm-symbolizer on {len(addr_list)} PCs...", file=sys.stderr)

    try:
        result = subprocess.run(
            cmd, input=input_str, capture_output=True, text=True, timeout=300
        )
    except FileNotFoundError:
        print(f"[!] llvm-symbolizer not found at {symbolizer}", file=sys.stderr)
        sys.exit(1)

    # GNU style: function line then file:line:col line, blank line between addresses
    out_lines = result.stdout.splitlines()
    pc_idx = 0
    i = 0
    while i < len(out_lines) and pc_idx < len(addr_list):
        line = out_lines[i].strip()
        if not line:
            pc_idx += 1
            i += 1
            continue
        func = line
        i += 1
        if i < len(out_lines):
            loc = out_lines[i].strip()
            i += 1
            parts = loc.rsplit(':', 2)
            if len(parts) == 3:
                try:
                    filename = parts[0]
                    lineno   = int(parts[1])
                    col      = int(parts[2])
                    pc = addr_list[pc_idx].lower()
                    pc_to_locs[pc].append((filename, lineno, col, func))
                except ValueError:
                    pass

    # Fallback: one at a time
    if not pc_to_locs:
        print("[*] Batch parse failed, falling back to one-at-a-time...", file=sys.stderr)
        for pc in addr_list:
            cmd2 = [symbolizer, f"--exe={binary}", f"0x{pc}"]
            try:
                r = subprocess.run(cmd2, capture_output=True, text=True, timeout=10)
                lines2 = r.stdout.strip().splitlines()
                for j in range(0, len(lines2) - 1, 2):
                    parts2 = lines2[j+1].strip().rsplit(':', 2)
                    if len(parts2) == 3:
                        try:
                            pc_to_locs[pc.lower()].append((
                                parts2[0], int(parts2[1]), int(parts2[2]),
                                lines2[j].strip()
                            ))
                        except ValueError:
                            pass
            except Exception:
                pass

    print(f"[*] Symbolized {len(pc_to_locs)} PCs successfully", file=sys.stderr)
    return pc_to_locs


# ---------------------------------------------------------------------------
# Step 3: Parse .ll file - branch instructions AND debug metadata
# ---------------------------------------------------------------------------

BRANCH_OPS = re.compile(
    r'^\s*(br\b|switch\b|indirectbr\b|invoke\b|callbr\b)'
)

def parse_ll_file(ll_path):
    """
    Returns:
        branch_dbg_nums  : set of dbg nums attached to branch instructions
        loc_to_dbg_all   : (basename, line, col) -> [dbg_num, ...]  all metadata
        loc_to_dbg_br    : (basename, line, col) -> [dbg_num, ...]  branch-only
        dbg_to_locs      : dbg_num -> [(basename, line, col), ...]
        all_llvm_branches: [(dbg_num, basename, line, col), ...]
    """
    diloc_re     = re.compile(
        r'^!(\d+)\s*=\s*!DILocation\(line:\s*(\d+),\s*column:\s*(\d+),\s*scope:\s*!(\d+)'
    )
    disubprog_re = re.compile(
        r'^!(\d+)\s*=\s*(?:distinct\s+)?!DISubprogram\(.*?file:\s*!(\d+)'
    )
    difile_re    = re.compile(
        r'^!(\d+)\s*=\s*!DIFile\(filename:\s*"([^"]+)"'
    )
    dilexical_re = re.compile(
        r'^!(\d+)\s*=\s*(?:distinct\s+)?!DILexicalBlock[^(]*\(.*?scope:\s*!(\d+)'
    )
    dbg_ref_re   = re.compile(r',\s*!dbg\s*!(\d+)')

    difile    = {}
    discope   = {}
    disubprog = {}
    dilocs    = []
    branch_dbg_nums = set()

    print(f"[*] Parsing .ll file for branch instructions and debug metadata...",
          file=sys.stderr)

    with open(ll_path) as f:
        for raw in f:
            line = raw.rstrip()

            m = difile_re.match(line)
            if m:
                difile[int(m.group(1))] = m.group(2)
                continue

            m = disubprog_re.match(line)
            if m:
                disubprog[int(m.group(1))] = int(m.group(2))
                continue

            m = dilexical_re.match(line)
            if m:
                discope[int(m.group(1))] = int(m.group(2))
                continue

            m = diloc_re.match(line)
            if m:
                dilocs.append((
                    int(m.group(1)), int(m.group(2)),
                    int(m.group(3)), int(m.group(4))
                ))
                continue

            # Branch instruction with !dbg reference
            if BRANCH_OPS.match(line):
                dm = dbg_ref_re.search(line)
                if dm:
                    branch_dbg_nums.add(int(dm.group(1)))

    def resolve_file(scope_id, depth=0):
        if depth > 30:
            return None
        if scope_id in disubprog:
            return difile.get(disubprog[scope_id])
        if scope_id in discope:
            return resolve_file(discope[scope_id], depth + 1)
        return None

    loc_to_dbg_all = defaultdict(list)
    loc_to_dbg_br  = defaultdict(list)
    dbg_to_locs    = defaultdict(list)
    all_llvm_branches = []

    for dbg_num, lineno, col, scope_id in dilocs:
        filename = resolve_file(scope_id)
        if not filename:
            continue
        basename = filename.split('/')[-1]
        key = (basename, lineno, col)

        loc_to_dbg_all[key].append(dbg_num)
        dbg_to_locs[dbg_num].append(key)

        if dbg_num in branch_dbg_nums:
            loc_to_dbg_br[key].append(dbg_num)
            all_llvm_branches.append((dbg_num, basename, lineno, col))

    print(f"[*] Found {len(branch_dbg_nums)} branch !dbg references", file=sys.stderr)
    print(f"[*] Resolved {len(loc_to_dbg_br)} unique branch source locations",
          file=sys.stderr)

    return (branch_dbg_nums, loc_to_dbg_all, loc_to_dbg_br,
            dbg_to_locs, all_llvm_branches)


# ---------------------------------------------------------------------------
# Step 4: Join PC locations to dbg numbers, preferring branch dbgs
# ---------------------------------------------------------------------------

def build_map(pc_to_locs, loc_to_dbg_all, loc_to_dbg_br):
    """
    For each PC:
      1. Try loc_to_dbg_br  (only dbg nums on actual branch instructions)
      2. Fall back to loc_to_dbg_all if no branch dbg found at that location
      3. If still multiple, map to all and record as ambiguous

    Returns:
        dbg_to_pcs   : dbg_num -> set of PCs
        pc_ambiguous : pc -> [candidate dbg_nums]
        pc_unmatched : set of PCs with no .ll match
    """
    dbg_to_pcs   = defaultdict(set)
    pc_ambiguous = {}
    pc_unmatched = set()

    for pc, locs in pc_to_locs.items():
        matched = False
        for filename, lineno, col, func in locs:
            basename = filename.split('/')[-1]
            key = (basename, lineno, col)

            candidates = loc_to_dbg_br.get(key, [])
            if not candidates:
                candidates = loc_to_dbg_all.get(key, [])

            if not candidates:
                continue

            matched = True
            if len(candidates) == 1:
                dbg_to_pcs[candidates[0]].add(pc)
            else:
                pc_ambiguous[pc] = candidates
                for c in candidates:
                    dbg_to_pcs[c].add(pc)

        if not matched:
            pc_unmatched.add(pc)

    return dbg_to_pcs, pc_ambiguous, pc_unmatched


# ---------------------------------------------------------------------------
# Step 5: Report unmatched LLVM branches
# ---------------------------------------------------------------------------

def report_unmatched_llvm(all_llvm_branches, dbg_to_pcs):
    unmatched = [
        (dbg, f, l, c) for (dbg, f, l, c) in all_llvm_branches
        if dbg not in dbg_to_pcs
    ]
    total = len(all_llvm_branches)
    print(f"\n[*] LLVM branch coverage:", file=sys.stderr)
    print(f"    Total IR branches:          {total}", file=sys.stderr)
    print(f"    Matched to TAGE PC:         {total - len(unmatched)}", file=sys.stderr)
    print(f"    Unmatched (no TAGE entry):  {len(unmatched)}", file=sys.stderr)

    if unmatched:
        print(f"\n    Unmatched branch breakdown:", file=sys.stderr)
        print(f"    Likely causes:", file=sys.stderr)
        print(f"      (a) Branch never executed at runtime (TAGE only sees live branches)",
              file=sys.stderr)
        print(f"      (b) Branch optimized/merged into another instruction by backend",
              file=sys.stderr)
        print(f"      (c) Inlining caused the PC to appear at a different source location",
              file=sys.stderr)
        print(f"\n    {'DBG':>8}  {'File':<25}  {'Line':>6}  {'Col':>5}", file=sys.stderr)
        print(f"    {'-'*55}", file=sys.stderr)
        for dbg, f, l, c in sorted(unmatched, key=lambda x: (x[1], x[2])):
            print(f"    !{dbg:>7}  {f:<25}  {l:>6}  {c:>5}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Step 6: Write map file
# ---------------------------------------------------------------------------

def write_map(dbg_to_pcs, output_path):
    with open(output_path, 'w') as f:
        for dbg_num in sorted(dbg_to_pcs):
            pcs = ' '.join(sorted(dbg_to_pcs[dbg_num]))
            f.write(f"{dbg_num} {pcs}\n")
    print(f"\n[*] Wrote {len(dbg_to_pcs)} entries to {output_path}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Generate !dbg->PC map, disambiguating using branch instructions in .ll'
    )
    parser.add_argument('--tage',      required=True, help='Path to tage.anal')
    parser.add_argument('--ll',        required=True, help='Path to linked .ll file')
    parser.add_argument('--binary',    required=True, help='Path to binary (compiled with -g)')
    parser.add_argument('--llvm-bin',  required=True,
                        help='LLVM bin directory containing llvm-symbolizer')
    parser.add_argument('--output',    default='dbg_pc.map', help='Output map file')
    parser.add_argument('--ambiguous', default='ambiguous.txt',
                        help='File to write remaining ambiguous PC->dbg mappings')
    args = parser.parse_args()

    pcs        = extract_tage_pcs(args.tage)
    pc_to_locs = symbolize_pcs(pcs, args.binary, args.llvm_bin)

    (branch_dbg_nums, loc_to_dbg_all,
     loc_to_dbg_br, dbg_to_locs,
     all_llvm_branches) = parse_ll_file(args.ll)

    dbg_to_pcs, pc_ambiguous, pc_unmatched = build_map(
        pc_to_locs, loc_to_dbg_all, loc_to_dbg_br
    )

    report_unmatched_llvm(all_llvm_branches, dbg_to_pcs)

    if pc_ambiguous:
        print(f"\n[*] Remaining ambiguous PCs after branch filter: {len(pc_ambiguous)}",
              file=sys.stderr)
        print(f"    (These matched multiple branch !dbg nums at same source location)",
              file=sys.stderr)
        with open(args.ambiguous, 'w') as f:
            f.write("# pc -> candidate dbg numbers (all retained in map)\n\n")
            for pc, candidates in sorted(pc_ambiguous.items()):
                f.write(f"{pc}  ->  {' '.join(str(c) for c in candidates)}\n")
        print(f"    Written to {args.ambiguous}", file=sys.stderr)

    print(f"[*] PCs with no .ll match at all: {len(pc_unmatched)}", file=sys.stderr)

    write_map(dbg_to_pcs, args.output)


if __name__ == '__main__':
    main()
