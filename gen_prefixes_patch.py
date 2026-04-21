#!/usr/bin/env python3
"""
gen_prefix_patch_llvm.py

Generates a CSV of (nop_pc, prefix_byte) pairs for patching NOP placeholders
inserted before branch instructions. The prefix byte is determined purely from
the LLVM static analysis (H value / predicted bank) with no TAGE data required.

Inputs:
    - llvm.anal        : output of your LLVM branch analysis script
    - one or more .bc  : post-LTO .bc files (e.g. *.5.precodegen.bc)
                         these are disassembled inline via llvm-dis,
                         no intermediate .ll files are written to disk
    - binary           : compiled binary with -g (for llvm-symbolizer)
    - asm              : objdump disassembly (to locate NOPs before branches)

The NOP immediately before a branch is at PC = branch_pc - NOP_SIZE.

Usage:
    python3 gen_prefix_patch_llvm.py \
        --llvm-anal  llvm.anal \
        --bc         *.5.precodegen.bc \
        --binary     mcf_r \
        --asm        mcf_r.asm \
        --llvm-bin   /home/eddiet/interplay/tageCS/build/bin \
        --output     patches.csv
"""

import re
import sys
import csv
import argparse
import subprocess
import random
from collections import defaultdict

# ---------------------------------------------------------------------------
# CUSTOMIZABLE BANK -> PREFIX BYTE MAPPING
# Index corresponds to TAGE bank number (0 = bimodal, 1-7 = tagged banks)
# The H value from llvm.anal maps to a bank via H_TO_BANK below.
# Edit these 8 bytes to whatever prefix values you want to emit.
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

# Maps H value string from llvm.anal to bank index
H_TO_BANK = {
    'bimodal': 0,
    '5':       1,
    '9':       2,
    '15':      3,
    '26':      4,
    '44':      5,
    '76':      6,
    '130':     7,
}

# Size in bytes of the NOP inserted before each branch
NOP_SIZE = 1

# ---------------------------------------------------------------------------
# Step 1: Parse llvm.anal
# ---------------------------------------------------------------------------

def parse_llvm_anal(llvm_anal_path):
    """
    Parse llvm.anal and return:
        dbg_to_h: dbg_num (int) -> H value string (e.g. '130', 'bimodal')
        dbg_to_info: dbg_num -> {function, node, H, explanation}

    Handles entries with — (no dbg) by skipping them.
    """
    header_re = re.compile(
        r'^(?P<func>[^:]+)::(?P<node>\S+)\s*\|\s*'
        r'(?P<dbg>!dbg\s+!\d+|—)\s*\|\s*'
        r'(?P<h>\S+)\s*\|\s*(?P<expl>.+)$'
    )

    dbg_to_h    = {}
    dbg_to_info = {}

    with open(llvm_anal_path) as f:
        for line in f:
            line = line.rstrip()
            m = header_re.match(line)
            if not m:
                continue
            dbg_raw = m.group('dbg').strip()
            if dbg_raw == '—':
                continue
            dbg_num = int(re.search(r'\d+', dbg_raw).group())
            h       = m.group('h').strip()
            dbg_to_h[dbg_num]    = h
            dbg_to_info[dbg_num] = {
                'function':    m.group('func').strip().lstrip('.'),
                'node':        m.group('node').strip(),
                'H':           h,
                'explanation': m.group('expl').strip(),
            }

    print(f"[*] Parsed {len(dbg_to_h)} branches from llvm.anal", file=sys.stderr)
    return dbg_to_h, dbg_to_info


# ---------------------------------------------------------------------------
# Step 2: Parse .ll file for branch !dbg metadata
# ---------------------------------------------------------------------------

BRANCH_OPS = re.compile(
    r'^\s*(br\b|switch\b|indirectbr\b|invoke\b|callbr\b)'
)

# Compiled metadata regexes reused across all bc files
_DILOC_RE     = re.compile(
    r'^!(\d+)\s*=\s*!DILocation\(line:\s*(\d+),\s*column:\s*(\d+),\s*scope:\s*!(\d+)'
)
_DISUBPROG_RE = re.compile(
    r'^!(\d+)\s*=\s*(?:distinct\s+)?!DISubprogram\(.*?file:\s*!(\d+)'
)
_DIFILE_RE    = re.compile(
    r'^!(\d+)\s*=\s*!DIFile\(filename:\s*"([^"]+)"'
)
_DILEXICAL_RE = re.compile(
    r'^!(\d+)\s*=\s*(?:distinct\s+)?!DILexicalBlock[^(]*\(.*?scope:\s*!(\d+)'
)
_DBG_REF_RE   = re.compile(r',\s*!dbg\s*!(\d+)')


def _parse_ll_lines(lines, loc_to_dbg_all, loc_to_dbg_br, branch_dbg_nums):
    """
    Parse lines of LLVM IR text (from a single module) and accumulate
    metadata into the shared dicts. Handles per-module node ID namespacing
    by treating each module independently — the join key is always
    (basename, line, col) not the node ID, so cross-module ID collisions
    don't matter.
    """
    difile    = {}
    discope   = {}
    disubprog = {}
    dilocs    = []
    local_branch_dbgs = set()

    for raw in lines:
        line = raw.rstrip()

        m = _DIFILE_RE.match(line)
        if m:
            difile[int(m.group(1))] = m.group(2)
            continue

        m = _DISUBPROG_RE.match(line)
        if m:
            disubprog[int(m.group(1))] = int(m.group(2))
            continue

        m = _DILEXICAL_RE.match(line)
        if m:
            discope[int(m.group(1))] = int(m.group(2))
            continue

        m = _DILOC_RE.match(line)
        if m:
            dilocs.append((
                int(m.group(1)), int(m.group(2)),
                int(m.group(3)), int(m.group(4))
            ))
            continue

        if BRANCH_OPS.match(line):
            dm = _DBG_REF_RE.search(line)
            if dm:
                local_branch_dbgs.add(int(dm.group(1)))

    def resolve_file(scope_id, depth=0):
        if depth > 30:
            return None
        if scope_id in disubprog:
            return difile.get(disubprog[scope_id])
        if scope_id in discope:
            return resolve_file(discope[scope_id], depth + 1)
        return None

    for dbg_num, lineno, col, scope_id in dilocs:
        filename = resolve_file(scope_id)
        if not filename:
            continue
        basename = filename.split('/')[-1]
        key = (basename, lineno, col)
        loc_to_dbg_all[key].append(dbg_num)
        if dbg_num in local_branch_dbgs:
            loc_to_dbg_br[key].append(dbg_num)
            branch_dbg_nums.add(dbg_num)


def parse_bc_files(bc_paths, llvm_bin):
    """
    Disassemble each .bc file inline using llvm-dis (no files written to disk)
    and accumulate metadata across all modules.

    Returns:
        branch_dbg_nums : set of dbg nums on branch instructions (across all modules)
        loc_to_dbg_br   : (basename, line, col) -> [dbg_num, ...]  branch-only
        loc_to_dbg_all  : (basename, line, col) -> [dbg_num, ...]  all metadata
    """
    llvm_dis = f"{llvm_bin}/llvm-dis"

    loc_to_dbg_all  = defaultdict(list)
    loc_to_dbg_br   = defaultdict(list)
    branch_dbg_nums = set()

    total_branches = 0

    for bc_path in bc_paths:
        print(f"[*] Disassembling {bc_path} ...", file=sys.stderr)
        try:
            result = subprocess.run(
                [llvm_dis, bc_path, '-o', '-'],
                capture_output=True, text=True, timeout=120
            )
        except FileNotFoundError:
            print(f"[!] llvm-dis not found at {llvm_dis}", file=sys.stderr)
            sys.exit(1)

        if result.returncode != 0:
            print(f"[!] llvm-dis failed on {bc_path}: {result.stderr[:200]}",
                  file=sys.stderr)
            continue

        before = len(branch_dbg_nums)
        _parse_ll_lines(
            result.stdout.splitlines(),
            loc_to_dbg_all, loc_to_dbg_br, branch_dbg_nums
        )
        added = len(branch_dbg_nums) - before
        total_branches += added
        print(f"    +{added} branch dbg refs", file=sys.stderr)

    print(f"[*] Total branch !dbg refs across all modules: {len(branch_dbg_nums)}",
          file=sys.stderr)
    print(f"[*] Unique branch source locations: {len(loc_to_dbg_br)}",
          file=sys.stderr)
    return branch_dbg_nums, loc_to_dbg_br, loc_to_dbg_all


# ---------------------------------------------------------------------------
# Step 3: Parse assembly for branch and NOP PCs
# ---------------------------------------------------------------------------

def parse_asm(asm_path):
    """
    Returns:
        branch_pcs : set of PC strings (hex, lowercase)
        nop_pcs    : set of PC strings for NOP instructions
        pc_to_mnemonic : pc -> mnemonic string
    """
    branch_re = re.compile(
        r'^\s*([0-9a-fA-F]+):\s+'
        r'(?:[0-9a-fA-F]{2}\s+)*'
        r'(j[a-z]+|call|callq|jmp|jmpq)\s'
    )
    branch_re_nobytes = re.compile(
        r'^\s*([0-9a-fA-F]+):\s+'
        r'(j[a-z]+|call|callq|jmp|jmpq)\s'
    )
    nop_re = re.compile(
        r'^\s*([0-9a-fA-F]+):\s+'
        r'(?:[0-9a-fA-F]{2}\s+)*'
        r'nop\b'
    )

    branch_pcs     = set()
    nop_pcs        = set()
    pc_to_mnemonic = {}

    with open(asm_path) as f:
        for line in f:
            m = branch_re.match(line) or branch_re_nobytes.match(line)
            if m:
                pc = m.group(1).lower()
                branch_pcs.add(pc)
                pc_to_mnemonic[pc] = m.group(2).lower()
                continue
            m = nop_re.match(line)
            if m:
                nop_pcs.add(m.group(1).lower())

    print(f"[*] Found {len(branch_pcs)} branches and {len(nop_pcs)} NOPs in asm",
          file=sys.stderr)
    return branch_pcs, nop_pcs, pc_to_mnemonic


# ---------------------------------------------------------------------------
# Step 4: Symbolize branch PCs
# ---------------------------------------------------------------------------

def symbolize_pcs(pcs, binary, llvm_bin):
    symbolizer = f"{llvm_bin}/llvm-symbolizer"
    pc_to_locs = defaultdict(list)
    addr_list  = sorted(pcs)
    input_str  = '\n'.join(f"0x{pc}" for pc in addr_list)

    cmd = [symbolizer, f"--exe={binary}", "--output-style=GNU", "--inlines"]
    print(f"[*] Running llvm-symbolizer on {len(addr_list)} branch PCs...",
          file=sys.stderr)

    try:
        result = subprocess.run(
            cmd, input=input_str, capture_output=True, text=True, timeout=300
        )
    except FileNotFoundError:
        print(f"[!] llvm-symbolizer not found at {symbolizer}", file=sys.stderr)
        sys.exit(1)

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
                    pc = addr_list[pc_idx].lower()
                    pc_to_locs[pc].append((
                        parts[0], int(parts[1]), int(parts[2]), func
                    ))
                except ValueError:
                    pass

    # Fallback
    if not pc_to_locs:
        print("[*] Batch parse failed, falling back to one-at-a-time...", file=sys.stderr)
        for pc in addr_list:
            try:
                r = subprocess.run(
                    [symbolizer, f"--exe={binary}", f"0x{pc}"],
                    capture_output=True, text=True, timeout=10
                )
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

    print(f"[*] Symbolized {len(pc_to_locs)} branch PCs", file=sys.stderr)
    return pc_to_locs


# ---------------------------------------------------------------------------
# Step 5: Join everything and build patch table
# ---------------------------------------------------------------------------

def pc_minus(pc_hex, offset):
    val = int(pc_hex, 16) - offset
    return format(val, f'0{len(pc_hex)}x')


def build_patch_table(branch_pcs, pc_to_locs, loc_to_dbg_br, loc_to_dbg_all,
                      dbg_to_h, dbg_to_info, nop_pcs, pc_to_mnemonic):
    """
    For each branch PC:
      1. Symbolize to (file, line, col)
      2. Look up dbg number from .ll (branch-first, then any)
      3. Look up H value from llvm.anal via dbg number
      4. Map H -> bank -> prefix byte
      5. Compute nop_pc = branch_pc - NOP_SIZE
      6. Validate NOP exists in asm
    """
    rows = []
    baseline_rows = []
    rand_rows = []
    seen = set()

    stats = defaultdict(int)

    for pc in sorted(branch_pcs):
        if pc in seen:
            continue
        seen.add(pc)

        locs = pc_to_locs.get(pc, [])
        nop_pc   = pc_minus(pc, NOP_SIZE)
        valid_nop = nop_pc in nop_pcs
        mnemonic  = pc_to_mnemonic.get(pc, '?')

        matched_dbg  = None
        matched_h    = None
        matched_bank = None
        prefix_byte  = None
        note         = 'no_symbolizer_result'
        func_name    = '?'

        for filename, lineno, col, func in locs:
            basename = filename.split('/')[-1]
            key = (basename, lineno, col)
            func_name = func

            # Prefer branch-tagged dbg nums, fall back to all
            candidates = loc_to_dbg_br.get(key, []) or loc_to_dbg_all.get(key, [])
            if not candidates:
                note = 'no_ll_match'
                continue

            # Among candidates, prefer those that appear in llvm.anal
            anal_candidates = [c for c in candidates if c in dbg_to_h]
            chosen = anal_candidates[0] if anal_candidates else candidates[0]

            matched_dbg = chosen
            matched_h   = dbg_to_h.get(chosen)

            if matched_h is None:
                note = 'dbg_not_in_llvm_anal'
                break

            matched_bank = H_TO_BANK.get(str(matched_h))
            if matched_bank is None:
                print(matched_h)
                note = f'unknown_H_value_{matched_h}'
                break

            prefix_byte = BANK_TO_BYTE[matched_bank]
            note = 'ok' if valid_nop else 'nop_not_found_in_asm'
            break

        stats[note] += 1

        if valid_nop:
            rows.append({
                'nop_pc':      f'0x{nop_pc}',
                'prefix_byte': f'0x{prefix_byte:02x}' if prefix_byte is not None else '0x{BANK_TO_BYTE[0]:02x}'
            })
            baseline_rows.append({
                'nop_pc':      f'0x{nop_pc}',
                'prefix_byte': f'0x{BANK_TO_BYTE[0]:02x}'
            })
            rand_rows.append({
                'nop_pc':      f'0x{nop_pc}',
                'prefix_byte': f'0x{BANK_TO_BYTE[random.randint(0,7)]:02x}'
            })

    print(f"\n[*] Patch table summary:", file=sys.stderr)
    for k, v in sorted(stats.items()):
        print(f"    {k:<35}: {v}", file=sys.stderr)

    return rows, baseline_rows, rand_rows


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_csv(rows, output_path, clean_only=False):
    if clean_only:
        rows = [r for r in rows if r['note'] == 'ok']

    fieldnames = [
        'nop_pc', 'prefix_byte'
    ]

    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in sorted(rows, key=lambda r: r['nop_pc']):
            writer.writerow(row)

    print(f"[*] Wrote {len(rows)} rows to {output_path}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Generate NOP prefix patch CSV from LLVM IR analysis (no TAGE required)'
    )
    parser.add_argument('--llvm-anal', required=True, help='Path to llvm.anal')
    parser.add_argument('--bc',        required=True, nargs='+',
                        help='One or more .bc files (e.g. *.5.precodegen.bc). '
                             'Disassembled inline via llvm-dis, no .ll files written.')
    parser.add_argument('--binary',    required=True, help='Path to binary (with -g)')
    parser.add_argument('--asm',       required=True, help='objdump disassembly')
    parser.add_argument('--llvm-bin',  required=True,
                        help='LLVM bin dir containing llvm-symbolizer and llvm-dis')
    parser.add_argument('--output',    default='patches.csv',
                        help='Output CSV (default: patches.csv)')
    parser.add_argument('--clean-only', action='store_true',
                        help='Only output rows with note==ok')
    parser.add_argument('--nop-size', type=int, default=NOP_SIZE,
                        help=f'NOP size in bytes (default: {NOP_SIZE})')
    args = parser.parse_args()

    print(f"[*] Active BANK_TO_BYTE mapping:", file=sys.stderr)
    for i, b in enumerate(BANK_TO_BYTE):
        label = 'bimodal' if i == 0 else f'H={list(H_TO_BANK.keys())[i]}'
        print(f"    bank {i} ({label:<12}): 0x{b:02x}", file=sys.stderr)
    print(f"[*] NOP_SIZE: {NOP_SIZE} byte(s)", file=sys.stderr)
    print(f"[*] BC files: {len(args.bc)}\n", file=sys.stderr)

    dbg_to_h, dbg_to_info               = parse_llvm_anal(args.llvm_anal)
    branch_dbg_nums, loc_to_dbg_br, \
        loc_to_dbg_all                   = parse_bc_files(args.bc, args.llvm_bin)
    branch_pcs, nop_pcs, pc_to_mnemonic = parse_asm(args.asm)
    pc_to_locs                           = symbolize_pcs(branch_pcs, args.binary,
                                                          args.llvm_bin)

    rows, baseline_rows, rand_rows = build_patch_table(
        branch_pcs, pc_to_locs,
        loc_to_dbg_br, loc_to_dbg_all,
        dbg_to_h, dbg_to_info,
        nop_pcs, pc_to_mnemonic
    )

    write_csv(rows, args.output, clean_only=args.clean_only)
    write_csv(baseline_rows, 'baseline_'+args.output, clean_only=args.clean_only)
    write_csv(rand_rows, 'rand_'+args.output, clean_only=args.clean_only)


if __name__ == '__main__':
    main()
