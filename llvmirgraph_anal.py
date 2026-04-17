#!/usr/bin/env python3
"""
Branch History Length Predictor
--------------------------------
Analyzes LLVM DOT graph dumps (CFG, DDG, dominator tree, post-dominator tree,
call graph) and predicts the ideal TAGE history length for each branch.

The emphasis of this tool is on TRANSPARENCY: every signal that contributes
to a prediction is shown explicitly so you can audit, tune, and validate the
heuristics against ground truth misprediction data.

Generating the DOT files:
    opt -passes="dot-cfg"  input.ll -o /dev/null   # produces cfg.funcname.dot
    opt -passes="dot-ddg"                                     input.ll -o /dev/null
    opt -passes="dot-dom"                                     input.ll -o /dev/null
    opt -passes="dot-postdom"                                 input.ll -o /dev/null
    opt -passes="dot-callgraph"                               input.ll -o /dev/null

Usage:
    python branch_history_predictor.py [options]

Options:
    --cfg-dir DIR         Directory containing CFG DOT files          (default: .)
    --ddg-dir DIR         Directory containing DDG DOT files          (default: .)
    --dom-dir DIR         Directory containing dominator DOT files    (default: .)
    --postdom-dir DIR     Directory containing post-dom DOT files     (default: .)
    --callgraph-dir DIR   Directory containing call graph DOT file    (default: .)
    --output FILE         Write results to FILE instead of stdout
    --format FORMAT       table | detail | json | csv                 (default: detail)
    --verbose             Print debug/progress information
"""

import os
import re
import sys
import json
import glob
import math
import argparse
from collections import defaultdict, Counter
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

try:
    import networkx as nx
    from networkx.drawing.nx_pydot import read_dot
except ImportError:
    print("ERROR: Required packages missing.  pip install networkx pydot")
    sys.exit(1)

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False


# ---------------------------------------------------------------------------
# gem5 TAGEBase configuration (src/cpu/pred/BranchPredictor.py)
# ---------------------------------------------------------------------------
# TAGEBase defaults:
#   nHistoryTables = 7
#   minHist        = 5
#   maxHist        = 130
#   logTagTableSizes = [13, 9, 9, 9, 9, 9, 9, 9]   (index 0 = bimodal)
#   tagTableTagWidths = [0, 9, 9, 10, 10, 11, 11, 12]
#
# History lengths are computed geometrically inside TAGEBase::init():
#   histLengths[i] = minHist * (maxHist/minHist)^((i-1)/(nTables-1))  rounded
# Computed values for the default config:
TAGE_N_TABLES      = 7
TAGE_MIN_HIST      = 5
TAGE_MAX_HIST      = 130

# Actual geometric series (table index 1..7):
TAGE_HISTORY_LENGTHS = [5, 9, 15, 26, 44, 76, 130]

# Log2 of each tagged table size (entries = 2^logSize).
# Index 0 unused (bimodal), indices 1-7 correspond to TAGE_HISTORY_LENGTHS.
TAGE_LOG_TABLE_SIZES = [13, 9, 9, 9, 9, 9, 9, 9]

# Tag widths per table (bits).
TAGE_TAG_WIDTHS = [0, 9, 9, 10, 10, 11, 11, 12]

# instShiftAmt: how many bits the PC is right-shifted before hashing.
TAGE_INST_SHIFT = 2

# Bimodal table parameters (no GHR involvement).
# bindex(pc) = (pc >> instShiftAmt) & ((1 << logSizeBiMP) - 1)
# logSizeBiMP default = 13 -> 8192 entries, shared 2:1 with hysteresis bits
TAGE_LOG_BIMODAL_SIZE = 13

# Full history length list including bimodal (history=0).
# Index 0 = bimodal, indices 1-7 = tagged tables.
TAGE_ALL_LENGTHS = [0] + TAGE_HISTORY_LENGTHS


def _gem5_compute_hist_lengths(n_tables: int, min_hist: int, max_hist: int) -> list:
    """Reproduce gem5 TAGEBase::calculateParameters() geometric series."""
    lengths = [0] * (n_tables + 1)  # index 0 unused
    for i in range(1, n_tables + 1):
        lengths[i] = int(min_hist * ((max_hist / min_hist) **
                         ((i - 1) / (n_tables - 1))) + 0.5)
    return lengths


# Verify / override with exact computed values
_computed = _gem5_compute_hist_lengths(TAGE_N_TABLES, TAGE_MIN_HIST, TAGE_MAX_HIST)
TAGE_HISTORY_LENGTHS = _computed[1:]   # strip unused index-0


# ---------------------------------------------------------------------------
# gem5 TAGEBase hash functions  (tage_base.cc)
# ---------------------------------------------------------------------------
# F(A, size, M): fold a value A of `size` bits into M bits by XOR-ing
# successive M-bit chunks.  This is the FoldedHistory::update() logic.
def _F(A: int, size: int, M: int) -> int:
    A = A & ((1 << size) - 1)
    result = 0
    while size > 0:
        result ^= A & ((1 << M) - 1)
        A >>= M
        size -= M
    return result & ((1 << M) - 1)


def gem5_gindex(pc: int, comp_index: int, hist_len: int, log_table_size: int) -> int:
    """
    Compute the tagged-table index for a branch.

    gem5 tage_base.cc gindex():
        index  = pc >> instShiftAmt
        index ^= (pc >> instShiftAmt) >> logTableSize
        index ^= ci                        (compressed index = folded GHR)
        index ^= F(ci, histLen, logTableSize)
        index  &= (tableSize - 1)

    We approximate ci (compressed index) as F(GHR_pattern, hist_len, log_table_size).
    For static alias analysis we work with *symbolic* GHR patterns, so we pass
    comp_index directly.
    """
    shifted_pc = (pc >> TAGE_INST_SHIFT) & 0xFFFFFFFF
    index = shifted_pc
    index ^= shifted_pc >> log_table_size
    index ^= comp_index
    index ^= _F(comp_index, hist_len, log_table_size)
    return index & ((1 << log_table_size) - 1)


def gem5_gtag(pc: int, comp_tag0: int, comp_tag1: int, tag_width: int) -> int:
    """
    Compute the partial tag for a tagged table entry.

    gem5 tage_base.cc gtag():
        tag = pc >> instShiftAmt
        tag ^= ct0                         (compressed tag 0)
        tag ^= ct1 << 1                    (compressed tag 1, shifted)
        tag &= (1 << tagWidth) - 1
    """
    shifted_pc = (pc >> TAGE_INST_SHIFT) & 0xFFFFFFFF
    tag = shifted_pc ^ comp_tag0 ^ (comp_tag1 << 1)
    return tag & ((1 << tag_width) - 1)


def gem5_bindex(pc: int) -> int:
    """
    Compute the bimodal table index for a branch.

    gem5 tage_base.cc bindex():
        return (pc >> instShiftAmt) & ((1 << logSizeBiMP) - 1)

    No GHR involvement — purely PC-based.
    """
    return (pc >> TAGE_INST_SHIFT) & ((1 << TAGE_LOG_BIMODAL_SIZE) - 1)


def snap_to_tage(raw: float) -> int:
    """
    Round a raw history estimate UP to the nearest gem5 TAGEBase table length.
    A score of 0 maps to the bimodal (history length 0).
    """
    for h in TAGE_ALL_LENGTHS:
        if raw <= h:
            return h
    return TAGE_HISTORY_LENGTHS[-1]


def table_index_for_length(h: int) -> int:
    """
    Return the TAGE table index for a given history length.
    Returns 0 for the bimodal (h=0), 1-7 for tagged tables.
    """
    for i, tl in enumerate(TAGE_ALL_LENGTHS):
        if h <= tl:
            return i   # 0 = bimodal, 1..7 = tagged tables
    return len(TAGE_HISTORY_LENGTHS)

# ---------------------------------------------------------------------------
# Scoring weights — all named constants so they're easy to tune
# ---------------------------------------------------------------------------

# How many raw history bits each loop nesting level contributes.
# Intuition: one loop level means the branch outcome repeats over a period
# proportional to the loop trip count; ~4 bits captures simple loops.
W_LOOP_DEPTH          = 4.0

# Each level of loop nesting also shortens the effective back-edge distance,
# so we add a small bonus per unit of closeness to the loop header.
W_BACK_EDGE_PROXIMITY = 0.5   # multiplied by (1 / (back_edge_dist + 1))

# Longest def-use chain upstream of the branch in the DDG.
# Captures branches whose outcome depends on values computed far upstream.
W_DDU_DEPTH           = 1.0

# Depth of branch node in the dominator tree.
# Deeper = more prior conditional context has executed = more history is
# potentially useful.  Noisy signal so discounted.
W_DOM_DEPTH           = 0.5

# Distance from branch to its immediate post-dominator.
# Long shadow = this branch's outcome affects many subsequent instructions.
# Cleaner signal than dom depth so weighted slightly higher.
W_POSTDOM_DISTANCE    = 0.75

# log2(call-site fan-in): a function called from N call sites needs enough
# GHR bits to distinguish those N contexts.
W_CALL_FANIN          = 1.0

# Call depth (longest path from program root to this function in call graph).
# Deep call chains consume GHR bits on call/return overhead; branches deep
# in the stack need longer history to see useful correlation.
W_CALL_DEPTH          = 0.5

# Recursive functions produce periodic GHR patterns; we add a floor equal to
# the estimated recursion period (call graph SCC size * base factor).
W_RECURSION           = 2.0

# Bimodal candidacy: a branch is a bimodal candidate if its static bias
# exceeds this threshold.  At 0.85 the strongly-biased counter will absorb
# most destructive aliases without flipping, so history adds little value.
BIMODAL_BIAS_THRESHOLD = 0.85


# ---------------------------------------------------------------------------
# Ablation configuration
# ---------------------------------------------------------------------------

@dataclass
class AblationConfig:
    """
    Controls which analysis steps are active.
    Structural signals (loop/DDU/dom/postdom/call) are always on.
    Each of the three optional steps can be disabled independently
    for ablation studies.
    """
    destructive_alias: bool = True   # bump branches that have destructive PHT aliases
    constructive_alias: bool = True  # note branches that benefit from constructive aliases
    static_bias: bool = True         # bimodal candidacy via structural bias estimation

    def summary(self) -> str:
        steps = ["structural (always)"]
        if self.destructive_alias:  steps.append("destructive-alias")
        if self.constructive_alias: steps.append("constructive-alias")
        if self.static_bias:        steps.append("static-bias")
        return ", ".join(steps)


def snap_to_tage(raw: float) -> int:
    for h in TAGE_HISTORY_LENGTHS:
        if raw <= h:
            return h
    return TAGE_HISTORY_LENGTHS[-1]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SignalBreakdown:
    """
    Stores every intermediate value that feeds into the score for one branch.
    This is the audit trail — the output formatter prints all of this.
    """
    # Raw measurements
    loop_depth:          int   = 0
    back_edge_dist:      int   = 0   # edges from branch to nearest loop header
    ddu_depth:           int   = 0   # longest DDG path to branch node
    dom_depth:           int   = 0   # depth in dominator tree
    postdom_distance:    int   = 0   # distance to immediate post-dominator
    call_fanin:          int   = 0   # number of call sites to this function
    call_depth:          int   = 0   # longest call chain depth to this function
    is_recursive:        bool  = False
    recursion_scc_size:  int   = 0   # size of SCC containing this function
    static_bias:         float = 0.5 # structural bias estimate [0.5=balanced, 1.0=always taken]
    bimodal_candidate:   bool  = False  # True if bias makes bimodal viable regardless of history

    # Weighted contributions (raw_measurement × weight)
    contrib_loop:        float = 0.0
    contrib_back_edge:   float = 0.0
    contrib_ddu:         float = 0.0
    contrib_dom:         float = 0.0
    contrib_postdom:     float = 0.0
    contrib_call_fanin:  float = 0.0
    contrib_call_depth:  float = 0.0
    contrib_recursion:   float = 0.0

    # Which signal won (drove the max)
    dominant_signal:     str   = ""
    raw_score:           float = 0.0
    tage_length:         int   = 4

    # Which graphs were actually available for this branch
    graphs_used:         list  = field(default_factory=list)
    graphs_missing:      list  = field(default_factory=list)

    # Phase 3: aliasing results (filled in after initial scoring)
    alias_destructive:   int   = 0
    alias_constructive:  int   = 0
    alias_free_table:    int   = 0
    alias_note:          str   = ""
    # Final table after applying alias bump
    final_table:         int   = 0
    final_length:        int   = 0


@dataclass
class BranchInfo:
    branch_id:    str
    function:     str
    block:        str
    node_id:      str   = ""   # raw DOT node ID (e.g. Node0x9c4980640)
    dbg_location: str   = ""   # !dbg tag from terminator IR instruction
    signals:      SignalBreakdown = field(default_factory=SignalBreakdown)


# ---------------------------------------------------------------------------
# DOT loading
# ---------------------------------------------------------------------------

def _strip_port(node: str) -> str:
    """
    LLVM CFG DOT files use record-style port syntax: Node0xABCD:s0
    Strip the port suffix so edges are attributed to the base node.
    """
    return str(node).split(':')[0]


def _safe_read_dot(path: str, verbose: bool = False) -> Optional[nx.DiGraph]:
    try:
        g = read_dot(path)
        raw = nx.DiGraph(g)
        # Normalise port-qualified node IDs (Node0xABCD:s0 -> Node0xABCD)
        # LLVM uses record-style nodes so edges carry port suffixes which
        # make every base node appear to have out-degree 0.
        normalised = nx.DiGraph()
        for n, data in raw.nodes(data=True):
            normalised.add_node(_strip_port(n), **data)
        for u, v, data in raw.edges(data=True):
            su, sv = _strip_port(u), _strip_port(v)
            if su != sv:  # drop self-loops created by port collapsing
                normalised.add_edge(su, sv, **data)
        return normalised
    except Exception as e:
        if verbose:
            print(f"  [warn] Could not read {path}: {e}", file=sys.stderr)
        return None


def load_dot_dir(directory: str, patterns: list, verbose: bool) -> dict:
    graphs = {}
    for pat in patterns:
        for path in glob.glob(os.path.join(directory, pat)):
            stem = Path(path).stem
            if stem in graphs:
                continue
            g = _safe_read_dot(path, verbose)
            if g is not None:
                graphs[stem] = g
                if verbose:
                    print(f"  [load] {path}  "
                          f"({g.number_of_nodes()}n {g.number_of_edges()}e)",
                          file=sys.stderr)
    return graphs


# ---------------------------------------------------------------------------
# CFG analysis
# ---------------------------------------------------------------------------

def _is_branch(node, graph: nx.DiGraph) -> bool:
    return graph.out_degree(node) > 1


def _find_back_edges(graph: nx.DiGraph) -> set:
    back_edges = set()
    visited, stack = set(), set()
    sys.setrecursionlimit(max(sys.getrecursionlimit(), graph.number_of_nodes() * 4))

    def dfs(u):
        visited.add(u); stack.add(u)
        for v in graph.successors(u):
            if v not in visited:
                dfs(v)
            elif v in stack:
                back_edges.add((u, v))
        stack.discard(u)

    for n in graph.nodes():
        if n not in visited:
            dfs(n)
    return back_edges


def _loop_depths(graph: nx.DiGraph) -> dict:
    back_edges = _find_back_edges(graph)
    depth = defaultdict(int)
    rev = graph.reverse(copy=False)
    for (tail, header) in back_edges:
        try:
            body = nx.descendants(rev, tail) | {tail, header}
        except Exception:
            body = {tail, header}
        for n in body:
            depth[n] += 1
    return depth


def _extract_dbg_location(node, cfg: nx.DiGraph) -> str:
    """
    Extract the !dbg tag from the terminator instruction of a basic block.

    LLVM CFG DOT labels encode instructions separated by \\l.  The terminator
    (branch instruction) is the last non-empty line and typically ends with
    a !dbg annotation like:  br i1 %cmp, label %bb.4, label %bb.5, !dbg !123

    Returns a string like "!dbg !123" or "" if not found.
    """
    raw = cfg.nodes[node].get("label", "")
    # Unescape DOT record label: strip outer quotes/braces, split on \l
    raw = raw.strip('"').strip("{}")
    lines = [l.strip() for l in re.split(r'\\l', raw) if l.strip()]
    # Walk backwards to find the terminator (last line with a !dbg tag)
    for line in reversed(lines):
        m = re.search(r'(!dbg\s+!\d+)', line)
        if m:
            return m.group(1)
    return ""


def _static_bias(node, cfg: nx.DiGraph) -> float:
    """
    Estimate static branch bias from CFG structure.

    A branch is considered biased if one successor dominates the reachable
    subgraph much more than the other.  We approximate this by comparing
    the number of nodes reachable from each successor — a taken edge leading
    to a large subgraph vs a not-taken edge to a small one suggests bias.

    Returns a value in [0.5, 1.0] where 1.0 = perfectly biased (one path
    always taken), 0.5 = perfectly balanced.

    This is a structural heuristic only.  Profile data would give exact bias.
    """
    succs = list(cfg.successors(node))
    if len(succs) != 2:
        return 0.5   # not a simple conditional branch

    # Count nodes reachable from each successor (proxy for path weight)
    try:
        r0 = len(nx.descendants(cfg, succs[0])) + 1
        r1 = len(nx.descendants(cfg, succs[1])) + 1
    except Exception:
        return 0.5

    total = r0 + r1
    if total == 0:
        return 0.5
    dominant = max(r0, r1)
    return dominant / total


def analyze_cfg(cfg: nx.DiGraph) -> dict:
    """
    Returns {node: {loop_depth, back_edge_dist, static_bias}} for every
    branch node.
    """
    depths     = _loop_depths(cfg)
    back_edges = _find_back_edges(cfg)
    headers    = {v for (_, v) in back_edges}
    rev        = cfg.reverse(copy=False)
    results    = {}

    for node in cfg.nodes():
        if not _is_branch(node, cfg):
            continue
        ld = depths.get(node, 0)
        back_dist = 0
        if ld > 0:
            for dist, n in _bfs_depth(rev, node):
                if n in headers and n != node:
                    back_dist = dist
                    break
        results[node] = {
            "loop_depth":    ld,
            "back_edge_dist": back_dist,
            "static_bias":   _static_bias(node, cfg),
            "dbg_location":  _extract_dbg_location(node, cfg),
        }

    return results


def _bfs_depth(graph, start):
    visited = {start}
    queue   = [(0, start)]
    while queue:
        d, node = queue.pop(0)
        yield d, node
        for nb in graph.successors(node):
            if nb not in visited:
                visited.add(nb)
                queue.append((d + 1, nb))


# ---------------------------------------------------------------------------
# DDG analysis
# ---------------------------------------------------------------------------

def analyze_ddg(ddg: nx.DiGraph) -> dict:
    """
    Longest path (in edges) to every node via topological sort.
    Returns {node_label: depth}.
    """
    def label(n):
        return ddg.nodes[n].get("label", str(n)).strip('"').strip()

    try:
        order = list(nx.topological_sort(ddg))
    except nx.NetworkXUnfeasible:
        return {label(n): 1 for n in ddg.nodes()}

    dist = defaultdict(int)
    for n in order:
        for succ in ddg.successors(n):
            dist[succ] = max(dist[succ], dist[n] + 1)

    return {label(n): dist[n] for n in ddg.nodes()}


# ---------------------------------------------------------------------------
# Dominator tree analysis
# ---------------------------------------------------------------------------

def analyze_dom(dom: nx.DiGraph) -> dict:
    """Returns {node: depth} for all nodes in the dominator tree."""
    roots = [n for n in dom.nodes() if dom.in_degree(n) == 0]
    if not roots:
        return {}
    depths = {}
    for node in nx.bfs_tree(dom, roots[0]).nodes():
        try:
            depths[node] = len(nx.shortest_path(dom, roots[0], node)) - 1
        except nx.NetworkXNoPath:
            depths[node] = 0
    return depths


# ---------------------------------------------------------------------------
# Post-dominator tree analysis
# ---------------------------------------------------------------------------

def analyze_postdom(postdom: nx.DiGraph) -> dict:
    """
    Returns {node: post_dom_distance}.

    In a post-dominator tree the root is the exit node.  The depth of a node
    from the root is how many 'reconvergence steps' are between it and the
    exit — i.e. the length of its forward shadow in the CFG.  A branch that
    post-dominates nothing except itself (very short shadow) gets depth 0;
    a branch deep in the post-dom tree has a long shadow and its outcome
    influences many subsequent blocks.
    """
    roots = [n for n in postdom.nodes() if postdom.in_degree(n) == 0]
    if not roots:
        return {}
    depths = {}
    for node in nx.bfs_tree(postdom, roots[0]).nodes():
        try:
            depths[node] = len(nx.shortest_path(postdom, roots[0], node)) - 1
        except nx.NetworkXNoPath:
            depths[node] = 0
    return depths


# ---------------------------------------------------------------------------
# Call graph analysis
# ---------------------------------------------------------------------------

def load_callgraph_dot(directory: str, verbose: bool) -> Optional[nx.DiGraph]:
    """
    Load the call graph produced by opt -passes="dot-callgraph".
    LLVM writes a single file named callgraph.dot in the working directory.
    Node labels are function names; edges are caller -> callee.
    Returns None if no call graph DOT file is found.
    """
    candidates = (glob.glob(os.path.join(directory, "callgraph.dot")) +
                  glob.glob(os.path.join(directory, "*callgraph*.dot")) +
                  glob.glob(os.path.join(directory, "call_graph*.dot")))
    if not candidates:
        if verbose:
            print(f"  [warn] No callgraph DOT found in {directory}", file=sys.stderr)
        return None

    path = candidates[0]
    g = _safe_read_dot(path, verbose)
    if g is None:
        return None

    if verbose:
        print(f"  [load] {path}  ({g.number_of_nodes()}n {g.number_of_edges()}e)",
              file=sys.stderr)

    # dot-callgraph stores function names in node label attributes.
    # Rebuild the graph keyed by function name rather than DOT node IDs
    # so that _match() can find functions by name later.
    named = nx.DiGraph()
    def fn_name(n):
        raw = g.nodes[n].get("label", str(n)).strip('"').strip()
        # LLVM callgraph labels are record-style: "{funcname}"
        # Extract the content between the braces rather than stripping them.
        m = re.search(r'\{([^}]+)\}', raw)
        if m:
            return m.group(1).strip()
        return raw

    for n in g.nodes():
        named.add_node(fn_name(n))
    for u, v in g.edges():
        named.add_edge(fn_name(u), fn_name(v))

    return named


def analyze_callgraph(cg: nx.DiGraph) -> dict:
    """
    Returns per-function dict with keys:
        fanin, call_depth, is_recursive, scc_size
    """
    if cg.number_of_nodes() == 0:
        return {}

    call_depth = defaultdict(int)
    try:
        for n in nx.topological_sort(cg):
            for succ in cg.successors(n):
                call_depth[succ] = max(call_depth[succ], call_depth[n] + 1)
    except nx.NetworkXUnfeasible:
        pass  # Recursive CG — depth stays at 0 for affected nodes

    node_scc = {}
    for scc in nx.strongly_connected_components(cg):
        for n in scc:
            node_scc[n] = scc

    results = {}
    for func in cg.nodes():
        scc = node_scc.get(func, {func})
        results[func] = {
            "fanin":        cg.in_degree(func),
            "call_depth":   call_depth.get(func, 0),
            "is_recursive": len(scc) > 1 or func in list(cg.successors(func)),
            "scc_size":     len(scc),
        }
    return results


# ---------------------------------------------------------------------------
# Phase 2 & 3: gem5 TAGEBase aliasing analysis
# ---------------------------------------------------------------------------

@dataclass
class AliasResult:
    """Per-branch aliasing analysis results."""
    # Table index (1-based) recommended by alias analysis (0 = no change)
    alias_min_table:    int   = 0
    # Raw number of destructive alias candidates found at current table
    destructive_count:  int   = 0
    constructive_count: int   = 0
    # Table index where aliasing becomes acceptably low
    alias_free_table:   int   = 0
    # Human-readable explanation
    alias_note:         str   = ""


def _symbolic_ghr_patterns(hist_len: int, n_samples: int = 16) -> list:
    """
    Generate a sample of symbolic GHR patterns of length hist_len.
    We use a simple LFSR-style sequence to get spread-out bit patterns
    rather than enumerating all 2^hist_len possibilities.
    """
    patterns = set()
    v = 0xACE1
    mask = (1 << hist_len) - 1
    for _ in range(n_samples * 4):
        v = ((v >> 1) ^ (-(v & 1) & 0xB400)) & 0xFFFF
        patterns.add(v & mask)
        if len(patterns) >= n_samples:
            break
    return list(patterns)


def _estimate_alias_probability(pc1: int, pc2: int,
                                 table_idx: int) -> float:
    """
    Estimate the probability that two branches collide in a given TAGE table.

    Table index 0 = bimodal: uses gem5 bindex() which is purely PC-based,
    so collision is deterministic (either they always alias or never do).

    Table index 1-7 = tagged tables: uses gem5 gindex() sampled over a range
    of GHR patterns.  Returns a value in [0, 1].
    """
    if table_idx == 0:
        # Bimodal: purely PC-based, no GHR — deterministic collision check
        return 1.0 if gem5_bindex(pc1) == gem5_bindex(pc2) else 0.0

    if table_idx < 1 or table_idx > len(TAGE_HISTORY_LENGTHS):
        return 0.0

    hist_len       = TAGE_HISTORY_LENGTHS[table_idx - 1]
    log_table_size = TAGE_LOG_TABLE_SIZES[table_idx]

    patterns = _symbolic_ghr_patterns(hist_len, n_samples=32)
    collisions = sum(
        1 for pat in patterns
        if gem5_gindex(pc1, pat, hist_len, log_table_size)
        == gem5_gindex(pc2, pat, hist_len, log_table_size)
    )
    return collisions / len(patterns) if patterns else 0.0


def _pc_for_branch(branch_id: str) -> int:
    """
    Derive a synthetic PC from the branch ID for hashing purposes.
    In a real implementation this would come from the object file symbol table.
    We use a stable hash of the branch_id string, aligned to 4 bytes.
    """
    h = hash(branch_id) & 0xFFFFFFFF
    return (h & ~0x3)   # align to 4 bytes (instShiftAmt=2 will shift out low 2 bits)


# Alias risk thresholds
ALIAS_DESTRUCTIVE_THRESHOLD = 0.15   # >15% collision rate = high risk
ALIAS_BENIGN_THRESHOLD      = 0.05   # <5%  collision rate = acceptable


def analyze_aliasing(branches: list, ablation: "AblationConfig") -> dict:
    """
    For each branch, scan all other branches that land in the same TAGE table
    at the branch's current recommended history length.  Classify each pair
    as constructive, destructive, or negligible.

    Respects ablation flags:
      ablation.destructive_alias  — whether to bump on destructive aliases
      ablation.constructive_alias — whether to record constructive aliases

    Returns {branch_id: AliasResult}.
    """
    results = {}

    # Group branches by their recommended table index
    by_table = defaultdict(list)
    for b in branches:
        tidx = table_index_for_length(b.signals.tage_length)
        by_table[tidx].append(b)

    for b in branches:
        pc1  = _pc_for_branch(b.branch_id)
        tidx = table_index_for_length(b.signals.tage_length)
        peers = [p for p in by_table[tidx] if p.branch_id != b.branch_id]

        destructive = 0
        constructive = 0
        for peer in peers:
            pc2  = _pc_for_branch(peer.branch_id)
            prob = _estimate_alias_probability(pc1, pc2, tidx)
            if ablation.destructive_alias and prob > ALIAS_DESTRUCTIVE_THRESHOLD:
                destructive += 1
            elif ablation.constructive_alias and prob > ALIAS_BENIGN_THRESHOLD:
                constructive += 1

        # Find the lowest table where destructive aliases drop to zero
        alias_free = tidx
        for t in range(tidx, len(TAGE_ALL_LENGTHS)):
            peers_at_t = [p for p in branches
                          if table_index_for_length(p.signals.tage_length) == t
                          and p.branch_id != b.branch_id]
            d = sum(1 for p in peers_at_t
                    if _estimate_alias_probability(pc1, _pc_for_branch(p.branch_id), t)
                    > ALIAS_DESTRUCTIVE_THRESHOLD)
            if d == 0:
                alias_free = t
                break

        def _len_for_table(t):
            return TAGE_ALL_LENGTHS[t] if t < len(TAGE_ALL_LENGTHS) else TAGE_ALL_LENGTHS[-1]

        if destructive > 0:
            note = (f"{destructive} destructive alias(es) at table {tidx} "
                    f"(H={_len_for_table(tidx)}); "
                    f"alias-free at table {alias_free} "
                    f"(H={_len_for_table(alias_free)})")
        elif constructive > 0:
            note = (f"{constructive} constructive alias(es) at table {tidx} "
                    f"(H={_len_for_table(tidx)}) — benign")
            alias_free = tidx
        else:
            tname = "bimodal" if tidx == 0 else f"table {tidx}"
            note = f"no significant aliasing detected at {tname} (H={_len_for_table(tidx)})"
            alias_free = tidx

        results[b.branch_id] = AliasResult(
            alias_min_table    = alias_free,
            destructive_count  = destructive,
            constructive_count = constructive,
            alias_free_table   = alias_free,
            alias_note         = note,
        )

    return results


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def compute_signals(
    loop_depth:       int,
    back_edge_dist:   int,
    ddu_depth:        int,
    dom_depth:        int,
    postdom_distance: int,
    call_fanin:       int,
    call_depth:       int,
    is_recursive:     bool,
    scc_size:         int,
    static_bias:      float,
    ablation:         "AblationConfig",
    graphs_used:      list,
    graphs_missing:   list,
) -> SignalBreakdown:
    """
    Compute all weighted contributions, identify the dominant signal, snap to
    nearest TAGE table length.  Every intermediate value is stored in the
    returned SignalBreakdown for full auditability.
    """
    s = SignalBreakdown(
        loop_depth         = loop_depth,
        back_edge_dist     = back_edge_dist,
        ddu_depth          = ddu_depth,
        dom_depth          = dom_depth,
        postdom_distance   = postdom_distance,
        call_fanin         = call_fanin,
        call_depth         = call_depth,
        is_recursive       = is_recursive,
        recursion_scc_size = scc_size,
        static_bias        = static_bias,
        bimodal_candidate  = ablation.static_bias and static_bias >= BIMODAL_BIAS_THRESHOLD,
        graphs_used        = graphs_used,
        graphs_missing     = graphs_missing,
    )

    s.contrib_loop       = loop_depth * W_LOOP_DEPTH
    s.contrib_back_edge  = (1.0 / (back_edge_dist + 1)) * W_BACK_EDGE_PROXIMITY * loop_depth
    s.contrib_ddu        = ddu_depth * W_DDU_DEPTH
    s.contrib_dom        = dom_depth * W_DOM_DEPTH
    s.contrib_postdom    = postdom_distance * W_POSTDOM_DISTANCE
    s.contrib_call_fanin = math.log2(call_fanin + 1) * W_CALL_FANIN
    s.contrib_call_depth = call_depth * W_CALL_DEPTH
    s.contrib_recursion  = (scc_size * W_RECURSION) if is_recursive else 0.0

    contribs = {
        "loop_depth":       s.contrib_loop,
        "back_edge_prox":   s.contrib_back_edge,
        "ddu_depth":        s.contrib_ddu,
        "dom_depth":        s.contrib_dom,
        "postdom_distance": s.contrib_postdom,
        "call_fanin":       s.contrib_call_fanin,
        "call_depth":       s.contrib_call_depth,
        "recursion":        s.contrib_recursion,
    }

    s.raw_score       = max(contribs.values()) if contribs else 0.0
    s.dominant_signal = max(contribs, key=contribs.get)
    s.tage_length     = snap_to_tage(s.raw_score)
    # Bimodal override: if the branch is strongly biased, history adds little
    # value even if the structural signals suggest otherwise.  Mark it as a
    # bimodal candidate here; apply_alias_results() will confirm or override
    # based on actual aliasing at the bimodal table.
    if s.bimodal_candidate:
        s.tage_length = 0
    # final_table/final_length will be updated by apply_alias_results()
    s.final_table     = table_index_for_length(s.tage_length)
    s.final_length    = s.tage_length
    return s


def apply_alias_results(branches: list, alias_map: dict) -> None:
    """
    Phase 3: apply aliasing analysis results to each branch.

    For bimodal candidates: confirm bimodal placement if no destructive
    aliasing at the bimodal table, otherwise bump to the shortest tagged
    table that is alias-free.

    For non-bimodal branches: bump to a longer table if destructive aliases
    are detected at the current table.

    Modifies branches in-place.
    """
    for b in branches:
        ar = alias_map.get(b.branch_id)
        if ar is None:
            continue
        s = b.signals
        s.alias_destructive  = ar.destructive_count
        s.alias_constructive = ar.constructive_count
        s.alias_free_table   = ar.alias_free_table
        s.alias_note         = ar.alias_note

        if s.bimodal_candidate:
            if ar.destructive_count == 0:
                # Bias is high and no destructive aliasing — bimodal confirmed
                s.final_table  = 0
                s.final_length = 0
                if "no significant aliasing" not in s.alias_note:
                    s.alias_note += " — bimodal confirmed"
                else:
                    s.alias_note = (f"bias={s.static_bias:.2f} ≥ {BIMODAL_BIAS_THRESHOLD}"
                                    f", no destructive aliasing — bimodal confirmed")
            else:
                # Destructive aliasing at bimodal — must use a tagged table
                s.final_table  = ar.alias_free_table if ar.alias_free_table > 0 else 1
                s.final_length = (TAGE_ALL_LENGTHS[s.final_table]
                                  if s.final_table < len(TAGE_ALL_LENGTHS)
                                  else TAGE_ALL_LENGTHS[-1])
                s.alias_note  += (f" — bimodal rejected due to destructive aliasing,"
                                  f" promoted to table {s.final_table}"
                                  f" (H={s.final_length})")
        else:
            # Non-bimodal: bump if alias analysis recommends higher table
            if ar.alias_free_table > s.final_table:
                s.final_table  = ar.alias_free_table
                s.final_length = (TAGE_ALL_LENGTHS[s.final_table]
                                  if s.final_table < len(TAGE_ALL_LENGTHS)
                                  else TAGE_ALL_LENGTHS[-1])
            else:
                s.final_table  = table_index_for_length(s.tage_length)
                s.final_length = s.tage_length


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def run_analysis(
    cfg_dir:        str,
    ddg_dir:        str,
    dom_dir:        str,
    postdom_dir:    str,
    callgraph_dir:  str,
    ablation:       "AblationConfig",
    verbose:        bool,
) -> list:

    if verbose: print("\n[1/5] Loading CFG files (cfg.*.dot or .*.dot)...", file=sys.stderr)
    cfg_graphs = load_dot_dir(cfg_dir,     ["cfg.*.dot", ".*.dot"], verbose)

    if verbose: print("\n[2/5] Loading DDG files (ddg.*.dot)...",            file=sys.stderr)
    ddg_graphs = load_dot_dir(ddg_dir,     ["ddg.*.dot"],        verbose)

    if verbose: print("\n[3/5] Loading dominator trees (dom.*.dot)...",      file=sys.stderr)
    dom_graphs = load_dot_dir(dom_dir,     ["dom.*.dot"],        verbose)

    if verbose: print("\n[4/5] Loading post-dominator trees (postdom.*.dot)...", file=sys.stderr)
    postdom_graphs = load_dot_dir(postdom_dir, ["postdom.*.dot"], verbose)

    if verbose: print("\n[5/5] Loading call graph DOT...",       file=sys.stderr)
    cg_data = {}
    cg = load_callgraph_dot(callgraph_dir, verbose)
    if cg is not None:
        cg_data = analyze_callgraph(cg)
        if verbose:
            print(f"  [cg] {len(cg_data)} functions", file=sys.stderr)

    if not cfg_graphs:
        print("WARNING: No CFG DOT files found.", file=sys.stderr)

    branches = []

    for func_name, cfg in cfg_graphs.items():
        if verbose:
            print(f"\n  Analyzing: {func_name}", file=sys.stderr)

        cfg_results = analyze_cfg(cfg)

        ddg     = _match(ddg_graphs,     func_name)
        dom     = _match(dom_graphs,     func_name)
        postdom = _match(postdom_graphs, func_name)

        ddg_depths     = analyze_ddg(ddg)        if ddg     else {}
        dom_depths     = analyze_dom(dom)        if dom     else {}
        postdom_depths = analyze_postdom(postdom) if postdom else {}
        bare_fn = _bare(func_name)
        # Try: exact key, bare key, case-insensitive bare scan
        cg_func = (cg_data.get(func_name)
                   or cg_data.get(bare_fn)
                   or next((v for k, v in cg_data.items()
                             if _bare(k) == bare_fn), None)
                   or {})

        graphs_used = (["cfg"]
                       + (["ddg"]       if ddg     else [])
                       + (["dom"]       if dom     else [])
                       + (["postdom"]   if postdom else [])
                       + (["callgraph"] if cg_func else []))
        graphs_missing = [g for g in
                          [None if ddg     else "ddg",
                           None if dom     else "dom",
                           None if postdom else "postdom",
                           None if cg_func else "callgraph"]
                          if g is not None]

        for node, cfg_node_data in cfg_results.items():
            label = _clean(node)

            signals = compute_signals(
                loop_depth       = cfg_node_data["loop_depth"],
                back_edge_dist   = cfg_node_data["back_edge_dist"],
                ddu_depth        = _lookup(ddg_depths, label),
                dom_depth        = dom_depths.get(node, dom_depths.get(label, 0)),
                postdom_distance = postdom_depths.get(node,
                                       postdom_depths.get(label, 0)),
                call_fanin       = cg_func.get("fanin", 0),
                call_depth       = cg_func.get("call_depth", 0),
                is_recursive     = cg_func.get("is_recursive", False),
                scc_size         = cg_func.get("scc_size", 1),
                static_bias      = cfg_node_data.get("static_bias", 0.5),
                ablation         = ablation,
                graphs_used      = graphs_used,
                graphs_missing   = graphs_missing,
            )

            branches.append(BranchInfo(
                branch_id    = f"{func_name}::{label}",
                function     = func_name,
                block        = label,
                node_id      = str(node),
                dbg_location = cfg_node_data.get("dbg_location", ""),
                signals      = signals,
            ))

    # Phase 2+3: aliasing analysis and table bump
    if branches:
        alias_map = analyze_aliasing(branches, ablation)
        apply_alias_results(branches, alias_map)

    branches.sort(key=lambda b: (-b.signals.final_length, -b.signals.raw_score))
    return branches


def _clean(node) -> str:
    return str(node).strip('"').strip()

def _bare(stem: str) -> str:
    """
    Strip all known LLVM DOT filename prefixes/suffixes to get the bare
    function name, then lowercase for case-insensitive comparison.

    Handles:
      'postdom.my_func'  -> 'my_func'
      'cfg.my_func'      -> 'my_func'
      'ddg.my_func.'     -> 'my_func'  (double-dot DDG names)
      '.my_func'         -> 'my_func'  (leading-dot opt output without prefix)
    """
    stem = stem.lower()
    # Strip known prefixes
    for prefix in ("postdom.", "post_dom.", "dom.", "ddg.", "cfg."):
        if stem.startswith(prefix):
            stem = stem[len(prefix):]
            break
    # Strip a bare leading dot (opt -passes=dot-cfg without prefix flag
    # produces .funcname.dot whose stem is .funcname)
    stem = stem.lstrip('.')
    # Strip trailing dots from double-dot DDG filenames (ddg.funcname..dot)
    stem = stem.rstrip('.')
    return stem


def _match(graphs: dict, func_name: str):
    """
    Match a loaded graph to a function name by comparing bare function name
    portions of the stems, so that e.g. 'postdom.foo' matches func_name 'foo'
    or 'cfg.foo'.
    """
    bare_func = _bare(func_name)
    # exact key match first
    if func_name in graphs:
        return graphs[func_name]
    # bare-name match: strip prefixes from both sides and compare
    for k, g in graphs.items():
        if _bare(k) == bare_func:
            return g
    # fallback: substring match
    for k, g in graphs.items():
        if bare_func in _bare(k) or _bare(k) in bare_func:
            return g
    return None

def _lookup(depths: dict, label: str) -> int:
    if label in depths: return depths[label]
    for k, v in depths.items():
        if label in k or k in label: return v
    return 0


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def _short_explanation(b: "BranchInfo") -> str:
    """
    Generate a concise plain-English explanation of why a branch received its
    final history length.  Covers the dominant structural signal, any aliasing
    action taken, and bimodal candidacy where relevant.
    """
    s = b.signals
    parts = []

    # ── structural reason ──────────────────────────────────────────────────
    dom = s.dominant_signal
    if s.bimodal_candidate and s.final_length == 0:
        parts.append(f"strongly biased (bias={s.static_bias:.2f}), "
                     f"no destructive aliasing at bimodal table")
    elif s.bimodal_candidate and s.final_length > 0:
        parts.append(f"biased (bias={s.static_bias:.2f}) but destructive aliasing "
                     f"at bimodal forced to H={s.final_length}")
    elif dom == "loop_depth":
        parts.append(f"loop depth {s.loop_depth} drives prediction "
                     f"(loop-internal branch, H={s.tage_length})")
    elif dom == "back_edge_prox":
        parts.append(f"close to loop header (dist={s.back_edge_dist}) "
                     f"at depth {s.loop_depth}")
    elif dom == "ddu_depth":
        parts.append(f"long def-use chain ({s.ddu_depth} steps) to branch condition")
    elif dom == "dom_depth":
        parts.append(f"deep in dominator tree (depth={s.dom_depth}), "
                     f"many prior conditions")
    elif dom == "postdom_distance":
        parts.append(f"long forward shadow (postdom dist={s.postdom_distance}), "
                     f"outcome influences many successors")
    elif dom == "call_fanin":
        parts.append(f"called from {s.call_fanin} call sites, "
                     f"needs history to distinguish contexts")
    elif dom == "call_depth":
        parts.append(f"call depth {s.call_depth}, GHR budget consumed by call/ret overhead")
    elif dom == "recursion":
        parts.append(f"recursive (SCC size={s.recursion_scc_size}), "
                     f"periodic GHR pattern")
    else:
        parts.append("all signals weak, minimum table")

    # ── aliasing action ─────────────────────────────────────────────────────
    if s.final_length > s.tage_length and not s.bimodal_candidate:
        parts.append(f"{s.alias_destructive} destructive alias(es) bumped "
                     f"H={s.tage_length}→{s.final_length}")
    elif s.alias_constructive > 0 and s.final_length == s.tage_length:
        parts.append(f"{s.alias_constructive} constructive alias(es), no change needed")

    # ── missing graphs caveat ───────────────────────────────────────────────
    if s.graphs_missing:
        parts.append(f"[{', '.join(s.graphs_missing)} unavailable]")

    return "; ".join(parts)


def format_report(branches: list, ablation: "AblationConfig") -> str:
    """
    Primary output format: one row per branch.
    Columns: !dbg | Final H | Explanation
    """
    headers = ["Function::Block", "!dbg", "H", "Explanation"]
    rows = []
    for b in branches:
        s = b.signals
        # Abbreviate node ID to last 6 hex chars for readability
        h_str = "bimodal" if s.final_length == 0 else str(s.final_length)
        rows.append([
            b.branch_id,
            b.dbg_location or "—",
            h_str,
            _short_explanation(b),
        ])

    if HAS_TABULATE:
        return tabulate(rows, headers=headers, tablefmt="rounded_outline",
                        maxcolwidths=[40, 12, 7, 60])
    else:
        out = "  |  ".join(headers) + "\n" + "-" * 160 + "\n"
        for r in rows:
            out += "  |  ".join(str(c) for c in r) + "\n"
        return out


def format_summary(branches: list, ablation: "AblationConfig") -> str:
    """Bar-chart distribution of final history lengths plus aliasing stats."""
    if not branches:
        return "No branches found."

    dist  = Counter(b.signals.final_length   for b in branches)
    total = len(branches)

    lines = [
        "",
        "=" * 64,
        f"  TAGE History Length Distribution  "
        f"[analyses: {ablation.summary()}]",
        "=" * 64,
        f"  Total branches: {total}",
        "",
    ]
    for h in TAGE_ALL_LENGTHS:
        count = dist.get(h, 0)
        pct   = 100 * count / total if total else 0
        bar   = "█" * int(pct / 2)
        label = "bimodal" if h == 0 else f"H={h:>3}"
        lines.append(f"  {label:<10}  {count:>4}  ({pct:5.1f}%)  {bar}")

    # Aliasing stats
    n_bumped     = sum(1 for b in branches
                       if b.signals.final_length > b.signals.tage_length
                       and not b.signals.bimodal_candidate)
    n_bimodal    = sum(1 for b in branches
                       if b.signals.final_length == 0 and b.signals.bimodal_candidate)
    n_bio_reject = sum(1 for b in branches
                       if b.signals.bimodal_candidate and b.signals.final_length > 0)

    if ablation.destructive_alias or ablation.static_bias:
        lines += [""]
        if ablation.destructive_alias:
            lines.append(f"  Branches bumped by destructive aliasing : {n_bumped}")
        if ablation.static_bias:
            lines.append(f"  Branches confirmed in bimodal           : {n_bimodal}")
            lines.append(f"  Bimodal candidates rejected (aliased)   : {n_bio_reject}")

    # Coverage warnings
    missing_ddg = sum(1 for b in branches if "ddg"       in b.signals.graphs_missing)
    missing_pd  = sum(1 for b in branches if "postdom"   in b.signals.graphs_missing)
    missing_cg  = sum(1 for b in branches if "callgraph" in b.signals.graphs_missing)
    if any([missing_ddg, missing_pd, missing_cg]):
        lines += ["", "  Coverage warnings (signals zeroed):"]
        if missing_ddg:
            lines.append(f"    ddu_depth  — no DDG for {missing_ddg} function(s)"
                         f" (too simple or opt did not emit)")
        if missing_pd:
            lines.append(f"    postdom    — missing for {missing_pd} branch(es)"
                         f", run: opt -passes='dot-postdom'")
        if missing_cg:
            lines.append(f"    callgraph  — missing, run: opt -passes='dot-callgraph'")

    lines.append("=" * 64)
    return "\n".join(lines)


def format_json(branches: list) -> str:
    out = []
    for b in branches:
        s = b.signals
        out.append({
            "branch_id":    b.branch_id,
            "function":     b.function,
            "block":        b.block,
            "node_id":      b.node_id,
            "dbg_location": b.dbg_location,
            "prediction": {
                "base_tage_length":   s.tage_length,
                "raw_score":          round(s.raw_score, 3),
                "dominant_signal":    s.dominant_signal,
                "alias_destructive":  s.alias_destructive,
                "alias_constructive": s.alias_constructive,
                "alias_note":         s.alias_note,
                "final_table":        s.final_table,
                "final_length":       s.final_length,
                "bimodal_candidate":  s.bimodal_candidate,
                "static_bias":        round(s.static_bias, 3),
            },
            "raw_measurements": {
                "loop_depth":         s.loop_depth,
                "back_edge_dist":     s.back_edge_dist,
                "ddu_depth":          s.ddu_depth,
                "dom_depth":          s.dom_depth,
                "postdom_distance":   s.postdom_distance,
                "call_fanin":         s.call_fanin,
                "call_depth":         s.call_depth,
                "is_recursive":       s.is_recursive,
                "recursion_scc_size": s.recursion_scc_size,
            },
            "weighted_contributions": {
                "loop":       round(s.contrib_loop,        3),
                "back_edge":  round(s.contrib_back_edge,   3),
                "ddu":        round(s.contrib_ddu,         3),
                "dom":        round(s.contrib_dom,         3),
                "postdom":    round(s.contrib_postdom,     3),
                "call_fanin": round(s.contrib_call_fanin,  3),
                "call_depth": round(s.contrib_call_depth,  3),
                "recursion":  round(s.contrib_recursion,   3),
            },
            "coverage": {
                "graphs_used":    s.graphs_used,
                "graphs_missing": s.graphs_missing,
            },
            "explanation": _short_explanation(b),
        })
    return json.dumps(out, indent=2)


def format_csv(branches: list) -> str:
    hdr = ("branch_id,function,block,node_id,dbg_location,"
           "loop_depth,back_edge_dist,ddu_depth,dom_depth,postdom_distance,"
           "call_fanin,call_depth,is_recursive,recursion_scc_size,static_bias,"
           "contrib_loop,contrib_back_edge,contrib_ddu,contrib_dom,"
           "contrib_postdom,contrib_call_fanin,contrib_call_depth,contrib_recursion,"
           "raw_score,base_tage_length,dominant_signal,bimodal_candidate,"
           "alias_destructive,alias_constructive,alias_note,"
           "final_table,final_length,explanation,graphs_missing")
    lines = [hdr]
    for b in branches:
        s = b.signals
        expl = _short_explanation(b).replace('"', "'")
        lines.append(
            f'"{b.branch_id}","{b.function}","{b.block}",'
            f'"{b.node_id}","{b.dbg_location}",'
            f'{s.loop_depth},{s.back_edge_dist},{s.ddu_depth},{s.dom_depth},'
            f'{s.postdom_distance},{s.call_fanin},{s.call_depth},'
            f'{"true" if s.is_recursive else "false"},{s.recursion_scc_size},'
            f'{s.static_bias:.3f},'
            f'{s.contrib_loop:.3f},{s.contrib_back_edge:.3f},{s.contrib_ddu:.3f},'
            f'{s.contrib_dom:.3f},{s.contrib_postdom:.3f},{s.contrib_call_fanin:.3f},'
            f'{s.contrib_call_depth:.3f},{s.contrib_recursion:.3f},'
            f'{s.raw_score:.3f},{s.tage_length},"{s.dominant_signal}",'
            f'{"true" if s.bimodal_candidate else "false"},'
            f'{s.alias_destructive},{s.alias_constructive},"{s.alias_note}",'
            f'{s.final_table},{s.final_length},"{expl}",'
            f'"{";".join(s.graphs_missing)}"'
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Predict TAGE branch history lengths from LLVM DOT dumps.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    # ── graph directories ────────────────────────────────────────────────────
    parser.add_argument("--cfg-dir",       default=".", metavar="DIR",
                        help="Directory with CFG DOT files (default: .)")
    parser.add_argument("--ddg-dir",       default=".", metavar="DIR",
                        help="Directory with DDG DOT files (default: .)")
    parser.add_argument("--dom-dir",       default=".", metavar="DIR",
                        help="Directory with dominator tree DOT files (default: .)")
    parser.add_argument("--postdom-dir",   default=".", metavar="DIR",
                        help="Directory with post-dominator DOT files (default: .)")
    parser.add_argument("--callgraph-dir", default=".", metavar="DIR",
                        help="Directory with callgraph DOT (default: .)")
    # ── ablation flags ───────────────────────────────────────────────────────
    parser.add_argument("--no-destructive-alias", action="store_true",
                        help="Disable destructive aliasing check "
                             "(do not bump branches to longer tables)")
    parser.add_argument("--no-constructive-alias", action="store_true",
                        help="Disable constructive aliasing detection "
                             "(do not note beneficial alias pairs)")
    parser.add_argument("--no-static-bias", action="store_true",
                        help="Disable static bias / bimodal candidacy "
                             "(never assign branches to bimodal table)")
    # ── output options ───────────────────────────────────────────────────────
    parser.add_argument("--output",  default=None, metavar="FILE",
                        help="Write output to FILE (default: stdout)")
    parser.add_argument("--format",
                        choices=["report", "json", "csv"],
                        default="report",
                        help="report=table+summary (default), "
                             "json/csv=machine readable")
    parser.add_argument("--verbose", action="store_true",
                        help="Print loading/analysis progress to stderr")
    args = parser.parse_args()

    ablation = AblationConfig(
        destructive_alias  = not args.no_destructive_alias,
        constructive_alias = not args.no_constructive_alias,
        static_bias        = not args.no_static_bias,
    )

    print("Branch History Length Predictor", file=sys.stderr)
    for label, val in [
        ("CFG dir",     args.cfg_dir),
        ("DDG dir",     args.ddg_dir),
        ("DOM dir",     args.dom_dir),
        ("PostDOM dir", args.postdom_dir),
        ("CG dir",      args.callgraph_dir),
        ("Analyses",    ablation.summary()),
        ("Format",      args.format),
    ]:
        print(f"  {label:<12}: {val}", file=sys.stderr)

    branches = run_analysis(
        cfg_dir        = args.cfg_dir,
        ddg_dir        = args.ddg_dir,
        dom_dir        = args.dom_dir,
        postdom_dir    = args.postdom_dir,
        callgraph_dir  = args.callgraph_dir,
        ablation       = ablation,
        verbose        = args.verbose,
    )

    if not branches:
        print("\nNo branches found. Check DOT files exist in the specified dirs.",
              file=sys.stderr)
        sys.exit(1)

    if args.format == "report":
        output = format_report(branches, ablation) + "\n" + format_summary(branches, ablation)
    elif args.format == "json":
        output = format_json(branches)
    else:
        output = format_csv(branches)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"\nResults written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
