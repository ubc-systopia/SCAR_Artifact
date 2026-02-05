import glob
from collections import Counter

CONSUME_ZERO = 0
WINDOW = 1
TRAILING = 2
GAP = -1


def lat_to_clevel(lat):
    if lat < 70:
        return 1
    elif lat < 90:
        return 2
    elif lat < 140:
        return 3
    elif lat < 240:
        return 4
    elif lat < 460:
        return 5
    else:
        return 6


def parse_trace(file):
    hits = []
    with open(file) as f:
        lines = f.read().strip().splitlines()

    for line in lines:
        hit = []
        entries = line.strip().split()

        for entry in entries:
            entry = int(entry.split(":")[1])
            hit.append(lat_to_clevel(entry) <= 4)

        hits.append(hit)

    i = 0
    while i < len(hits) and not (
            hits[i][CONSUME_ZERO] and hits[i][WINDOW] and hits[i][TRAILING]
    ):
        i += 1
    hits = hits[i + 2:]

    i = len(hits) - 1
    while i > 2 and not (any(hits[i])):
        i -= 1
    hits = hits[:i]

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


def merge_traces(size, files):
    merged = [Counter() for i in range(size)]

    for file in files:
        trace = parse_trace(file)
        for i, ctr in enumerate(trace):
            merged[i][ctr[1]] += 1

    return merged


def infer(merged, nr):
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


def collect_metrics(d, inf, size):
    recoverable = 0
    recoverable_leading = 0
    masked = []
    i = 0
    l = len(d)
    offset = 0
    recovered = 0
    correct = 0
    first_failure = 0
    end_window = 0
    while i < l:
        if d[i] == 0:
            recoverable_leading += 1
            i += 1
            masked.append(0)
            continue

        t = 0
        end = min(l - 1, i + 4)
        while end > i:
            if d[end] == 1:
                break
            recoverable += 1
            end -= 1
            t += 1

        s = end - i + 1
        recoverable += min(s, 2)
        i += s + t

        masked.append(1)
        for j in range(s - 2):
            masked.append(-1)
        if s > 1:
            masked.append(1)
        for j in range(t):
            masked.append(0)

        if i == l:
            end_window = s + t

    for o in range(15):
        correct = 0
        first_failure = 0
        recovered = 0
        for i, (x, y) in enumerate(zip(d[o:], inf)):
            if y != -1:
                recovered += 1
                if x == y:
                    correct += 1
                elif first_failure == 0 and y >= 0:
                    first_failure = i
        offset = o
        if correct / (recoverable + recoverable_leading) > 0.75:
            break

    return {
        "Sample Size": size,
        "Bits": len(inf),
        "Offset": offset,
        "Recovered": recovered,
        "Correct": correct,
        "Accuracy": correct / l,
        "Relative Accuracy (incl. leading and trailing)": correct
                                                          / (recoverable + recoverable_leading),
        "Inference Accuracy (excl leading and trailing)": correct
                                                          / (recoverable + recoverable_leading - end_window - o),
        "First Failure": first_failure,
    }


def extract(folder):
    with open(f"{folder}/private.key") as f:
        keys = f.read().strip()
        d = list(map(int, keys[2:]))

    files = glob.glob(
        f"{folder}/output/*.out"
    )

    merged = [Counter() for i in range(len(d))]
    metrics = []

    prev = 0
    next = 1
    while next <= len(files):
        for i in range(prev, next):
            trace = parse_trace(files[i])
            for i, ctr in enumerate(trace):
                merged[i][ctr[1]] += 1

        inf = infer(merged, next)

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

    return metrics
