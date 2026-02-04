import argparse
from pathlib import Path

from PIL import Image
import numpy as np
from bokeh.io import show
from bokeh.plotting import figure
from scipy.signal import convolve

from utils import *

idct_loop_cluster_lb = 10000
idct_loop_cluster_ub = 90000

sample_interval = PP_sample_interval

class Cluster(object):
    begin: int
    end: int
    nodes: list[int]

    def __init__(self, node):
        self.begin = node
        self.end = node
        self.nodes = [node]

    def append(self, node):
        self.end = max(self.end, node)
        self.nodes.append(node)

    def size(self):
        return len(self.nodes)

    def length(self):
        return self.end - self.begin

    def center(self):
        return (self.begin + self.end) // 2

    def merge(self, cluster):
        if self.end < cluster.begin:
            self.nodes.extend(cluster.nodes)
            self.end = cluster.end
        elif self.begin > cluster.end:
            self.nodes = cluster.nodes + self.nodes
            self.begin = cluster.begin
        else:
            raise AssertionError("Cannot merge clusters")


def get_trace_clusters(strace, base_interval=3000):
    clusters = []
    i = 0

    # basic cluster
    while i < len(strace):
        cluster = Cluster(strace[i])
        j = i + 1
        while j < len(strace) and strace[j] < cluster.end + 1.5 * base_interval:
            cluster.append(strace[j])
            j += 1
        clusters.append(cluster)
        i = j

    # bridge 1 scale missing hits
    i = 0
    while i < len(clusters) - 1:
        cluster_i = clusters[i]
        cluster_j = clusters[i + 1]
        if (
            cluster_j.begin - cluster_i.end <= 2.5 * base_interval
            and cluster_i.size() + cluster_j.size() >= 4
        ):
            cluster_i.merge(cluster_j)
            clusters.pop(i + 1)
        else:
            i = i + 1

    return clusters


def instrument_clusters(clusters):
    x = []
    size = []
    length = []
    i = 0
    while i < len(clusters):
        c = clusters[i]
        x.append(c.center())
        size.append(c.size())
        length.append(c.length())
        if i + 1 < len(clusters):
            c1 = clusters[i + 1]
            x.append((c.end + c1.begin) // 2)
            size.append(0)
            length.append(0)
        else:
            x.append(c.end)
            size.append(0)
            length.append(0)
        i += 1
    return x, size, length


def patch_goto16_cluster_fractures(clusters, calibration, fracture_thres):
    i = 1

    print(f"cali: {calibration}, fracture thres: {fracture_thres}")

    def close_to(a, b, ratio=0.25):
        if a > b:
            a, b = b, a
        return (b - a) / a <= ratio

    while i < len(clusters) - 2:
        ch = clusters[i - 1]
        ci = clusters[i]
        cj = clusters[i + 1]
        ck = clusters[i + 2]
        c_gap = cj.begin - ci.end
        p_gap = ci.begin - ch.end
        n_gap = ck.begin - cj.end
        if c_gap <= fracture_thres:
            print(
                f"i,j: {(ci.center(), cj.center())} c_gap: {c_gap} p_gap: {p_gap} n_gap: {n_gap} close_to({close_to(p_gap, calibration),close_to(n_gap, calibration)})"
            )
            if close_to(p_gap, calibration) and close_to(n_gap, calibration):
                print(
                    f"new range: {idct_loop_cluster_lb}<={cj.end-ci.begin}<={idct_loop_cluster_ub}"
                )
                if (
                    cj.end - ci.begin >= idct_loop_cluster_lb
                    and cj.end - ci.begin <= idct_loop_cluster_ub
                ):
                    print(f"Merge range: {ci.begin, ci.end}")
                    ci.merge(cj)
                    print(f"Merge range: {ci.begin, ci.end}")
                    cj = clusters.pop(i + 1)
                    print(f"Merge range: {clusters[i].begin, clusters[i].end}")
                    i = i
                else:
                    i = i + 1
            if n_gap <= fracture_thres and close_to(c_gap, n_gap):
                # bloack line separator, skip
                i = i + 2
            else:
                i = i + 1
        else:
            i = i + 1


def check_image_width(occ, dist, line_width):
    match_score = {0: 0}
    sep={}
    for i in range(1, len(occ)):
        match_score[i] = 1 << 30
        for j in range(i):
            rnd = round(dist[j][i] // line_width)
            diff = (2 * abs(dist[j][i] - line_width * rnd))**2
            if rnd == 0:
                continue
            extra = (rnd ** 2) -1
            raw = (i - j - 1) ** 2
            score = match_score[j] + raw + diff + extra
            # print("i, j, dist[j][i], rnd, diff, extra, score\n", i, j, dist[j][i], rnd, diff, extra, score)
            if score < match_score[i]:
                sep[i] = j
                match_score[i] = score
        # print(f"score {i}, {match_score[i]}")
    # print(match_score)
    return match_score, sep



def extract_p_from_file(filepath, at="PP"):
    trace = load_trace(filepath)

    pos = trace[0].apply(lambda x: lat_to_hit(x[1], at))
    goto16 = trace[0][pos].apply(lambda x: x[0]).astype(float)
    pos = trace[1].apply(lambda x: lat_to_hit(x[1], at))
    shl = trace[1][pos].apply(lambda x: x[0]).astype(float)

    goto16_clusters = get_trace_clusters(goto16)
    shl_clusters = get_trace_clusters(shl)
    print(f"#goto16 cluster {len(goto16_clusters)}")
    print(f"#shl cluster {len(shl_clusters)}")

    goto16_x, goto16_size, goto16_length = instrument_clusters(goto16_clusters)
    shl_x, shl_size, shl_length = instrument_clusters(shl_clusters)

    idct_cand = list(
        filter(
            lambda t: t[1] >= idct_loop_cluster_lb and t[1] <= idct_loop_cluster_ub,
            zip(goto16_x, goto16_length),
        )
    )
    if len(idct_cand) == 0:
        print("Did not detect idct trace")
        return 0, 0, []

    idct_pos = [x for x, l in idct_cand]
    goto16_peaks_cluster = get_trace_clusters(idct_pos, 100000)
    idct_cluster = max(goto16_peaks_cluster, key=lambda x: x.size())

    flex_bound = 120000
    idct_begin = idct_cluster.begin - flex_bound
    idct_end = idct_cluster.end + flex_bound

    print(f"idct (begin, end): {(idct_begin, idct_end)}")
    idct_goto16_clusters = list(
        filter(
            lambda c: c.begin >= idct_begin and c.end <= idct_end,
            goto16_clusters,
        )
    )

    idct_loop_goto16_clusters = list(
        filter(
            lambda c: c.length() >= idct_loop_cluster_lb
            and c.length() <= idct_loop_cluster_ub
            and c.begin >= idct_begin
            and c.end <= idct_end,
            goto16_clusters,
        )
    )

    idct_length = [c.length() for c in idct_loop_goto16_clusters]

    idct_goto16_turning_cand = list(
        map(
            lambda p: p[0],
            filter(
                lambda t: t[0] >= idct_begin
                and t[0] <= idct_end
                and t[1] >= 1
                and t[1] <= 4,
                zip(goto16_x, goto16_size),
            ),
        )
    )
    idct_shl_turning_cand = list(
        map(
            lambda p: p[0],
            filter(
                lambda t: t[0] >= idct_begin
                and t[0] <= idct_end
                and t[1] >= 1
                and t[1] <= 4,
                zip(shl_x, shl_size),
            ),
        )
    )

    goto16_sig = probes_to_signal(
        idct_goto16_turning_cand,
        sample_interval,
        (idct_begin, idct_end),
        0,
    )

    shl_sig = probes_to_signal(
        idct_shl_turning_cand,
        sample_interval,
        (idct_begin, idct_end),
        0,
    )
    tolerance = 5

    kernel = np.ones(2 * tolerance + 1)

    shl_blurred = convolve(shl_sig, kernel, mode="same")
    co_seq = (goto16_sig == 1) & (shl_blurred > 0)

    co = [idct_begin + sample_interval * i for i, v in enumerate(co_seq) if v]
    co = [idct_goto16_clusters[0].begin] + co + [idct_goto16_clusters[-1].end]
    print("goto16 cluster count ", len(idct_loop_goto16_clusters))

    group_dist = {}
    gl = 0
    gr = 0
    for i in range(len(co)):
        group_dist[i] = {}
        gl = 0
        while (
            gl < len(idct_loop_goto16_clusters)
            and idct_loop_goto16_clusters[gl].begin <= co[i]
        ):
            gl += 1
        gr = gl -1
        for j in range(i, len(co)):
            while (
                gr + 1 < len(idct_loop_goto16_clusters)
                and idct_loop_goto16_clusters[gr + 1].end < co[j]
            ):
                gr += 1
            group_dist[i][j] = gr - gl + 1

    # print(group_dist)

    warr = []

    # for i in range(1, len(idct_loop_goto16_clusters)):
    for i in range(10, 30):
        score, sep = check_image_width(co, group_dist, i)
        warr.append((score[len(co)-1], i))
    warr=sorted(warr)

    # print(warr)
    print(f"optimal width {warr[0][1]}")
    line_width = warr[0][1]

    image_groups = []
    width = line_width

    height = 0
    interval = []

    _, opt_sep = check_image_width(co, group_dist, width)

    def split_idct_group(clusters, co_index):
        global height
        if co_index == 0:
            return 0, 0
        height, c_index = split_idct_group(clusters, opt_sep[co_index])
        image_groups.append([])
        lb = co[opt_sep[co_index]]
        ub = co[co_index]
        while c_index < len(clusters) and clusters[c_index].begin<lb:
            c_index += 1
        while c_index < len(clusters) and clusters[c_index].end<=ub:
            image_groups[height].append(clusters[c_index].length())
            c_index += 1
        return height + 1, c_index

    height, _ = split_idct_group(idct_loop_goto16_clusters, len(co)-1)

    # print("image height", len(image_groups))
    # for p in image_groups:
    #     print("image width", len(p))

    flat = np.array([x for row in image_groups for x in row], dtype=np.float64)
    low, high = np.percentile(flat, [10, 90])
    def normalize_trim(x, low, high):
        x = np.clip(x, low, high)
        return (x - low) / (high - low)

    normed = [
        [normalize_trim(x, low, high) for x in row]
        for row in image_groups
    ]
    max_len = max(len(row) for row in normed)

    padded = np.array([
        row + [1.0] * (max_len - len(row))
        for row in normed
    ])

    image_pixel = np.round((1- padded) * 255).astype(np.uint8)

    width = max_len

    # print(image_pixel)
    # for r in image_pixel:
    #     print(r)

    output_fp = Path(__file__).resolve().parent.parent / Path(
        "output/jpeg-extraction.out"
    )
    with open(output_fp, "wb") as f:
        f.write(bytes(image_pixel))

    return (height, width, image_pixel)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extract image from on quickjs jpeg trace"
    )

    parser.add_argument(
        "--att",
        choices=["FR", "PS", "PP"],
        default="FR",
        help="Attack Primitive: FR or PS (default: FR)",
    )

    parser.add_argument(
        "-f",
        "--file",
        type=str,
        help="Output file",
    )

    args = parser.parse_args()

    attack_type = args.att

    if args.file:
        h, w, img_array = extract_p_from_file(args.file)

        scale = 8
        img_scaled = np.repeat(img_array, scale, axis=0)
        img_scaled = np.repeat(img_scaled, scale, axis=1)

        img = Image.fromarray(img_scaled, mode="L")
        img.save("extract.jpg")
