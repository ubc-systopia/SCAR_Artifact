from statistics import mean, median


def aggregate_metrics(metrics):
    agg = {}
    for i in metrics[0].keys():
        agg[i] = []
        for v in metrics:
            agg[i].append(v[i])

    print("\n=== Results ===\n")
    print("Metrics: min / median / max - mean")
    for k, v in agg.items():
        print(k + ":", min(v), "/", median(v), "/", max(v), "-", mean(v))
