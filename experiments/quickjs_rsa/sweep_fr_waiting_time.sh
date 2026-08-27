#!/usr/bin/env bash
# Sweep quickjs_rsa_fr's WAITING_TIME and compare decode accuracy across runs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# TSC-cycle candidates to try. Override with WAITING_TIMES="5000 10000 ..." env var.
read -ra WAITING_TIMES <<<"${WAITING_TIMES:-2000 5000 10000 20000 40000 80000}"
TRIALS="${TRIALS:-3}"

RESULTS_CSV="${SCRIPT_DIR}/fr_sweep_results.csv"
echo "waiting_time,trial,known,wrong,unknown,known_acc" >"$RESULTS_CSV"

for wt in "${WAITING_TIMES[@]}"; do
	for ((t = 1; t <= TRIALS; t++)); do
		echo "== waiting_time=${wt} trial=${t}/${TRIALS} =="
		out="$(WAITING_TIME="$wt" "${SCRIPT_DIR}/run_fr_eval.sh" 2>&1)" || {
			echo "  run failed, skipping" >&2
			echo "$out" | tail -20 >&2
			continue
		}

		line="$(echo "$out" | grep -E '^Key 000 \|' || true)"
		if [ -z "$line" ]; then
			echo "  no decodable trace" >&2
			echo "${wt},${t},0,0,0," >>"$RESULTS_CSV"
			continue
		fi
		echo "  $line"

		acc="$(echo "$line" | sed -n 's/.*acc \([0-9.]*\).*/\1/p')"
		known="$(echo "$line" | sed -n 's/.*known *\([0-9]*\).*/\1/p')"
		wrong="$(echo "$line" | sed -n 's/.*wrong *\([0-9]*\).*/\1/p')"
		unknown="$(echo "$line" | sed -n 's/.*unknown *\([0-9]*\).*/\1/p')"
		echo "${wt},${t},${known},${wrong},${unknown},${acc}" >>"$RESULTS_CSV"
	done
done

echo
echo "== Summary (mean known-bit accuracy per waiting_time) =="
"${ROOT}/.venv/bin/python3" - "$RESULTS_CSV" <<'EOF'
import sys
import csv
from collections import defaultdict

rows = list(csv.DictReader(open(sys.argv[1])))
by_wt = defaultdict(list)
for r in rows:
    if r["known_acc"]:
        by_wt[int(r["waiting_time"])].append(float(r["known_acc"]))

for wt in sorted(by_wt):
    accs = by_wt[wt]
    mean = sum(accs) / len(accs)
    print(f"  waiting_time={wt:>7}  n={len(accs)}  mean_acc={mean:.4f}  runs={['%.4f' % a for a in accs]}")
EOF

echo
echo "Full per-run results: ${RESULTS_CSV}"
