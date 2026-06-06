#!/usr/bin/env bash
# Generate one RSA key with openssl, then derive three CSI calibration PEMs that
# share the same n/p/q but use different d values (regex-style pattern,
# MSB-first). These drive cache-set identification for the cz/aw/at targets:
#   csi_aw.pem  — 1+        -> 4096 ones                  (absorb_window)
#   csi_cz.pem  — 10+       -> 1 then 4095 zeros (2**4095) (consume_zero)
#   csi_at.pem  — (10000)+  -> 10000 10000 10000 ...       (absorb_trailing)
#
# They live alongside the attack pool in experiments/cpython_pow/rsa_key_pool/,
# which is where cpython_pow.c (key_path_cz/aw/at) expects them.
#
# Usage: csi_key_gen.sh [bits] [outdir]
set -euo pipefail

BITS="${1:-4096}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Default: the shared key pool dir (sibling of evaluation/).
OUTDIR="${2:-$SCRIPT_DIR/../rsa_key_pool}"

mkdir -p "$OUTDIR"
TEMP_KEY="$(mktemp -t csi_base_XXXXXX.pem)"
trap 'rm -f "$TEMP_KEY"' EXIT

openssl genpkey -algorithm RSA -out "${TEMP_KEY}" -pkeyopt rsa_keygen_bits:${BITS} >/dev/null 2>&1
# python-rsa needs PKCS#1 (-----BEGIN RSA PRIVATE KEY-----); genpkey emits PKCS#8.
openssl rsa -in "${TEMP_KEY}" -traditional -out "${TEMP_KEY}" >/dev/null 2>&1
echo "base key ${TEMP_KEY}: ${BITS}-bit"

python3 "$SCRIPT_DIR/csi_key_gen.py" --in "$TEMP_KEY" --bits "$BITS" \
    --pattern '1+'       --out "$OUTDIR/csi_aw.pem"
python3 "$SCRIPT_DIR/csi_key_gen.py" --in "$TEMP_KEY" --bits "$BITS" \
    --pattern '10+'      --out "$OUTDIR/csi_cz.pem"
python3 "$SCRIPT_DIR/csi_key_gen.py" --in "$TEMP_KEY" --bits "$BITS" \
    --pattern '(10000)+' --out "$OUTDIR/csi_at.pem"
