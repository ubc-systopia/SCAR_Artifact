#!/usr/bin/env bash
# Generate one RSA key with openssl, then derive three PEMs that share the
# same n/p/q but use different d values (regex-style pattern, MSB-first):
#   private_1+.pem        — 1+        -> 4096 ones
#   private_10+.pem       — 10+       -> 1 then 4095 zeros (= 2**4095)
#   private_(10000)+.pem  — (10000)+  -> 10000 10000 10000 ...
#
# Usage: csi_key_gen.sh [bits] [outdir]
set -euo pipefail

BITS="${1:-4096}"
OUTDIR="${2:-.}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

mkdir -p "$OUTDIR"
TEMP_KEY="temp_key.pem"

openssl genpkey -algorithm RSA -out ${TEMP_KEY} -pkeyopt rsa_keygen_bits:${BITS} >/dev/null 2>&1
# python-rsa needs PKCS#1 (-----BEGIN RSA PRIVATE KEY-----); genpkey emits PKCS#8.
openssl rsa -in ${TEMP_KEY} -traditional -out ${TEMP_KEY} >/dev/null 2>&1
echo "base key ${TEMP_KEY}: ${BITS}-bit"

python3 "$SCRIPT_DIR/csi_key_gen.py" --in "$TEMP_KEY" --bits "$BITS" \
    --pattern '1+'       --out "$OUTDIR/private_1+.pem"
python3 "$SCRIPT_DIR/csi_key_gen.py" --in "$TEMP_KEY" --bits "$BITS" \
    --pattern '10+'      --out "$OUTDIR/private_10+.pem"
python3 "$SCRIPT_DIR/csi_key_gen.py" --in "$TEMP_KEY" --bits "$BITS" \
    --pattern '(10000)+' --out "$OUTDIR/private_(10000)+.pem"
