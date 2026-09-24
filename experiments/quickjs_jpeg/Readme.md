# Case Study 2: QuickJS — jpeg-js

Reproduces the results in **paper §5.2** (QuickJS — jpeg-js).

QuickJS version: `3b45d15`

jpeg-js version: `72cb036`

## Description

Case Study 2: QuickJS — jpeg-js evaluates the exploitability of jpeg-js's jpeg.

## Evaluation

Run the attack on the victim script of the image to recover:

```bash
experiments/quickjs_jpeg/evaluation/capture.sh \
    experiments/quickjs_jpeg/js/jpeg_decode_emacs.js emacs 1
```

Then extract.

```bash
python3 experiments/quickjs_jpeg/evaluation/extract_jpeg_js.py \
    -f build/output/emacs_1/r0.out \
    -o recovered.jpg
```

### Measuring accuracy

`evaluation/gen_ground_truth.py` instruments jpeg-js itself and dumps the exact
`<nz_rows> <nz_cols>` of every block, so recovery can be scored against the real
branch outcomes instead of a DCT approximation of the decoded pixels:

```bash
python3 experiments/quickjs_jpeg/evaluation/gen_ground_truth.py \
    --image ./experiments/quickjs_jpeg/evaluation/emacs_gs.jpg \
    --out build/output/gt_emacs.txt
```

`evaluation/compare.py` renders `[original | theoretical best | recovered]` and
reports cosine similarity against both the grayscale original and the channel
ceiling.

## Alternative attack: targeting the bytecode instructions (I1/DA)

`quickjs_jpeg_bc` is a second attack that monitors `quantizeAndInverse`'s own
bytecode buffer instead of the shared bytecode handlers. The simple and complex
IDCT paths occupy distinct, fixed offsets in that buffer, and the interpreter
reads those bytes (`opcode = *pc++`) only while this function runs, so the signal
is automatically confined to the IDCT.

The bytecode buffer is heap-allocated, so its address is not stable across
processes. The attack therefore runs the victim as a thread in the **same
process** and reads the address the patched runtime exports in
`llct_qai_bytecode` (set in `js_create_function`) after the function compiles —
no cache-set identification needed.

```bash
cd SCAR_Artifact/build
taskset -c 1,3,5,7,9,11,13,15 ./experiments/quickjs_jpeg/quickjs_jpeg_bc \
    experiments/quickjs_jpeg/js/jpeg_decode_emacs.js
cd SCAR_Artifact
python3 experiments/quickjs_jpeg/evaluation/extract_jpeg_bc.py \
    -f build/output/quickjs_jpeg_bc_r00001/r0.out -o recovered_bc.jpg
```
