# Case Study 2: QuickJS — jpeg-js

QuickJS version: `3b45d15`

OpenPGP.js version: `72cb036`

## Description

Case Study 2: QuickJS — jpeg-js evaluates the exploitability of jpeg-js's jpeg.

Jpeg-js's IDCT implementation contains secret-dependent control-flow which results in  different timing measurements of blocks being processed within the image. These timings can be used to approximate images that are processed by jpeg-js.

## Evaluation

To run the evaluation execute the following command:

```bash
cd build
./experiments/quickjs_jpeg/quickjs_jpeg ./experiments/quickjs_jpeg/js/jpeg_decode_emacs.js
```

```bash
cd SCAR_Artifact
python evaluation/extract_jpeg_js.py -f build/output/quickjs_jpeg_js_r00001/r0.out
```
