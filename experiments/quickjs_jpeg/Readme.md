# Case Study 2: QuickJS — jpeg-js

Reproduces the results in **paper §5.2** (QuickJS — jpeg-js).

QuickJS version: `3b45d15`

jpeg-js version: `72cb036`

## Description

Case Study 2: QuickJS — jpeg-js evaluates the exploitability of jpeg-js's jpeg.

Jpeg-js's IDCT implementation contains secret-dependent control-flow which results in  different timing measurements of blocks being processed within the image. These timings can be used to approximate images that are processed by jpeg-js.

## Evaluation

Run the attack on the victim script of the image to recover:

```bash
cd anonymous-sc-language-runtimes/build
taskset -c 1,3,5,7,9,11,13,15 ./src/runtime/quickjs/quickjs_rt \
    ../experiments/quickjs_jpeg/js/jpeg_decode_emacs.js
```

Then start the attacker in a second shell:

```bash
cd anonymous-sc-language-runtimes/build
taskset -c 1,3,5,7,9,11,13,15 ./experiments/quickjs_jpeg/quickjs_jpeg
```

Then extract the image from the recorded trace:

```bash
cd anonymous-sc-language-runtimes
python experiments/quickjs_jpeg/evaluation/extract_jpeg_js.py \
    -f build/output/quickjs_jpeg_js_r00001/r0.out \
    -o recovered.jpg
```
