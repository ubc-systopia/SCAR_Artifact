"""Generate exact per-block IDCT ground truth for the jpeg-js case study.

The attack recovers, per 8x8 block, how many row and column IDCT passes took the
COMPLEX (non-flat) path. That number is not derivable from the decoded pixels
exactly -- `compare.py`'s DCT-based `complexity_map` only approximates it. This
script instruments jpeg-js itself. It writes a patched copy of `jpeg-js.js`
that counts the complex rows and columns of every block, runs it under the
QuickJS build, and dumps one `<nz_rows> <nz_cols>` line per block in decode
order.

It writes two generated files next to the library, `js/jpeg-js-gt.js` and
`js/_gt_driver.js` (both git-ignored), because the driver has to import the
patched copy and `utils.js` by relative path.

Run on leapx02 (it needs build/quickjs/bin/qjs):

  build/cpython/venv/bin/python3 experiments/quickjs_jpeg/evaluation/gen_ground_truth.py \
      --image experiments/quickjs_jpeg/evaluation/emacs_gs.jpg \
      --out build/output/gt_emacs.txt
"""
import argparse
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
JS = HERE.parent / "js"

PATCHES = [
    # (must occur exactly N times, old, new)
    (1,
     "    function quantizeAndInverse(zz, dataOut, dataIn) {\n"
     "      var qt = component.quantizationTable;",
     "    function quantizeAndInverse(zz, dataOut, dataIn) {\n"
     "      var _nzr = 0, _nzc = 0;\n"
     "      var qt = component.quantizationTable;"),
    (1,
     "          continue;\n        }\n\n        // stage 4\n"
     "        v0 = (dctSqrt2 * p[0 + row] + 128) >> 8;",
     "          continue;\n        }\n        _nzr++;\n\n        // stage 4\n"
     "        v0 = (dctSqrt2 * p[0 + row] + 128) >> 8;"),
    (1,
     "          continue;\n        }\n\n        // stage 4\n"
     "        v0 = (dctSqrt2 * p[0*8 + col] + 2048) >> 12;",
     "          continue;\n        }\n        _nzc++;\n\n        // stage 4\n"
     "        v0 = (dctSqrt2 * p[0*8 + col] + 2048) >> 12;"),
    (1,
     "        dataOut[i] = sample < 0 ? 0 : sample > 0xFF ? 0xFF : sample;\n"
     "      }\n    }",
     "        dataOut[i] = sample < 0 ? 0 : sample > 0xFF ? 0xFF : sample;\n"
     "      }\n      globalThis.__gt.push(_nzr, _nzc);\n    }"),
]

DRIVER = """import * as std from 'std';
import * as os from 'os';
globalThis.std = std;
globalThis.os = os;
globalThis.__gt = [];

import {{ decode }} from './jpeg-js-gt.js';
import {{ Fixture, FindProjectRoot }} from './utils.js';

var jpegData = Fixture('{image}');
decode(jpegData, {{ useTArray: true }});

var out = std.open(FindProjectRoot() + '{out}', 'w');
for (var i = 0; i < globalThis.__gt.length; i += 2) {{
    out.puts(globalThis.__gt[i] + ' ' + globalThis.__gt[i + 1] + '\\n');
}}
out.close();
std.out.printf('blocks: %d\\n', globalThis.__gt.length / 2);
"""


def patch_source():
    src = (JS / "jpeg-js.js").read_text()
    for n, old, new in PATCHES:
        if src.count(old) != n:
            sys.exit(f"patch anchor not found exactly {n}x:\n{old[:90]}...")
        src = src.replace(old, new)
    return src


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--image", required=True,
                    help="jpeg to decode, relative to the project root")
    ap.add_argument("--out", required=True,
                    help="ground-truth output path, relative to the project root")
    ap.add_argument("--qjs", default="build/quickjs/bin/qjs")
    a = ap.parse_args()

    root = HERE.parents[2]
    (JS / "jpeg-js-gt.js").write_text(patch_source())
    driver = JS / "_gt_driver.js"
    driver.write_text(DRIVER.format(image=a.image, out=a.out))
    r = subprocess.run([str(root / a.qjs), "-m", str(driver)],
                       cwd=root, capture_output=True, text=True)
    print(r.stdout.strip() or r.stderr.strip())
    if r.returncode != 0:
        sys.exit(r.returncode)
    print(f"ground truth -> {a.out}")


if __name__ == "__main__":
    main()
