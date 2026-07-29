# Localizing `selectBigInt` timing differences with Intel PT

This document describes how to reproduce and interpret the instruction-level
control-flow comparison for:

```js
selectBigInt(false, a, b, maxBitLength)
selectBigInt(true,  a, b, maxBitLength)
```

The experiment combines two measurements:

1. `run_opcode_timing.sh` measures the timing difference attributed to each
   QuickJS bytecode handler.
2. `run_intel_pt.sh` records the native instruction paths for fixed false and
   true conditions and compares their symbol-relative instruction offsets.

Intel PT identifies which instructions execute. It does not, by itself,
measure the cost of each instruction. The bytecode timing experiment supplies
the timing evidence, while Intel PT localizes the differing native path.

## 1. Prerequisites

The machine used for this experiment has an Intel Xeon Silver 4309Y. Its CPU
flags include `intel_pt`, so the hardware supports Intel Processor Trace.

Confirm that the kernel exposes the Intel PT PMU:

```bash
ls /sys/bus/event_source/devices/intel_pt
```

An Ubuntu `perf` wrapper may fail when the running kernel is custom or does not
have a matching `linux-tools` package. Locate an installed real binary:

```bash
find /usr/lib/linux-tools -type f -name perf -executable
```

In this environment, the usable binary is:

```text
/usr/lib/linux-tools/5.15.0-186-generic/perf
```

Although that binary was packaged for a 5.15 kernel, its Intel PT capture works
with the running 6.6 kernel through the `perf_event_open` ABI.

Verify capture before running the full experiment:

```bash
PERF_BIN=/usr/lib/linux-tools/5.15.0-186-generic/perf

"$PERF_BIN" record -e intel_pt//u \
  -o /tmp/pt-test.data -- /bin/true
```

If this fails with a permissions error, repeat it with `sudo`. If the sysfs
device is absent despite the CPU flag, the kernel or hypervisor is not exposing
Intel PT.

## 2. Measure the bytecode-handler timing differences

Run repeated measurements on a pinned CPU:

```bash
RUNS=10 PIN_CPU=5 ./run_opcode_timing.sh 10000 4095
```

The final table summarizes the per-run median cycle difference:

```text
handler,runs,median_difference,min_difference,max_difference
add,10,+1455,+1448,+1648
and,10,+37,+14,+48
or,10,+2,-2,+30
shl,10,-2,-6,-2
sub,10,+137.5,+65,+261
```

The large, consistently positive `add` difference is the primary signal.
`sub` and `and` also show smaller condition-dependent differences, while
argument loads, local-variable operations, and returns are balanced.

## 3. Capture fixed-condition Intel PT traces

Run one `selectBigInt` call for each condition:

```bash
PERF_BIN=/usr/lib/linux-tools/5.15.0-186-generic/perf \
PIN_CPU=5 \
./run_intel_pt.sh 4095 1
```

The script:

1. Copies QuickJS into `pt_results/quickjs-build`.
2. Builds that private copy with debug information and frame pointers.
3. Executes a fixed-false harness under Intel PT.
4. Executes a fixed-true harness under Intel PT.
5. Decodes both traces into native instruction sequences.
6. Normalizes absolute addresses and creates a focused path diff.

The original QuickJS source tree is not modified.

Generated files:

```text
pt_results/false.data       Raw false-condition Intel PT data
pt_results/true.data        Raw true-condition Intel PT data
pt_results/false.trace      Decoded false instruction trace
pt_results/true.trace       Decoded true instruction trace
pt_results/path_diff.txt    Focused false-versus-true path diff
pt_results/quickjs-build/qjs
```

The decoded traces can be large. In the initial run, each was approximately
376 MB because Intel PT also captured QuickJS startup and module loading.

## 4. Inspect the focused path difference

Open the generated comparison:

```bash
less pt_results/path_diff.txt
```

Search directly for the relevant function and first branch:

```bash
rg -n "bf_add_internal\+0x26a|bf_add_internal\+0x2e0" \
  pt_results/path_diff.txt
```

The important divergence occurs at:

```text
bf_add_internal+0x26a
```

Intel PT reports executed instruction offsets and bytes; it does not emit the
source-level descriptions below. To inspect the instructions around the first
divergence, disassemble the exact binary used for capture:

```bash
QJS_BIN=pt_results/quickjs-build/qjs

objdump -d -Mintel --disassemble=bf_add_internal "$QJS_BIN" | less
```

The raw instructions immediately before the divergence are:

```asm
bf_add_internal+0x254  mov  rax,QWORD PTR [r12+0x18]
bf_add_internal+0x259  mov  rcx,QWORD PTR [r12+0x10]
bf_add_internal+0x25e  test rax,rax
bf_add_internal+0x261  je   bf_add_internal+0x26c
bf_add_internal+0x263  mov  rdx,QWORD PTR [rbx+0x18]
bf_add_internal+0x267  test rdx,rdx
bf_add_internal+0x26a  jne  bf_add_internal+0x2e0
```

The interpretation of the memory operands comes from the `bf_t` definition in
`libbf.h`:

```c
typedef struct {
    struct bf_context_t *ctx;  /* +0x00 */
    int sign;                  /* +0x08 */
    slimb_t expn;              /* +0x10 */
    limb_t len;                /* +0x18 */
    limb_t *tab;               /* +0x20 */
} bf_t;
```

At this point in `bf_add_internal`, `r12` holds `a` and `rbx` holds `b`.
Consequently, `[r12+0x18]` is `a->len`, while `[rbx+0x18]` is `b->len`.
The annotated sequence is therefore:

```text
bf_add_internal+0x254  load a->len
bf_add_internal+0x25e  test a->len
bf_add_internal+0x261  jump to the shortcut if a->len == 0
bf_add_internal+0x263  load b->len
bf_add_internal+0x267  test b->len
bf_add_internal+0x26a  jump to full arithmetic if b->len != 0
```

`addr2line` independently maps offsets `+0x25e` through `+0x26a` to
`libbf.c:908`, whose source is:

```c
} else if (a->len == 0 || b->len == 0) {
```

For the false condition, the second operand is `0n`. Its BigInt length is zero,
so execution falls through from `+0x26a` to the zero-operand shortcut beginning
at `+0x26c`.

For the true condition, the second operand is `1n`. Its length is nonzero, so
the branch at `+0x26a` is taken to `+0x2e0`, entering the full arithmetic path.

## 5. Resolve instruction offsets to source lines

Find the linked address of `bf_add_internal`:

```bash
QJS_BIN=pt_results/quickjs-build/qjs
nm -an "$QJS_BIN" | rg ' bf_add_internal$'
```

For this build, the function starts at:

```text
0x00000000000afdd0
```

Resolve an offset by adding it to the function address and passing the result
to `addr2line`. For example, `0xafdd0 + 0x26a = 0xb003a`:

```bash
addr2line -f -C -e "$QJS_BIN" 0xb003a
```

The important offsets from this run resolve as follows:

| Offset | Source line | Meaning |
|---|---|---|
| `bf_add_internal+0x26a` | `libbf.c:908` | Test whether either operand has zero length |
| `bf_add_internal+0x26c` | `libbf.c:910` | Begin the zero-operand shortcut |
| `bf_add_internal+0x530` | `libbf.c:923` | Copy the nonzero operand with `bf_set` |
| `bf_add_internal+0x2e0` | `libbf.c:932` | Enter the full arithmetic path |
| `bf_add_internal+0xf6` | `libbf.c:949` | Resize the result for limb arithmetic |
| `bf_add_internal+0x400` | `libbf.c:1004` | Execute the limb addition loop |
| `bf_add_internal+0x48b` | `libbf.c:1002` | Loop control for limb processing |

Offsets are specific to the exact compiler, flags, and binary. Always resolve
them against `pt_results/quickjs-build/qjs` from the same trace capture.

## 6. Source-level interpretation

The JavaScript expression responsible for the `add` handler is:

```js
mask - 1n + cond
```

It produces these additions:

```text
false: large BigInt + 0n
true:  large BigInt + 1n
```

Both calls reach QuickJS through this path:

```text
OP_add
  -> js_add_slow()
  -> js_binary_arith_bigint()
  -> bf_add()
  -> bf_add_internal()
```

Inside `bf_add_internal`, the controlling source branch is:

```c
} else if (a->len == 0 || b->len == 0) {
    /* zero-operand shortcut */
    bf_set(r, a);
    goto renorm;
} else {
    /* allocation, limb arithmetic, carry handling, and normalization */
}
```

The false condition takes the shortcut because `0n` has zero length. The true
condition executes the full path because `1n` has one nonzero limb. The true
trace consequently contains thousands more focused native instructions and
calls `bf_resize` before entering the limb loop.

This path divergence explains the stable bytecode-handler result:

```text
add: median true-minus-false difference = +1455 cycles
```

The smaller `sub` difference has the same general cause: subtracting `0n` can
take a zero-operand shortcut, while subtracting `1n` requires full arithmetic.

## 7. What the result establishes

The combined experiments establish that:

1. The true and false conditions have a stable timing difference in QuickJS's
   `OP_add` handler.
2. Intel PT identifies the first relevant native path divergence at
   `bf_add_internal+0x26a`.
3. That offset resolves to the zero-length operand test at `libbf.c:908`.
4. False takes the zero-operand copy path, while true takes allocation and limb
   arithmetic.
5. Therefore, the branchless JavaScript implementation is not constant-time
   after lowering to QuickJS BigInt operations.

Intel PT establishes path divergence, not the cycle cost of each native basic
block. If finer timing attribution is needed, add targeted `rdtscp` measurements
around the zero-operand shortcut, `bf_resize`, limb loop, and normalization in a
private instrumented QuickJS build.
