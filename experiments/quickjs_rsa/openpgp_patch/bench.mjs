// Runs unmodified on:
//   * QuickJS : qjs bench.mjs <impl.mjs> [samples] [bits] [seed]
//   * V8      : d8 --module bench.mjs -- <impl.mjs> [samples] [bits] [seed]
//   (qjs is patched to expose a global rdtscp() -> BigInt; d8 already exposes one)
//
// <impl.mjs> is resolved relative to THIS file (dynamic import semantics), so
// `./js/selectBigInt.mjs` works regardless of the current working directory.
//
//   samples : number of timed measurements (default 100000)
//   bits    : operand bit-length (default 4095, ~RSA-4096 limb)
//   seed    : PRNG seed for reproducible operands across engines (default 1)
//
// Output: CSV on stdout — a '#'-prefixed metadata line, a 'cond,cycles' header,
// then one `cond,cycles` row per measurement.
//

// ---- argument plumbing (qjs uses scriptArgs, d8 uses arguments) ----------
const ARGS =
	typeof scriptArgs !== 'undefined'
		? scriptArgs.slice(1) // drop script name
		: typeof arguments !== 'undefined'
		? Array.prototype.slice.call(arguments)
		: [];

const IMPL_PATH = ARGS[0];
if (!IMPL_PATH) {
	throw new Error('usage: bench.mjs <impl.mjs> [samples] [bits] [seed]');
}
const SAMPLES = (ARGS[1] | 0) || 100000;
const BITS = (ARGS[2] | 0) || 4095;
const SEED = (ARGS[3] | 0) || 1;

// Import the implementation module selected by path.
const mod = await import(IMPL_PATH);
const SELECT = mod.SELECT;
const IMPL = mod.IMPL_NAME || 'unknown';
if (typeof SELECT !== 'function') {
	throw new Error(`${IMPL_PATH}: module does not export a SELECT function`);
}

const ENGINE =
	typeof scriptArgs !== 'undefined'
		? 'quickjs'
		: typeof version === 'function'
		? 'v8'
		: 'unknown';

// ---- deterministic PRNG so operands & cond sequence match across engines --
function mulberry32(a) {
	return function () {
		a |= 0;
		a = (a + 0x6d2b79f5) | 0;
		let t = Math.imul(a ^ (a >>> 15), 1 | a);
		t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}
const rnd = mulberry32(SEED);

const _0n = BigInt(0);
const _1n = BigInt(1);

function bitLength(x) {
	const target = x < _0n ? BigInt(-1) : _0n;
	let bitlen = 1;
	let tmp = BigInt(x);
	while ((tmp >>= _1n) !== target) bitlen++;
	return bitlen;
}

function randomBigInt(bits) {
	const CHUNK = 30;
	let result = 0n;
	let remaining = bits;
	while (remaining > 0) {
		const chunk = Math.min(remaining, CHUNK);
		const r = BigInt((rnd() * (1 << chunk)) >>> 0);
		result = (result << BigInt(chunk)) | r;
		remaining -= chunk;
	}
	return result | (1n << BigInt(bits - 1)); // force exact bit length
}

// ---- setup ---------------------------------------------------------------
const a = randomBigInt(BITS);
const b = randomBigInt(BITS);
const len = BigInt(Math.max(bitLength(a), bitLength(b)));

const cond0 = BigInt(0);
const cond1 = BigInt(1);

let sink = 0n; // consume results so nothing is optimized away

// Warm up (matters for V8 JIT tiering; harmless for QuickJS).
for (let i = 0; i < 20000; i++) {
	sink ^= SELECT(BigInt(i & 1), a, b, len) & _1n;
}

// ---- measurement ---------------------------------------------------------
// Pre-generate the secret-bit sequence so both engines see the same trace.
const conds = new Int8Array(SAMPLES);
for (let i = 0; i < SAMPLES; i++) conds[i] = rnd() < 0.5 ? 0 : 1;

const cycles = new Float64Array(SAMPLES);

for (let i = 0; i < SAMPLES; i++) {
	const cond = conds[i] ? cond1 : cond0;
	// Exactly one full selection per measurement. There is deliberately no
	// inner repeat loop: any repeat count >1 is a footgun on a JIT (V8 hoists
	// the loop-invariant, constant-argument call out via LICM) and buys nothing
	// off a JIT either, because the only thing it amortizes is the fixed rdtscp
	// overhead — a constant added to every sample regardless of `cond`, which
	// cancels in Δmedian and is invisible to the rank-based AUC.
	//
	// `cond` varies per iteration (conds[i]), so the call is NOT loop-invariant
	// across `i` and cannot be hoisted; `v` feeds `sink` (printed below), so it
	// is observably live and cannot be eliminated.
	const t0 = rdtscp();
	const v = SELECT(cond, a, b, len);
	const t1 = rdtscp();
	sink ^= v & _1n;
	// rdtscp() returns BigInt; Number() is exact for these small deltas.
	cycles[i] = Number(t1 - t0);
}

// ---- emit ----------------------------------------------------------------
print(
	`# engine=${ENGINE} impl=${IMPL} samples=${SAMPLES} bits=${BITS}` +
		` seed=${SEED} sink=${(sink & _1n).toString()}`,
);
print('cond,cycles');

// Emit all rows in a single print() call (portable across qjs/d8 and avoids
// per-line write syscalls).
const rows = new Array(SAMPLES);
for (let i = 0; i < SAMPLES; i++) {
	rows[i] = conds[i] + ',' + cycles[i];
}
print(rows.join('\n'));
