// Standalone timing harness for js/selectBigInt.mjs.
//
// QuickJS:
//   qjs selectBigInt_timing.mjs [samples] [bits] [seed]
// V8:
//   d8 --module --single-threaded selectBigInt_timing.mjs -- [samples] [bits] [seed]
//
// The engine must expose rdtscp() returning a BigInt cycle counter.

import { SELECT } from './js/selectBigInt.mjs';

const args =
	typeof scriptArgs !== 'undefined'
		? scriptArgs.slice(1)
		: typeof arguments !== 'undefined'
		? Array.prototype.slice.call(arguments)
		: [];

const samples = Number(args[0] || 100000);
const bits = Number(args[1] || 4095);
const seed = Number(args[2] || 1);

if (!Number.isInteger(samples) || samples < 2) {
	throw new Error('samples must be an integer of at least 2');
}
if (!Number.isInteger(bits) || bits < 1) {
	throw new Error('bits must be a positive integer');
}
if (typeof rdtscp !== 'function') {
	throw new Error('this harness requires an engine exposing rdtscp()');
}

function mulberry32(initialSeed) {
	let state = initialSeed | 0;
	return function () {
		state = (state + 0x6d2b79f5) | 0;
		let value = Math.imul(state ^ (state >>> 15), 1 | state);
		value = (value + Math.imul(value ^ (value >>> 7), 61 | value)) ^ value;
		return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
	};
}

const random = mulberry32(seed);

function randomBigInt(bitCount) {
	const chunkBits = 30;
	let value = 0n;
	let remaining = bitCount;
	while (remaining > 0) {
		const width = Math.min(remaining, chunkBits);
		const chunk = BigInt((random() * (1 << width)) >>> 0);
		value = (value << BigInt(width)) | chunk;
		remaining -= width;
	}
	return value | (1n << BigInt(bitCount - 1));
}

function median(values) {
	values.sort((a, b) => a - b);
	const middle = values.length >> 1;
	return values.length & 1
		? values[middle]
		: (values[middle - 1] + values[middle]) / 2;
}

const a = randomBigInt(bits);
const b = randomBigInt(bits);
const maxBitLength = BigInt(bits);
let sink = 0n;

// Warm the JIT before collecting measurements.
for (let i = 0; i < 20000; i++) {
	sink ^= SELECT(BigInt(i & 1), a, b, maxBitLength) & 1n;
}

// Start balanced, then shuffle to prevent run-order drift from favouring one
// condition. With an odd sample count, false has one additional observation.
const conditions = new Int8Array(samples);
for (let i = 0; i < samples; i++) conditions[i] = i & 1;
for (let i = samples - 1; i > 0; i--) {
	const j = Math.floor(random() * (i + 1));
	const temporary = conditions[i];
	conditions[i] = conditions[j];
	conditions[j] = temporary;
}

const falseCycles = [];
const trueCycles = [];
const rows = new Array(samples);

for (let i = 0; i < samples; i++) {
	// selectBigInt expects the boolean condition encoded as BigInt 0 or 1.
	const condition = conditions[i] ? 1n : 0n;
	const start = rdtscp();
	const selected = SELECT(condition, a, b, maxBitLength);
	const end = rdtscp();
	const elapsed = Number(end - start);

	sink ^= selected & 1n;
	(conditions[i] ? trueCycles : falseCycles).push(elapsed);
	rows[i] = `${conditions[i] ? 'true' : 'false'},${elapsed}`;
}

const falseMedian = median(falseCycles);
const trueMedian = median(trueCycles);

print(
	`# samples=${samples} bits=${bits} seed=${seed}` +
		` false_samples=${falseCycles.length} true_samples=${trueCycles.length}` +
		` sink=${sink & 1n}`,
);
print('condition,cycles');
print(rows.join('\n'));
print(
	`# median_false_cycles=${falseMedian}` +
		` median_true_cycles=${trueMedian}` +
		` difference_true_minus_false_cycles=${trueMedian - falseMedian}`,
);
