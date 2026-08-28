import { SELECT } from './impl/selectBigInt.mjs';

const args = typeof scriptArgs !== 'undefined' ? scriptArgs.slice(1) : [];
const samples = Number(args[0] || 10000);
const bits = Number(args[1] || 4095);

if (!Number.isInteger(samples) || samples < 2)
	throw new Error('samples must be an integer of at least 2');
if (!Number.isInteger(bits) || bits < 1)
	throw new Error('bits must be a positive integer');

const a = (1n << BigInt(bits)) - 189n;
const b = (1n << BigInt(bits - 1)) + 61n;
const bitLength = BigInt(bits);
let sink = 0n;

for (let i = 0; i < samples; i++) {
	sink ^= SELECT(BigInt(i & 1), a, b, bitLength) & 1n;
}

print(`# samples=${samples} bits=${bits} sink=${sink & 1n}`);
