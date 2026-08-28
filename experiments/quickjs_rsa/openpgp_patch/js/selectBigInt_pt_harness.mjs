import { SELECT } from './impl/selectBigInt.mjs';

const args = typeof scriptArgs !== 'undefined' ? scriptArgs.slice(1) : [];
const conditionText = args[0] || 'false';
const bits = Number(args[1] || 4095);
const iterations = Number(args[2] || 1);

if (conditionText !== 'false' && conditionText !== 'true')
	throw new Error('condition must be false or true');
if (!Number.isInteger(bits) || bits < 1)
	throw new Error('bits must be a positive integer');
if (!Number.isInteger(iterations) || iterations < 1)
	throw new Error('iterations must be a positive integer');

const condition = conditionText === 'true' ? 1n : 0n;
const a = (1n << BigInt(bits)) - 189n;
const b = (1n << BigInt(bits - 1)) + 61n;
const bitLength = BigInt(bits);
let sink = 0n;

for (let i = 0; i < iterations; i++)
	sink ^= SELECT(condition, a, b, bitLength) & 1n;

print(
	`# condition=${conditionText} bits=${bits}` +
		` iterations=${iterations} sink=${sink & 1n}`,
);
