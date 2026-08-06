// Victim script for the FR cache-attack against the patched `selectBigInt`.
// Loops calling SELECT(cond, a, b, bits) with a *fixed* secret bit for the
// whole round, so a concurrent Flush+Reload attacker gets a wide sampling
// window over many identical calls instead of a single, too-fast-to-sample
// call. cond/iterations are read from env vars set by the attacker via
// sync_ctx.data before each round (same mechanism openpgp_rsa.js uses for
// KEY_ID).
import { SELECT } from './selectBigInt.mjs';
import * as std from 'std';

const cond = BigInt(std.getenv('COND') | 0);
const iters = (std.getenv('ITERS') | 0) || 50;
const bits = 4095n;

const a = (1n << bits) - 189n;
const b = (1n << (bits - 1n)) + 61n;

let sink = 0n;
for (let i = 0; i < iters; i++) {
	sink ^= SELECT(cond, a, b, bits) & 1n;
}

console.log(`cond=${cond} iters=${iters} sink=${sink & 1n}`);
