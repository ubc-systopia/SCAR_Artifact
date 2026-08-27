// Confound-check victim: runs modExp's per-iteration multiply/mod work
// ((r*x)%n and (x*x)%n) WITHOUT the SELECT()/ternary secret-dependent step,
// to test whether bf_add_internal's hit rate during real modExp is dominated
// by these unconditional operations rather than by SELECT's branch. Compare
// its hit rate against select_probe.js's SELECT-only baseline (cond=0
// ~0.6-0.7%, cond=1 ~1.2-1.5% over an 8ms/iters=50 window) using the same
// FR attacker (quickjs_select_fr) and iters/window settings.
import * as std from 'std';

const iters = (std.getenv('ITERS') | 0) || 50;
const bits = 4095n;

let r = (1n << bits) - 189n;
let x = (1n << (bits - 1n)) + 61n;
const n = (1n << bits) - 59n; // odd, ~4095-bit modulus-sized constant

for (let i = 0; i < iters; i++) {
	const rx = (r * x) % n;
	x = (x * x) % n;
	r = rx;
}

console.log(`iters=${iters} r_lsb=${r & 1n}`);
