// Original OpenPGP.js selection (pre-patch): `r = lsb ? rx : r`.
// Branches on the secret bit; returns a reference in O(1).
export const IMPL_NAME = 'ternary';

export function SELECT(cond, a, b /*, maxBitLength */) {
	return cond ? a : b;
}
