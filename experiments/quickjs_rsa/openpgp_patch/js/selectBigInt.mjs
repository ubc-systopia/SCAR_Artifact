// Patched selection from ct-modexp.patch — the OpenPGP.js team's
// "algorithmically constant-time" replacement for `r = lsb ? rx : r`:
//   r = selectBigInt(lsb, rx, r, nBitLength);
export const IMPL_NAME = 'selectBigInt';

export function SELECT(cond, a, b, maxBitLength) {
	const _1n = 1n;
	const mask = _1n << maxBitLength;
	return (a & (mask - cond)) | (b & (mask - _1n + cond));
}
