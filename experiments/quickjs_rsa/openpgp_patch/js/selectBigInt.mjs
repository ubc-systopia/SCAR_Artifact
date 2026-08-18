// Patched selection from ct-modexp.patch — the OpenPGP.js team's
// "algorithmically constant-time" replacement for `r = lsb ? rx : r`:
//   r = selectBigInt(lsb, rx, r, nBitLength);
export const IMPL_NAME = 'selectBigInt';

export function SELECT(cond, a, b, maxBitLength) {
	const _1n = 1n;
	const mask = _1n << maxBitLength;
	return (a & (mask - cond)) | (b & (mask - _1n + cond));
}

// selectBigInt.mjs:6: function: SELECT
//   mode: strict
//   args: cond a b maxBitLength
//   locals:
//     0: const _1n [level:1 next:-1]
//     1: const mask [level:1 next:0]
//   stack_size: 4
//   opcodes:
// ;; function SELECT(cond, a, b, maxBitLength) {

//     0  61 01 00                   set_loc_uninitialized 1: mask
//     3  61 00 00                   set_loc_uninitialized 0: _1n

// ;; 	const _1n = 1n;

//     6  C1 00                      push_const8 0: 1n
//     8  CB                         put_loc0 0: _1n

// ;; 	const mask = _1n << maxBitLength;

//     9  62 00 00                   get_loc_check 0: _1n
//    12  D6                         get_arg3 3: maxBitLength
//    13  A1                         shl
//    14  CC                         put_loc1 1: mask

// ;; 	return (a & (mask - cond)) | (b & (mask - _1n + cond));

//    15  D4                         get_arg1 1: a
//    16  62 01 00                   get_loc_check 1: mask
//    19  D3                         get_arg0 0: cond
//    20  9F                         sub
//    21  AE                         and
//    22  D5                         get_arg2 2: b
//    23  62 01 00                   get_loc_check 1: mask
//    26  62 00 00                   get_loc_check 0: _1n
//    29  9F                         sub
//    30  D3                         get_arg0 0: cond
//    31  9E                         add
//    32  AE                         and
//    33  B0                         or
//    34  28                         return

// ;; }
