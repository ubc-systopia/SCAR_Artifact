// constant-time-js select(), instrumented for gdb tracing: %SystemBreak()
// markers bracket each traced call so the returnLeft=true and returnLeft=false
// invocations of the SAME code object can be traced separately. The function
// body is verbatim constant-time-js.
//
// %SystemBreak() raises SIGTRAP, so this file terminates under bare d8; run it
// under gdb as described in the case study Readme.

function select(returnLeft, left, right) {
	if (left.length !== right.length) {
		throw new Error(
			'select() expects two Uint8Array objects of equal length',
		);
	}
	/*
	 If returnLeft, mask = 0xFF; else, mask = 0x00;
	 */
	const mask = -!!returnLeft & 0xff;
	const out = new Uint8Array(left.length);
	for (let i = 0; i < left.length; i++) {
		out[i] = right[i] ^ ((left[i] ^ right[i]) & mask);
	}
	return out;
}


let length = 8;
let a = new Uint8Array(length);
let b = new Uint8Array(length);
for (let i = 0; i < length; ++i) {
	a[i] = i;
	b[i] = length - 1 - i;
}
let res;
%PrepareFunctionForOptimization(select);
res = select(true, a, b);
res = select(false, a, b);
%OptimizeFunctionOnNextCall(select);
res = select(true, a, b);   // priming call: compile off-trace so both traced
                            // calls run in steady optimized state

// markers 1/2: optimized, returnLeft = true
%SystemBreak();
res = select(true, a, b);
%SystemBreak();

// markers 3/4: optimized, returnLeft = false
%SystemBreak();
res = select(false, a, b);
%SystemBreak();
