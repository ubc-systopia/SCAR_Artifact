#pragma once

#include <stdint.h>

#define LLCT_INST
#include "quickjs/quickjs.h"

void quickjs_eval_buf_loop(JSRuntime* rt,
						   JSContext* ctx,
						   const char* eval_file);

void quickjs_get_bytecode_handler_cacheline();

void quickjs_init(JSRuntime** rt, JSContext** ctx);
void quickjs_free(JSRuntime* rt, JSContext* ctx);

// TODO: move below into attacker

typedef struct quickjs_runtime_thread_config_t {
	const char* js_eval_file;
	int victim_runs;
	int pin_cpu;
} quickjs_runtime_thread_config_t;

void *quickjs_runtime_thread(void *param);

enum OPCodeEnum {
#define SHORT_OPCODES 1
#define CONFIG_BIGNUM 1
#define FMT(f)
#define DEF(id, size, n_pop, n_push, f) OP_##id,
#define def(id, size, n_pop, n_push, f)
#include "quickjs/quickjs-opcode.h"
#undef def
#undef DEF
#undef FMT
	OP_COUNT, /* excluding temporary opcodes */
	/* temporary opcodes : overlap with the short opcodes */
	OP_TEMP_START = OP_nop + 1,
	OP___dummy = OP_TEMP_START - 1,
#define FMT(f)
#define DEF(id, size, n_pop, n_push, f)
#define def(id, size, n_pop, n_push, f) OP_##id,
#include "quickjs/quickjs-opcode.h"
#undef def
#undef DEF
#undef FMT
	OP_TEMP_END,
};

// DIRECT_DISPATCH
#define JS_STD_EVAL_FILE_ADDR (&js_std_eval_file)

#define QUICKJS_TARGET_CACHELINE(V)                               \
	V(sub, quickjs_dispatch_table[OP_sub], 0)                     \
	V(shl, quickjs_dispatch_table[OP_shl], 0)                     \
	V(sar, quickjs_dispatch_table[OP_sar], 0)                     \
	V(mul, quickjs_dispatch_table[OP_mul], 0)                     \
	V(mod, quickjs_dispatch_table[OP_mod], 0)                     \
	V(goto8, quickjs_dispatch_table[OP_goto8], 0)                 \
	V(goto16, quickjs_dispatch_table[OP_goto16], 0)               \
	V(if_false8, quickjs_dispatch_table[OP_if_false8], 0)         \
	V(get_loc_check, quickjs_dispatch_table[OP_get_loc_check], 0)

#define EXTERN_DECLARE_CACHELINE(BC, BASE_ADR, OFFSET) \
	extern uintptr_t target_##BC;                      \
	extern uint64_t offset_##BC;

#define DECLARE_CACHELINE(BC, BASE_ADR, OFFSET) \
	uintptr_t target_##BC;                      \
	uint64_t offset_##BC;

#define TARGET_ADDRESS_OFFSET(BC, BASE_ADDR, OFFSET) \
	target_##BC = ((uintptr_t)(BASE_ADDR + OFFSET) & CACHE_LINE_MASK);

QUICKJS_TARGET_CACHELINE(EXTERN_DECLARE_CACHELINE);
