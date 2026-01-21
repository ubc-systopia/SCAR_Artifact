#pragma once

#include <stddef.h>

#include "arch.h"

typedef void** node;

typedef struct linked_list {
	// Candidate buffer staring address
	uintptr_t buffer_addr;
	int len;
	node head;
	node tail;
} linked_list;

inline __attribute__((always_inline)) node ln_get(node nd) {
	return mem_read(nd);
}

inline __attribute__((always_inline)) void ln_set(node nd, void* ptr) {
	if (nd == NULL) {
	} else {
		*nd = ptr;
	}
}

inline __attribute__((always_inline)) void ll_flush(linked_list* ll) {
	int len;
	node cur;
	asm volatile(
		"mov %[ll_len], %[len];"
		"mov %[ll_head], %[cur];"
		: [len] "=c"(len), [cur] "=d"(cur)
		: [ll_len] "r"(ll->len), [ll_head] "r"(ll->head));

loop_check:
	asm volatile goto(
		"test %[len], %[len];"
		"je %l[exit];"
		"mov (%[cur_old]), %%rax;"
		"clflush (%[cur_old]);"
		"mfence;"
		"mov %%rax, %[cur_new];"
		"decl %[len];"
		"jmp %l[loop_check];"
		: [cur_new] "=d"(cur), [dlen] "=c"(len)
		: [len] "c"(len), [cur_old] "d"(cur)
		: "rax", "cc"
		: exit, loop_check);
exit:
	asm volatile(
		"clflush (%[cur_old]);"
		"mfence;"
		:
		: [cur_old] "d"(cur)
		: "memory");
}

inline __attribute__((always_inline)) void ll_traverse(linked_list* ll) {
	int len;
	node cur;
	asm volatile(
		"mov %[ll_len], %[len];"
		"mov %[ll_head], %[cur];"
		: [len] "=c"(len), [cur] "=d"(cur)
		: [ll_len] "r"(ll->len), [ll_head] "r"(ll->head));

loop_check:
	asm volatile goto(
		"test %[len], %[len];"
		"je %l[exit];"
		"mov (%[cur_i]), %[cur_o];"
		"decl %[len];"
		"jmp %l[loop_check];"
		: [cur_o] "=d"(cur), [dlen] "=c"(len)
		: [len] "c"(len), [cur_i] "d"(cur)
		: "cc"
		: exit, loop_check);
exit:
	return;
}

inline __attribute__((always_inline)) void ll_traverse_y(linked_list* ll,
														 int y) {
	node cur = ll->head;
	while (y-- > 0) {
		cur = ln_get(cur);
	}
}

inline __attribute__((always_inline)) void ll_traverse_x(linked_list* ll,
														 int x) {
	while (x-- > 0) {
		ll_traverse(ll);
	}
}

inline __attribute__((always_inline)) void ll_traverse_xy(linked_list* ll,
														  int x,
														  int y) {
	node cur;
	int len = __min(ll->len, y);
	for (int xi = 0; xi < x; ++xi) {
		cur = ll->head;
		for (int i = 0; i < len; ++i) {
			cur = ln_get(cur);
		}
	}
}

void ll_push(linked_list* ll, void* addr);

void ll_push_nth(linked_list* ll, void* addr, int n);

void ll_push_back(linked_list* ll, void* addr);

node ll_pop(linked_list* ll);

node ll_pop_nth(linked_list* ll, int n);

node ll_get_nth(linked_list* ll, int n);

void ll_insert(linked_list* ll, node cur, void* addr);

void ll_filter_set_index(linked_list* ll, uint64_t set_index);

void ll_print(linked_list* ll);