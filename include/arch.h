#pragma once

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>

#include "cache.h"

#define __max(a, b)             \
	({                          \
		__typeof__(a) _a = (a); \
		__typeof__(b) _b = (b); \
		_a > _b ? _a : _b;      \
	})

#define __min(a, b)             \
	({                          \
		__typeof__(a) _a = (a); \
		__typeof__(b) _b = (b); \
		_a < _b ? _a : _b;      \
	})

#ifdef PAGE_SHIFT
#undef PAGE_SHIFT
#endif
#define PAGE_SHIFT (12u)
#define PAGE_SIZE (1ull << PAGE_SHIFT)

#define HUGEPAGE_SHIFT (30)
#define HUGEPAGE_SIZE (1ull << HUGEPAGE_SHIFT)

#define L1_LEVEL (1)
#define L2_LEVEL (2)
#define L3_LEVEL (3)
#define R2_LEVEL (4)
#define DRAM_LEVEL (5)
#define PAGE_LEVEL (6)
#define INTERRUPT_LEVEL (7)

extern const int pinned_cpu0;
extern const int pinned_cpu1;
extern const int pinned_cpu2;

int pin_cpu(int cpu_id);

inline __attribute__((always_inline)) void __cpuid(unsigned int* eax,
												   unsigned int* ebx,
												   unsigned int* ecx,
												   unsigned int* edx) {
	/* ecx is often an input as well as an output. */
	asm volatile("cpuid"
				 : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
				 : "0"(*eax), "2"(*ecx));
}

// NOTE: need ring 0 privilege
inline __attribute__((always_inline)) void wrmsr(uint32_t ecx, uint32_t eax) {
	asm volatile("wrmsr" : : "a"(eax), "c"(ecx), "d"(0));
}

inline __attribute__((always_inline)) uint64_t rdtsc() {
	uint32_t low = 0, high = 0;
	asm volatile("rdtsc" : "=d"(high), "=a"(low));
	return (((uint64_t)high) << 32) | low;
}

inline __attribute__((always_inline)) uint64_t rdtscp() {
	uint64_t low, high;
	asm volatile("rdtscp" : "=a"(low), "=d"(high) : : "rbx", "rcx");
	return ((high << 32) | low);
}

inline __attribute__((always_inline)) void mfence() {
	asm volatile("mfence" ::: "memory");
}

inline __attribute__((always_inline)) void lfence() {
	asm volatile("lfence" ::: "memory");
}

inline __attribute__((always_inline)) uint64_t mfence_rdtscp() {
	uint64_t low, high;
	asm volatile("mfence");
	asm volatile("rdtscp" : "=a"(low), "=d"(high) : : "rbx", "rcx", "memory");
	asm volatile("mfence");
	return ((high << 32) | low);
}

inline __attribute__((always_inline)) void mfence_clflush(volatile void* addr) {
	asm volatile(
		"mfence;"
		"clflush (%0);"
		"mfence;" ::"r"(addr)
		: "memory");
}

inline __attribute__((always_inline)) void clflush(volatile void* addr) {
	asm volatile("clflush (%0);" ::"r"(addr) : "memory");
}

inline __attribute__((always_inline)) void* mem_read(void* addr) {
	void* ret;
	asm volatile("mov (%1), %0;" : "+r"(ret) : "r"(addr) : "memory");
	return ret;
}

inline __attribute__((always_inline)) void cpuid(union cpuid_t* cp) {
	asm volatile("cpuid;"
				 : "+a"(cp->regs.eax), "+b"(cp->regs.ebx), "+c"(cp->regs.ecx),
				   "+d"(cp->regs.edx));
}

inline __attribute__((always_inline)) void mem_barrier(void) {
	asm volatile("" ::: "memory");
}

inline __attribute__((always_inline)) uint64_t timed_access(void* addr) {
	uint64_t val;
	/*
	1. fence
	2. rdtscp:
	  timestimp -> [ebx:eax]
	3. move lower timer to val:
	  mov: %eax [val]
	4. access *addr, we don't care the value
	  mov [addr], %eax
	5. fence wait for memory
	6. rdtscp:
	  timestimp -> [ebx:eax]
	7. get elapsed time
	  val = %eax - val
	  sub [val]
   */
	asm volatile(
		"mfence;"
		"rdtscp;"
		"lfence;"
		"mov %%eax, %%esi;"
		"mov (%1), %%eax;"
		"rdtscp;"
		"sub %%esi, %%eax;"
		: "=&a"(val)
		: "r"(addr)
		: "ecx", "edx", "esi", "memory");
	return val;
}

int level_in_cache(int level);
