#pragma once

#include <stdint.h>

#define CACHE_LINE_BITS (6)                   // lower 6 bits
#define CACHE_LINE_SIZE (64)                  // 64 Byte
#define CACHE_LINE_MASK (~((1ull << 6) - 1))  // 0xFFFFFFFFFFFFFFC0

struct latency_bound {
	int lb, ub;
};

extern struct latency_bound l1_b;
extern struct latency_bound l2_b;
extern struct latency_bound l3_b;
extern struct latency_bound r2_b;
extern struct latency_bound mm_b;

struct cpuid_regs {
	uint32_t eax;
	uint32_t ebx;
	uint32_t ecx;
	uint32_t edx;
};

/*
   Ref: Intel® 64 and IA-32 Architectures Software Developer’s Manual.pdf
   Table 3-8. Information Returned by CPUID Instruction (Contd.) */
struct cpuid_info {
	/* EAX */
	/* Bits 04-00: Cache Type Field. */
	/* 0 = Null - No more caches. */
	/* 1 = Data Cache. */
	/* 2 = Instruction Cache. */
	/* 3 = Unified Cache. */
	/* 4-31 = Reserved. */
	uint32_t type : 5;
	// Bits 07-05: Cache Level (starts at 1).
	uint32_t level : 3;
	// Bit 08: Self Initializing cache level (does not need SW initialization).
	uint32_t self_init : 1;
	// Bit 09: Fully Associative cache.
	uint32_t fully_associative : 1;
	// Bits 13-10: Reserved.
	uint32_t _reserved : 4;
	// Bits 25-14: Maximum number of addressable IDs for logical processors sharing this cache**, ***.
	uint32_t logical_IDs : 12;
	// Bits 31-26: Maximum number of addressable IDs for processor cores in the physical package**, ****, *****.
	uint32_t physical_IDs : 6;

	/* EBX */
	// Bits 11-00: L = System Coherency Line Size**.
	uint32_t line_size : 12;
	// Bits 21-12: P = Physical Line partitions**.
	uint32_t partitions : 10;
	// Bits 31-22: W = Ways of associativity**.
	uint32_t associativity : 10;

	/* ECX */
	// Bits 31-00: S = Number of Sets**.
	uint32_t sets : 32;

	/* EDX */
	/* Bit 00: Write-Back Invalidate/Invalidate. */
	/* 0 = WBINVD/INVD from threads sharing this cache acts upon lower level caches for threads sharing this cache. */
	/* 1 = WBINVD/INVD is not guaranteed to act upon lower level caches of non-originating threads sharing this cache. */
	uint32_t wbinvd : 1;
	/* Bit 01: Cache Inclusiveness. */
	/* 0 = Cache is not inclusive of lower cache levels. */
	/* 1 = Cache is inclusive of lower cache levels. */
	uint32_t inclusive : 1;
	/* Bit 02: Complex Cache Indexing. */
	/* 0 = Direct mapped cache. */
	/* 1 = A complex function is used to index the cache, potentially using all address bits. */
	uint32_t complex_index : 1;
	uint32_t __reserved : 29;

	/* REFERENCE NOTES: */
	/* * If ECX contains an invalid sub leaf index, EAX/EBX/ECX/EDX return 0. Sub-leaf index n+1 is invalid if sub-leaf n returns EAX[4:0] as 0. */
	/* ** Add one to the return value to get the result. */
	/* *** The nearest power-of-2 integer that is not smaller than (1 + EAX[25:14]) is the number of unique initial APIC IDs reserved for addressing different logical processors sharing this cache. */
	/* **** The nearest power-of-2 integer that is not smaller than (1 + EAX[31:26]) is the number of unique Core_IDs reserved for addressing different processor cores in a physical package. Core ID is a subset of bits of the initial APIC ID. */
	/* ***** The returned value is constant for valid initial values in ECX. Valid ECX values start from 0. */
};

union cpuid_t {
	struct cpuid_regs regs;
	struct cpuid_info info;
};

typedef struct cache_info_t {
	union cpuid_t aux;
	uint64_t sets;
	uint64_t ways;
	// cache size in bytes
	uint64_t size_b;
	// number of cache lines
	uint64_t n_cacheline;
	uint64_t stride;
} cache_info_t;

int mem_access_level(uint64_t lat);

int check_in_cache(int level);

uint64_t cache_sets_to_nbits(uint64_t sets);

uint64_t cache_sets_index_mask(int n_bits);

uint64_t cache_parse_set_index(uintptr_t addr, int sets);

uintptr_t cache_index_round_up(uintptr_t addr,
							   uint64_t stride,
							   uint64_t set_index);

void cpuid_cache_info(cache_info_t* cache_param, uint32_t level);

void print_cache_info(union cpuid_t* cache_param);