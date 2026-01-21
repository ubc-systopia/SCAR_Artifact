#include "cache.h"

#include <limits.h>

#include "arch.h"
#include "log.h"

struct latency_bound l1_b = {1, 60};
struct latency_bound l2_b = {61, 85};
struct latency_bound l3_b = {86, 160};
struct latency_bound r2_b = {161, 250};
struct latency_bound mm_b = {251, 471};
struct latency_bound pg_b = {472, INT_MAX};

uint64_t cache_sets_to_nbits(uint64_t sets) {
	uint64_t nbits = 0;
	while (sets) {
		if (sets & 1) {
			break;
		}
		++nbits;
		sets >>= 1;
	}
	if (sets != 1) {
		log_error("cache sets is not a power of 2\n");
	}
	return nbits;
}

uint64_t cache_sets_index_mask(int sets) {
	uint64_t n_bits = cache_sets_to_nbits(sets);
	return ((1ull << n_bits) - 1) << CACHE_LINE_BITS;
}

uint64_t cache_parse_set_index(uintptr_t addr, int sets) {
	uint64_t index_mask = cache_sets_index_mask(sets);
	uint64_t set_index_mask = (uintptr_t)addr & index_mask;
	uint64_t set_index = set_index_mask >> CACHE_LINE_BITS;
	return set_index;
}

uintptr_t cache_index_round_up(uintptr_t addr,
							   uint64_t stride,
							   uint64_t set_index) {
	uintptr_t left_over = addr & (stride - 1);
	uintptr_t set_index_mask = set_index << CACHE_LINE_BITS;
	if (set_index_mask >= left_over)
		return addr - left_over + set_index_mask;
	else {
		return addr - left_over + set_index_mask + stride;
	}
}

void print_cache_info(union cpuid_t* cache_param) {
	log_info("%30s", "Cache Parameters");
	log_info("%30s:\t%d", "Cache Type Field", cache_param->info.type);
	log_info("%30s:\t%d", "Cache Level", cache_param->info.level);
	log_info("%30s:\t%d", "Self Initializing cache level",
			  cache_param->info.self_init);
	log_info("%30s:\t%d", "Fully Associative cache",
			  cache_param->info.fully_associative);
	log_info("%30s:\t%d", "IDs for logical processors",
			  cache_param->info.logical_IDs);
	log_info("%30s:\t%d", "IDs for processor cores",
			  cache_param->info.physical_IDs);
	log_info("%30s:\t%d", "System Coherency Line Size",
			  cache_param->info.line_size);
	log_info("%30s:\t%d", "Physical Line partitions",
			  cache_param->info.partitions);
	log_info("%30s:\t%d", "Ways of associativity",
			  cache_param->info.associativity);
	log_info("%30s:\t%d", "Number of Sets", cache_param->info.sets);
	log_info("%30s:\t%d", "Cache Inclusiveness", cache_param->info.inclusive);
	log_info("%30s:\t%d", "Complex Cache Indexing",
			  cache_param->info.complex_index);
	log_info(SEPARATION_LINE);
}

void cpuid_cache_info(cache_info_t* cache_info, uint32_t level) {
	union cpuid_t* cache_param = &cache_info->aux;
	cache_param->regs.eax = 0x04;
	cache_param->regs.ecx = level;
	cpuid(cache_param);

	// +1 patch
	cache_param->info.logical_IDs++;
	cache_param->info.physical_IDs++;
	cache_param->info.line_size++;
	cache_param->info.partitions++;
	cache_param->info.associativity++;
	cache_param->info.sets++;

	if (cache_param->info.line_size != CACHE_LINE_SIZE) {
		log_warn("cache line is %u instead of common %d",
				 cache_param->info.line_size, CACHE_LINE_SIZE);
	}
	cache_info->sets = cache_info->aux.info.sets;
	cache_info->ways = cache_info->aux.info.associativity;
	cache_info->n_cacheline =
		cache_param->info.sets * cache_param->info.associativity;
	cache_info->size_b = cache_info->n_cacheline * CACHE_LINE_SIZE;
	cache_info->stride = cache_info->sets * CACHE_LINE_SIZE;
	print_cache_info(cache_param);
}

int check_in_cache(int level) {
	// [1, 2, 3] means [L1, L2, L3] cache
	return L1_LEVEL <= level && level <= L3_LEVEL;
}

int mem_access_level(uint64_t lat) {
	if (l1_b.lb <= lat && lat <= l1_b.ub) {
		return L1_LEVEL;
	}
	if (l2_b.lb <= lat && lat <= l2_b.ub) {
		return L2_LEVEL;
	}
	if (l3_b.lb <= lat && lat <= l3_b.ub) {
		return L3_LEVEL;
	}
	if (r2_b.lb <= lat && lat <= r2_b.ub) {
		return R2_LEVEL;
	}
	if (mm_b.lb <= lat && lat <= mm_b.ub) {
		return DRAM_LEVEL;
	}
	if (pg_b.lb <= lat && lat <= pg_b.ub) {
		return PAGE_LEVEL;
	}
	return INTERRUPT_LEVEL;
}
