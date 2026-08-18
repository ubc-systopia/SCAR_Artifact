#pragma once

#include <strings.h>
#include <stdint.h>
#include <pthread.h>

#include "arch.h"

/* One monitored cache line for a FLUSH+RELOAD attacker. Same fields as
 * PS_attacker_thread_config_t minus the three that are PRIME+SCOPE machinery
 * (evset, chain, scope); probe_time holds reload latencies here.
 *
 * One difference in how it is used: the PS_/PP_ configs are per THREAD, this is
 * per LINE. An F+R attacker flushes and reloads every line it watches from ONE
 * loop (a thread per line would serialise them against each other), so declare
 * one config per line and iterate them. `slot` still means the trace column. */
typedef struct FR_attacker_thread_config_t {
	const char *test_name;
	const char *label;
	int slot;
	int pin_cpu;
	int cache_line_count;
	int profile_iterations;
	uint64_t max_exec_cycles;
	int victim_runs;
	pthread_barrier_t *threads_barrier;
	uint64_t **sample_tsc;
	uint64_t **probe_time;
	uint8_t *target;
} FR_attacker_thread_config_t;

#define FR_thread_config_init(config)                   \
	do {                                                \
		config.test_name = test_name;                   \
		config.pin_cpu = -1;                            \
		config.cache_line_count = cache_line_count;     \
		config.profile_iterations = profile_iterations; \
		config.max_exec_cycles = max_exec_cycles;       \
		config.victim_runs = victim_runs;               \
		config.threads_barrier = sync_ctx.barrier;      \
		config.sample_tsc = sample_tsc;                 \
		config.probe_time = reload_time;                \
	} while (0)

#define CACHE_LINE(op, __cl_off) ((void*)((uintptr_t)target_##op + __cl_off * CACHE_LINE_SIZE))

#define FLUSH_CACHE_LINE(op, __cl_off) clflush(CACHE_LINE(op, __cl_off))

#define RELOAD_CACHE_LINE(op, __cl_off, __slot) do {                \
    sample_tsc[__slot][index] = rdtscp();                           \
    uint64_t access_time = timed_access(CACHE_LINE(op, __cl_off));  \
    reload_time[__slot][index] = access_time;                       \
} while(0)

uint64_t FR_wait(uint64_t waiting_time);
