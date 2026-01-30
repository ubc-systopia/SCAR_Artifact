#include "log.h"
#include "arch.h"
#include "sync.h"
#include "prime_probe.h"

const uint32_t l2_repeat = 1, array_repeat = 12;
const double bad_threshold_ratio = 0.10;
static uint32_t max_retry = 10;
EVSet ****sfevset_complex;
evset_algorithm evalgo = EVSET_ALGO_DEFAULT;
double cands_scaling = 3;
size_t extra_cong = 1;
size_t max_tries = 10, max_backtrack = 20, max_timeout = 0;
size_t total_runtime_limit = 0; // in minutes
bool l2_filter = true, single_thread = false;
size_t num_l2sets;
u32 extra_sf_cong = 0; // extra_cong wrt. SF!

EVSet *get_sf_kth_evset(int k) {
	int index, page_slot, l2_uc_bits, l2_uc_slot, l3_uc_slot;
	index = k;
	page_slot = index % NUM_PAGE_SLOTS;
	index /= NUM_PAGE_SLOTS;
	l2_uc_bits = cache_sets_to_nbits(detected_l2->n_sets) + CACHE_LINE_BITS -
	             cache_sets_to_nbits(PAGE_SIZE);
	l2_uc_slot = index & ((1 << l2_uc_bits) - 1);
	index >>= l2_uc_bits;
	l3_uc_slot = index;
	log_trace("k: %d/%x, [pageoff:%x][l2_uc_off:%x][l3_uc_off:%x]",
	          k,
	          k,
	          page_slot,
	          l2_uc_slot,
	          l3_uc_slot);
	if (sfevset_complex[page_slot][l2_uc_slot][l3_uc_slot] == NULL) {
		log_warn(
		    "Cannot find evset for [pageoff:%d][l2_uc_off:%d][l3_uc_off:%d]\n",
		    k,
		    page_slot,
		    l2_uc_slot,
		    l3_uc_slot);
	}
	return sfevset_complex[page_slot][l2_uc_slot][l3_uc_slot];
}

int measure_performance(EVSet *evset) {
	u32 n_repeat = 1000, aux;
	i64 para_lat = 0, ps_lat = 0, ptr_lat = 0;
	u64 end_tsc, start, end;

	prime_skx_sf_evset_para(evset, array_repeat, l2_repeat);
	start = _timer_start();
	for (u32 i = 0; i < n_repeat * 10; i++) {
		probe_skx_sf_evset_para(evset, &end_tsc, &aux);
	}
	end = _timer_end();
	para_lat = (end - start) / n_repeat / 10;

	u8 *ptr = evset->addrs[0];
	_time_maccess(ptr);
	start = _timer_start();
	for (u32 i = 0; i < n_repeat * 10; i++) {
		_time_maccess(ptr);
	}
	end = _timer_end();
	ps_lat = (end - start) / n_repeat / 10;

	start = _timer_start();
	for (u32 i = 0; i < n_repeat * 10; i++) {
		probe_skx_sf_evset_ptr_chase(evset, &end_tsc, &aux);
	}
	end = _timer_end();
	ptr_lat = (end - start) / n_repeat / 10;

	log_info(
	    "Para. Resolution: %lu cycles; Ptr-Chase Resolution: %lu cycles; PS "
	    "Resolution: %lu cycles",
	    para_lat,
	    ptr_lat,
	    ps_lat);
	return false;
}

static bool check_and_set_sf_evset(u8 *target, EVSet *evset) {
	if (!evset || evset->size < SF_ASSOC + extra_sf_cong) {
		_error("Failed to build sf evset\n");
		return false;
	}
	evset->size = SF_ASSOC + extra_sf_cong;

	EVTestRes tres = precise_evset_test_alt(target, evset);
	if (tres != EV_POS) {
		_error("Cannot evict target\n");
		return false;
	}

	tres = generic_test_eviction(
	    target, evset->addrs, SF_ASSOC, &evset->config->test_config_alt);
	if (tres != EV_POS) {
		_error("Cannot evict target with SF_ASSOC\n");
		return false;
	}
	return true;
}

EVSet *prepare_evsets(u8 *target, helper_thread_ctrl *hctrl) {
	EVSet *l2_evset = NULL;
	for (u32 i = 0; i < max_retry; i++) {
		l2_evset = build_l2_EVSet(target, &def_l2_ev_config, NULL);
		if (!l2_evset || generic_evset_test(target, l2_evset) != EV_POS) {
			l2_evset = NULL;
		} else {
			break;
		}
	}
	if (!l2_evset) {
		log_error("Failed to build an L2 evset\n");
		return NULL;
	}

	EVBuildConfig sf_config;
	default_skx_sf_evset_build_config(&sf_config, NULL, l2_evset, hctrl);

	EVSet *sf_evset = build_skx_sf_EVSet(target, &sf_config, NULL);

	if (!check_and_set_sf_evset(target, sf_evset)) {
		log_error("Failed to build the main SF evset\n");
		return NULL;
	}

	evchain *sf_chain1 = evchain_build(sf_evset->addrs, SF_ASSOC);

	if (measure_performance(sf_evset)) {
		log_error("Failed to measure prime+probe performance!\n");
		return NULL;
	}

	return sf_evset;
}

void prepare_evset_thres(uintptr_t target, EVSet **evset, int *threshold) {
	helper_thread_ctrl hctrl;
	if (start_helper_thread(&hctrl)) {
		_error("Failed to start helper!\n");
		return;
	}
	int retry = 4;
	for (int i = 0; i < retry; ++i) {
		*evset = prepare_evsets((uint8_t *)target, &hctrl);
		if (*evset != NULL) {
			*threshold = calibrate_para_probe_lat((uint8_t *)target,
			                                      *evset,
			                                      array_repeat,
			                                      l2_repeat,
			                                      bad_threshold_ratio);
		}
		if (*evset != NULL && *threshold != 0) {
			log_info("Find threshold: %d", *threshold);
			break;
		}
		if (i == retry - 1) {
			log_error("Cannot calibrate probe latency");
			exit(1);
		}
	}

	stop_helper_thread(&hctrl);
	return;
}

static void shuffle_index(u32 *idxs, u32 sz) {
	srand(time(NULL));
	for (u32 tail = sz - 1; tail > 0; tail--) {
		u32 n_choice = tail + 1;
		u32 choice = rand() % n_choice;
		_swap(idxs[choice], idxs[tail]);
	}
}

int build_sf_evset_all(u32 n_offset, helper_thread_ctrl *hctrl) {
	EVSet ***l2evsets = build_l2_evsets_all();
	if (!l2evsets) {
		log_error("Failed to build L2 evset complex\n");
		return EXIT_FAILURE;
	}

	u32 idxs[NUM_PAGE_SLOTS] = { 0 };
	for (u32 i = 0; i < NUM_PAGE_SLOTS; i++) {
		idxs[i] = i;
	}

	if (n_offset > 0) {
		shuffle_index(idxs, NUM_PAGE_SLOTS);
	}

	EVBuildConfig sf_config;
	default_skx_sf_evset_build_config(&sf_config, NULL, NULL, hctrl);
	sf_config.algorithm = evalgo;
	sf_config.cands_config.scaling = cands_scaling;
	sf_config.algo_config.verify_retry = max_tries;
	sf_config.algo_config.max_backtrack = max_backtrack;
	sf_config.algo_config.retry_timeout = max_timeout;
	sf_config.algo_config.ret_partial = true;
	sf_config.algo_config.prelim_test = true;
	sf_config.algo_config.extra_cong = extra_cong;

	EVCands ***sf_cands = build_evcands_all(&sf_config, l2evsets);
	if (!sf_cands) {
		log_error("Failed to allocate or filter SF candidates\n");
		return EXIT_FAILURE;
	}

	reset_evset_stats();

	if (single_thread) {
		sf_config.test_config.traverse = skx_sf_cands_traverse_st;
		sf_config.test_config.need_helper = false;
	} else {
		start_helper_thread(sf_config.test_config.hctrl);
	}

	n_offset = _min(n_offset, NUM_PAGE_SLOTS);
	if (n_offset == 0) {
		n_offset = NUM_PAGE_SLOTS;
	}

	sfevset_complex = calloc(NUM_PAGE_SLOTS, sizeof(*sfevset_complex));
	if (!sfevset_complex) {
		log_error("Failed to allocate SF complex\n");
		return EXIT_FAILURE;
	}

	for (u32 n = 0; n < NUM_PAGE_SLOTS; n++) {
		sfevset_complex[n] = calloc(num_l2sets, sizeof(**sfevset_complex));
		if (!sfevset_complex[n]) {
			log_error("Failed to allocate SF sub-complex\n");
			return EXIT_FAILURE;
		}
	}

	_info("About to start evset construction\n");
	size_t l3_cnt;

	cache_param *lower_cache = NULL;
	EVBuildConfig *lower_conf = NULL;
	size_t n_lower_evsets = 0;
	if (!l2_filter) {
		lower_cache = detected_l2;
		lower_conf = &def_l2_ev_config;
		n_lower_evsets = cache_uncertainty(detected_l2);
	}

	u64 start = time_ns(), end;
	for (u32 c = 0; c < n_offset; c++) {
		u32 n = idxs[c];
		u32 offset = n * CL_SIZE;
		for (u32 i = 0; i < num_l2sets; i++) {
			sf_config.test_config.lower_ev = l2evsets[n][i];
			EVSet **sf_evsets = build_evsets_at(offset,
			                                    &sf_config,
			                                    detected_l3,
			                                    sf_cands[n][i],
			                                    &l3_cnt,
			                                    lower_cache,
			                                    lower_conf,
			                                    l2evsets[n],
			                                    n_lower_evsets);
			sfevset_complex[n][i] = sf_evsets;
			if (!sf_evsets) {
				log_error("No sf evsets are built!\n");
			}

			if (total_runtime_limit &&
			    ((time_ns() - start) / 1e9 >= total_runtime_limit * 60)) {
				log_error("Timeout break!\n");
				goto timeout_break;
			}
		}
		_info("Offset %#x finished\n", offset);
	}

timeout_break:
	end = time_ns();
	_info("Finished evset construction\n");
	_info("L3 Duration: %.3fms\n", (end - start) / 1e6);
	pprint_evset_stats();
	_info("n_offset %d, num_l2sets %zu, l3_cnt %zu\n",
	      n_offset,
	      num_l2sets,
	      l3_cnt);
	size_t total_succ = 0, total_sf_succ = 0;
	for (u32 c = 0; c < n_offset; c++) {
		u32 n = idxs[c];
		size_t offset_succ = 0, offset_sf_succ = 0;
		for (u32 i = 0; i < num_l2sets; i++) {
			if (!sfevset_complex[n][i]) {
				continue;
			}

			for (u32 j = 0; j < l3_cnt; j++) {
				EVSet *sf_evset = sfevset_complex[n][i][j];
				if (!sf_evset || !sf_evset->addrs) {
					continue;
				}

				EVTestRes llc_test = evset_self_precise_test(sf_evset);
				bool succ = llc_test == EV_POS;
				offset_succ += succ;
				total_succ += succ;

				sf_evset->config->test_config_alt.foreign_evictor = true;

				if (sf_evset->size > SF_ASSOC + 1) {
					sf_evset->size = SF_ASSOC + 1;
				}

				EVTestRes sf_test = evset_self_precise_test_alt(sf_evset);
				bool sf_succ = sf_test == EV_POS;
				offset_sf_succ += sf_succ;
				total_sf_succ += sf_succ;
			}
		}

		_info("Offset %#5lx: %lu/%lu/%lu (LLC/SF/Expecting)\n",
		      n * CL_SIZE,
		      offset_succ,
		      offset_sf_succ,
		      cache_uncertainty(detected_l3));
	}

	_info("Aggregated: %lu/%lu/%lu (LLC/SF/Expecting)\n",
	      total_succ,
	      total_sf_succ,
	      cache_uncertainty(detected_l3) * n_offset);

	if (!single_thread) {
		stop_helper_thread(sf_config.test_config.hctrl);
	}

	return EXIT_SUCCESS;
}

int LLCF_multi_evset(u32 n_offset, helper_thread_ctrl *hctrl) {
	int opt, opt_idx;

	if (cache_env_init(1)) {
		log_error("Failed to initialize cache env!\n");
		return EXIT_FAILURE;
	}
	num_l2sets = cache_uncertainty(detected_l2);
	if (!l2_filter)
		num_l2sets = 1;

	extra_cong = SF_ASSOC - detected_l3->n_ways;
	cache_oracle_init();
	int ret = build_sf_evset_all(n_offset, hctrl);
	cache_oracle_cleanup();
	return ret;
}
